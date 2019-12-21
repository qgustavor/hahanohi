// Modules
const WebCrypto = require('node-webcrypto-ossl')
const secrets = require('./secrets-node')
const fetch = require('node-fetch')
const Jimp = require('jimp')
const path = require('path')
const util = require('util')
const fs = require('fs')

// Derived functions
const readFile = util.promisify(fs.readFile)
const writeFile = util.promisify(fs.writeFile)
const crypto = new WebCrypto()

// Conversion constants
const JSON_PLACEHOLDER = `<script id="game-data" type="application/json">{}</script>`
const DATA_FOLDER = path.resolve(__dirname, 'data')
const BASE_HTML_FOLDER = path.resolve(__dirname, 'base-html')
const FINAL_HTML_FOLDER = path.resolve(__dirname, 'generated-html')
const SPREADSHEET_CSV_URL = 'https://docs.google.com/spreadsheets/d/e/[insert spreadsheet id here]/pub?output=csv&gid='
const SPREADSHEET_LANGUAGE_IDS = {
  pt: 0,
  en: 1838584513
}

async function generateGame () {
  // TODO: those configurations it to a file
  // It needs to be random and unique per game
  const verificationKeys = JSON.parse(await readFile(path.join(DATA_FOLDER, 'data-keys.json')))
  const globalSettings = JSON.parse(await readFile(path.join(DATA_FOLDER, 'data-global.json')))
  const {
    gameRandomSalt,
    levelCount,
    hintThresholds,
    unlockedLevels,
    languages
  } = globalSettings

  const hintKeys = []
  const levelShares = []
  for (let i = 0; i < hintThresholds.length; i++) {
    const keyArrayBuffer = await crypto.subtle.digest({name: 'SHA-512'}, Buffer.from(gameRandomSalt + '-hint-' + i))
    const key = Buffer.from(keyArrayBuffer).slice(0, 16)
    const wrappedKey = await crypto.subtle.importKey('raw', key, {name: 'AES-GCM'}, false, ['encrypt'])
    hintKeys.push(wrappedKey)

    const shares = secrets.share(key, levelCount, hintThresholds[i])
    for (let j = 0; j < levelCount; j++) {
      if (!levelShares[j]) levelShares[j] = []
      levelShares[j].push(shares[j])
    }
  }

  const levelSalts = []
  const levelKeys = []
  const encryptedLevelKeys = []
  const shareKeys = []
  const verificationPublicKeys = []
  const verificationPrivateKeys = []
  const levelThumbnails = []
  const levelEncryptedData = []

  for (let i = 0; i < levelCount; i++) {
    const verificationKey = verificationKeys[i]
    if (!verificationKey) throw Error(`Missing ECDSA key ${i} - run script with --generate-key`)

    verificationPublicKeys.push(Buffer.from(verificationKey.publicKey, 'base64'))

    const privateKeyBuffer = Buffer.from(verificationKey.privateKey, 'base64')
    const privateKey = await crypto.subtle.importKey('pkcs8', privateKeyBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' }, true, [])

    const privateKeyJWK = await crypto.subtle.exportKey('jwk', privateKey)
    privateKeyJWK.crv = 'P-256'
    privateKeyJWK.ext = true
    privateKeyJWK.key_ops = ['sign']
    privateKeyJWK.kty = 'EC'

    const privateKeyJSON = Buffer.from(JSON.stringify(privateKeyJWK))
    if (privateKeyJSON.length !== 206) throw Error(`Private key length is ${privateKeyJSON.length}`)
    verificationPrivateKeys.push(privateKeyJSON)

    const saltArrayBuffer = await crypto.subtle.digest({name: 'SHA-512'}, Buffer.from(gameRandomSalt + '-salt-' + i))
    const salt = Buffer.from(saltArrayBuffer.slice(0, 16))
    levelSalts.push(salt)

    const imagePath = path.resolve(DATA_FOLDER, `${i + 1}.png`)
    const imageHash = await getHash(imagePath)

    const pbkdf2Wrapper = await crypto.subtle.importKey('raw', imageHash, {name: 'PBKDF2'}, false, ['deriveKey'])
    const encryptionKey = await crypto.subtle.deriveKey({
      name: 'PBKDF2',
      salt,
      iterations: 1e4,
      hash: {name: 'SHA-1'},
    }, pbkdf2Wrapper, {
      name: 'AES-GCM',
      length: 128
    }, false, ['encrypt'])

    const levelKeyAB = await crypto.subtle.digest({name: 'SHA-512'}, Buffer.from(gameRandomSalt + '-key-' + i))
    const levelKey = Buffer.from(levelKeyAB).slice(0, 16)
    levelKeys.push(levelKey)

    const encryptedKey = await crypto.subtle.encrypt({
      name: 'AES-GCM',
      iv: salt
    }, encryptionKey, levelKey)
    encryptedLevelKeys.push(Buffer.from(encryptedKey))

    const thumbPath = path.resolve(DATA_FOLDER, `${i + 1}_thumb.png`)
    const thumbnailImage = await Jimp.read(thumbPath)
    const thumbnailData = await new Promise((resolve, reject) => {
      thumbnailImage.resize(64, 64).quality(50)
      .color([{apply: 'desaturate', params: [25]}])
      .getBuffer(Jimp.MIME_JPEG, (err, data) => {
        if (err) return reject(err)
        resolve(data)
      })
    })
    levelThumbnails.push(thumbnailData)
  }

  let thumbnailHeader
  sizeLoop: for (let i = 0; i < 1000; i++) {
    const testHeader = levelThumbnails[0].slice(0, i)
    for (let j = 1; j < levelThumbnails.length; j++) {
      if (Buffer.compare(testHeader, levelThumbnails[j].slice(0, i)) !== 0) break sizeLoop
      thumbnailHeader = testHeader
    }
  }

  for (let i = 0; i < levelCount; i++) {
    const secretParts = [verificationPrivateKeys[i]]
      .concat(levelShares[i], [levelThumbnails[i].slice(thumbnailHeader.length)])
    const secretData = Buffer.concat(secretParts)

    const wrappedKey = await crypto.subtle.importKey('raw', levelKeys[i], {name: 'AES-GCM'}, false, ['encrypt'])
    const encryptedData = await crypto.subtle.encrypt({
      name: 'AES-GCM',
      iv: levelSalts[i]
    }, wrappedKey, secretData)
    levelEncryptedData.push(Buffer.concat([levelSalts[i], new Uint8Array(encryptedData)]))
  }

  for (let lang of languages) {
    const languageSaltAB = await crypto.subtle.digest({name: 'SHA-512'}, Buffer.from(gameRandomSalt + '-language-' + lang))
    const languageSalt = Buffer.from(languageSaltAB.slice(0, 16))

    const gameData = {
      levels: [],
      hintThresholds,
      hintSalt: languageSalt.toString('base64'),
      thumbnailHeader: thumbnailHeader.toString('base64'),
      unlockedLevels
    }

    const configPath = SPREADSHEET_CSV_URL + SPREADSHEET_LANGUAGE_IDS[lang]
    const gameCSV = await fetch(configPath).then(e => e.text())
    const gameConfig = gameCSV.split(/[\r\n]+/g).slice(1).map(e => {
      return (e.match(/(?<=^|,)(?:"[^"]+"(?=(?:,|$))|[^",]+(?=(?:,|$)))/g) || []).map(e => {
        return e.replace(/^"|"$/g, '')
      })
    }).reduce((obj, element) => {
      if (element) obj[element[0]] = element.slice(2, -1)
      return obj
    }, {})

    for (let i = 0; i < levelCount; i++) {
      const levelConfig = gameConfig[i + 1]
      const plainHints = levelConfig.slice(0, 3)
      const encryptedHints = levelConfig.slice(3)

      for (let j = 0; j < encryptedHints.length; j++) {
        const hintKey = hintKeys[j]
        if (!hintKey) {
          console.log('Missing hint keys!')
          encryptedHints.splice(j, encryptedHints.length - j)
          continue
        }

        const encryptedData = await crypto.subtle.encrypt({
          name: 'AES-GCM',
          iv: Buffer.concat([languageSalt, levelSalts[i]])
        }, hintKey, Buffer.from(encryptedHints[j]))
        encryptedHints[j] = Buffer.from(encryptedData).toString('base64')
      }

      const level = {
        key: encryptedLevelKeys[i].toString('base64'),
        data: levelEncryptedData[i].toString('base64'),
        hints: plainHints.concat(encryptedHints),
        publicKey: verificationPublicKeys[i].toString('base64')
      }
      gameData.levels.push(level)
    }

    const basePath = path.resolve(BASE_HTML_FOLDER, `index-${lang}.html`)
    const baseHTML = await readFile(basePath, 'utf-8')

    const finalPath = path.resolve(FINAL_HTML_FOLDER, `index-${lang}.html`)
    const finalHTML = baseHTML.replace(JSON_PLACEHOLDER, e => e.replace('{}', JSON.stringify(gameData)))
    await writeFile(finalPath, finalHTML)
  }
}

async function getHash (imagePath) {
  let hash = ''
  const sizeMin = 5
  const sizeMax = 6
  const image = await Jimp.read(imagePath)
  const {width, height} = image.bitmap

  const isLandscape = width > height * 16 / 9
  const fixedWidth = isLandscape ? height * 16 / 9 : width
  const fixedHeight = isLandscape ? height : width * 9 / 16
  const startX = (width - fixedWidth) / 2
  const startY = (height - fixedHeight) / 2
  
  const debugImage = false && image.clone()
  if (debugImage) drawRetangle(debugImage, startX, startY, fixedWidth, fixedHeight, 0x00FF00FF)

  const rX = fixedWidth / sizeMax
  const rY = fixedHeight / sizeMax
  const padding = 0.25

  const grayValues = []
  for (let y = 0; y < sizeMax; y++) {
    for (let x = 0; x < sizeMax; x++) {
      if (x === sizeMax - 1 && y === 0) continue

      let valueSum = 0
      let pixelCount = 0
      const minX = Math.floor(startX + Math.max(0, x - padding) * rX)
      const maxX = Math.ceil(startX + Math.min(sizeMax, x + 1 + padding) * rX)
      const minY = Math.floor(startY + Math.max(0, y - padding) * rY)
      const maxY = Math.ceil(startY + Math.min(sizeMax, y + 1 + padding) * rY)
      
      if (debugImage) drawRetangle(debugImage, minX, minY, maxX - minX, maxY - minY, 0xFFFFFFFF)

      for (let y2 = minY; y2 < maxY; y2++) {
        for (let x2 = minX + (y2 % 2); x2 < maxX; x2 += 2) {
          if (debugImage) debugImage.setPixelColor(0xFF0000FF, x2, y2)
          const i = (x2 + y2 * width) * 4
          valueSum += 3 * image.bitmap.data[i] + 5 * image.bitmap.data[i + 1] + image.bitmap.data[i + 2]
          pixelCount++
        }
      }

      grayValues[x + y * sizeMax] = valueSum / pixelCount
    }
  }
  
  if (debugImage) debugImage.write(path.join('test', 'debug', path.basename(imagePath)))

  for (let y = 0; y < sizeMin; y++) {
    for (let x = 0; x < sizeMin; x++) {
      const pixelA = grayValues[x + (y + 1) * sizeMax]
      const pixelB = grayValues[x + 1 + (y + 1) * sizeMax]
      hash += pixelA < pixelB ? 1 : 0
    }
  }

  for (let x = 0; x < sizeMin; x++) {
    for (let y = 0; y < sizeMin; y++) {
      const pixelA = grayValues[x + y * sizeMax]
      const pixelB = grayValues[x + (y + 1) * sizeMax]
      hash += pixelA < pixelB ? 1 : 0
    }
  }

  return bin2arr(hash)
}

function drawRetangle (canvas, x, y, width, height, color) {
  function iterator (x, y) { 
    canvas.setPixelColor(color, x, y)
  }

  canvas.scan(x, y , width, 1, iterator)
  canvas.scan(x, y, 1, height, iterator)
  canvas.scan(x, y + height, width, 1, iterator)
  canvas.scan(x + width, y, 1, height, iterator)
}

function bin2arr (str) {
  const result = []
  const len = Math.ceil(str.length / 8)
  str = str.padEnd(len * 8, 0)
  for (let i = 0; i < len; i++) result[i] = parseInt(str.substr(i * 8, 8), 2)
  return new Uint8Array(result)
}

async function generateKeys () {
  const keyCount = Number(process.argv[3]) || 30
  const keys = []

  for (let i = 0; i < keyCount; i++) {
    const keyPair = await crypto.subtle.generateKey({
      name: 'ECDSA',
      namedCurve: 'P-256'
    }, true, ['sign', 'verify'])

    const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey)
    const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)

    keys.push({
      publicKey: Buffer.from(publicKey).toString('base64'),
      privateKey: Buffer.from(privateKey).toString('base64')
    })
  }

  console.log(JSON.stringify(keys))
}

if (process.argv[2] === '--generate-keys') {
  generateKeys()
} else {
  generateGame()
}

process.on('unhandledRejection', (err) => {
  throw err
})
