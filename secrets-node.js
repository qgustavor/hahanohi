// secrets.js - by Alexander Stetsyuk - released under MIT License
const defaults = {
  bits: 8, // default number of bits
  radix: 16, // work with HEX by default
  minBits: 3,
  maxBits: 20, // this permits 1,048,575 shares, though going this high is NOT recommended in JS!
  bytesPerChar: 2,
  maxBytesPerChar: 6, // Math.pow(256, 7) > Math.pow(2, 53)

  // Primitive polynomials (in decimal form) for Galois Fields GF(2^n), for 2 <= n <= 30
  // The index of each term in the array corresponds to the n for that polynomial
  // i.e. to get the polynomial for n=16, use primitivePolynomials[16]
  primitivePolynomials: [null, null, 1, 3, 3, 5, 3, 3, 29, 17, 9, 5, 83, 27, 43, 3, 45, 9, 39, 39, 9, 5, 3, 33, 27, 9, 71, 39, 9, 5, 83]
}

// Protected settings object
let radix
let bits
let size
let max
let logs
let exps

function init (_bits = defaults.bits) {
  radix = defaults.radix
  bits = _bits
  size = 2 ** bits
  max = size - 1

  // Construct the exp and log tables for multiplication.
  logs = []
  exps = []
  let x = 1

  const primitive = defaults.primitivePolynomials[bits]
  for (let i = 0; i < size; i++) {
    exps[i] = x
    logs[x] = i
    x <<= 1
    if (x >= size) {
      x ^= primitive
      x &= max
    }
  }
}

const randomBits = require('crypto').randomBytes
function rng (bits) {
  const bytes = Math.ceil(bits / 8)
  return Array.from(randomBits(bytes)).map(e => e.toString(2).padStart(8, 0)).join('').substr(0, bits)
}

// Divides a `secret` number String str expressed in radix `inputRadix` (optional, default 16)
// into `numShares` shares, each expressed in radix `outputRadix` (optional, default to `inputRadix`),
// requiring `threshold` number of shares to reconstruct the secret.
// Optionally, zero-pads the secret to a length that is a multiple of padLength before sharing.
function share (secret, numShares, threshold, padLength = 0) {
  if (!(secret instanceof Uint8Array)) throw new Error('Secret must be a Uint8Array.')
  if (typeof numShares !== 'number' || numShares % 1 !== 0 || numShares < 2) {
    throw new Error(`Number of shares must be an integer between 2 and 2^bits-1 (${max}), inclusive.`)
  }

  if (numShares > max) {
    const neededBits = Math.ceil(Math.log(numShares + 1) / Math.LN2)
    throw new Error(`Number of shares must be an integer between 2 and 2^bits-1 (${max}), inclusive. To create ${numShares} shares, use at least ${neededBits} bits.`)
  }

  if (typeof threshold !== 'number' || threshold % 1 !== 0 || threshold < 2) {
    throw new Error(`Threshold number of shares must be an integer between 2 and 2^bits-1 (${max}), inclusive.`)
  }

  if (threshold > max) {
    const neededBits = Math.ceil(Math.log(threshold + 1) / Math.LN2)
    throw new Error(`Threshold number of shares must be an integer between 2 and 2^bits-1 (${max}), inclusive.  To use a threshold of ${threshold}, use at least ${neededBits} bits.`)
  }

  if (typeof padLength !== 'number' || padLength % 1 !== 0) {
    throw new Error('Zero-pad length must be an integer greater than 1.')
  }

  // append a 1 so that we can preserve the correct number of leading zeros in our secret
  secret = '1' + arr2bin(secret)
  secret = split(secret, padLength)

  const x = new Array(numShares)
  const y = new Array(numShares)
  for (var i = 0, len = secret.length; i < len; i++) {
    const subShares = _getShares(secret[i], numShares, threshold)
    for (let j = 0; j < numShares; j++) {
      x[j] = x[j] || subShares[j].x
      y[j] = subShares[j].y.toString(2).padStart(bits, 0) + (y[j] || '')
    }
  }

  for (let i = 0; i < numShares; i++) {
    x[i] = Buffer.concat([new Uint8Array([x[i]]), bin2arr(y[i])])
  }
  return x
}

// This is the basic polynomial generation and evaluation function
// for a `bits`-length secret (NOT an arbitrary length)
// Note: no error-checking at this stage! If `secrets` is NOT
// a NUMBER less than 2^bits-1, the output will be incorrect!
function _getShares (secret, numShares, threshold) {
  const shares = []
  const coeffs = [secret]
  for (let i = 1; i < threshold; i++) {
    coeffs[i] = parseInt(rng(bits), 2)
  }
  for (let i = 1, len = numShares + 1; i < len; i++) {
    shares[i - 1] = {
      x: i,
      y: horner(i, coeffs)
    }
  }
  return shares
}

// Polynomial evaluation at `x` using Horner's Method
// TODO: this can possibly be sped up using other methods
// NOTE: fx=fx * x + coeff[i] ->  exp(log(fx) + log(x)) + coeff[i],
//       so if fx===0, just set fx to coeff[i] because
//       using the exp/log form will result in incorrect value
function horner (x, coeffs) {
  const logx = logs[x]
  let fx = 0
  for (let i = coeffs.length - 1; i >= 0; i--) {
    if (fx === 0) {
      fx = coeffs[i]
      continue
    }
    fx = exps[(logx + logs[fx]) % max] ^ coeffs[i]
  }
  return fx
}

// Protected method that evaluates the Lagrange interpolation
// polynomial at x=`at` for individual bits-length
// segments of each share in the `shares` Array.
// Each share is expressed in base `inputRadix`. The output
// is expressed in base `outputRadix'
function combine (shares, setBits = bits) {
  const x = []
  const y = []
  let result = ''
  if (bits !== setBits) init(setBits)

  for (let i = 0, len = shares.length; i < len; i++) {
    let share = shares[i]
    let idx = x.push(share[0]) - 1
    share = split(arr2bin(share.slice(1)))
    for (let j = 0, len2 = share.length; j < len2; j++) {
      y[j] = y[j] || []
      y[j][idx] = share[j]
    }
  }
  for (let i = 0, len = y.length; i < len; i++) {
    result = lagrange(0, x, y[i]).toString(2).padStart(bits, 0) + result
  }

  const idx = result.indexOf('1') // find the first 1
  return bin2arr(result.slice(idx + 1))
}

// Data is internally stored as a string containing only zeros and ones
function bin2arr (str) {
  return new Uint8Array(str.match(/.{8}/g).map(e => parseInt(e, 2)))
}

function arr2bin (str) {
  return Array.from(str).map(e => e.toString(2).padStart(8, 0)).join('')
}

// Evaluate the Lagrange interpolation polynomial at x = `at`
// using x and y Arrays that are of the same length, with
// corresponding elements constituting points on the polynomial.
function lagrange (at, x, y) {
  let sum = 0
  let product
  for (let i = 0, len = x.length; i < len; i++) {
    if (!y[i]) continue

    product = logs[y[i]]
    for (let j = 0; j < len; j++) {
      if (i === j) continue
      if (at === x[j]) { // happens when computing a share that is in the list of shares used to compute it
        product = -1 // fix for a zero product term, after which the sum should be sum^0 = sum, not sum^1
        break
      }
      product = ((product + logs[at ^ x[j]] -
        logs[x[i] ^ x[j]] + max) /* to make sure it's not negative */) % max
    }
    // though exps[-1]= undefined and undefined ^ anything = anything in chrome, this behavior may not hold everywhere, so do the check
    sum = product === -1 ? sum : sum ^ exps[product]
  }
  return sum
}

// Splits a number string `bits`-length segments, after first
// optionally zero-padding it to a length that is a multiple of `padLength.
// Returns array of integers (each less than 2^bits-1), with each element
// representing a `bits`-length segment of the input string from right to left,
// i.e. parts[0] represents the right-most `bits`-length segment of the input string.
function split (str, padLength) {
  if (padLength) str = str.padStart(padLength, 0)
  const parts = []
  for (var i = str.length; i > bits; i -= bits) {
    parts.push(parseInt(str.slice(i - bits, i), 2))
  }
  parts.push(parseInt(str.slice(0, i), 2))
  return parts
}

// by default, initialize without an RNG
init()
module.exports.share = share
module.exports.combine = combine

/* const key = randomBits(16)
console.log(key)
console.log('key length: %d', key.length)

const shares = share(key, 10, 5)
console.log('share length: %d', shares[0].length)

const base64Shares = shares.map(arrToBase64)
console.log(base64Shares)

for (let i = 0; i < 10; i++) {
  const newShares = shuffle(base64Shares).slice(0, 5)
  const result = combine(newShares.map(e => Buffer.from(e, 'base64')))

  const isDifferent = !!Buffer.compare(key, result)
  console.log(Buffer.from(result), isDifferent ? 'different!' : 'equal')
  if (isDifferent) break
}

function arrToBase64 (arr) {
  return arr.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}
function shuffle (a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a
} */
