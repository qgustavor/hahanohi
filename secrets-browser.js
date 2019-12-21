// secrets.js - by Alexander Stetsyuk - released under MIT License
// Simplified to work only with 8 bits and using typed arrays instead of hexadecimal strings
const bits = 8
const size = 2 ** bits
const max = size - 1
const exps = []
const logs = []

// Construct the exp and log tables for multiplication.
let x = 1
for (let i = 0; i < size; i++) {
  exps[i] = x
  logs[x] = i
  x <<= 1
  if (x >= size) {
    x ^= 29
    x &= max
  }
}

// Protected method that evaluates the Lagrange interpolation
// polynomial at x=`at` for individual bits-length
// segments of each share in the `shares` Array.
function combine (shares) {
  const x = []
  const y = []
  let result = ''

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
      product = ((product + logs[at ^ x[j]] - logs[x[i] ^ x[j]] + max) /* to make sure it's not negative */) % max
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
