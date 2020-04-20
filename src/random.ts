import BigInteger from "big-integer";

function getRandomValues(buf: Uint8Array) {
  if (typeof self !== "undefined" && typeof self.crypto !== "undefined") {
    // Works for both browser (window) and React Native (global).
    self.crypto.getRandomValues(buf);
  } else {
    require("crypto").randomFillSync(buf);
  }
}

/**
 * A probably-prime (Miller-Rabin), cryptographically-secure, random-number generator.
 */
export function prime(
  bitLength: number,
  iterations = 16
): BigInteger.BigInteger {
  if (bitLength < 1)
    throw new RangeError(`bitLength MUST be > 0 and it is ${bitLength}`);

  let rnd = BigInteger.zero;
  do {
    rnd = fromBuffer(randBytes(bitLength / 8, true)).or(BigInteger.one);
  } while (!rnd.isProbablePrime(iterations));
  return rnd;
}

/**
 * Secure random bits for both node and browsers. Node version uses crypto.randomFill() and browser one self.crypto.getRandomValues()
 */
function randBits(bitLength: number, forceLength = false): Uint8Array {
  if (bitLength < 1)
    throw new RangeError(`bitLength MUST be > 0 and it is ${bitLength}`);

  const byteLength = Math.ceil(bitLength / 8);
  let rndBytes = randBytes(byteLength, false);
  // Fill with 0's the extra bits
  rndBytes[0] = rndBytes[0] & (2 ** (bitLength % 8) - 1);
  if (forceLength) {
    let mask = bitLength % 8 ? 2 ** ((bitLength % 8) - 1) : 128;
    rndBytes[0] = rndBytes[0] | mask;
  }
  return rndBytes;
}

/**
 * Secure random bytes for both node and browsers. Node version uses crypto.randomFill() and browser one self.crypto.getRandomValues()
 */
function randBytes(byteLength: number, forceLength = false) {
  if (byteLength < 1)
    throw new RangeError(`byteLength MUST be > 0 and it is ${byteLength}`);

  const buf = new Uint8Array(byteLength);
  getRandomValues(buf);
  // If fixed length is required we put the first bit to 1 -> to get the necessary bitLength
  if (forceLength) buf[0] = buf[0] | 128;
  return buf;
}

/**
 * Returns a cryptographically secure random integer between [min,max]
 */
export function randBetween(max: BigInteger.BigInteger, min = BigInteger.one) {
  if (max.leq(min)) throw new Error("max must be > min");
  const interval = max.minus(min);
  let bitLen = interval.bitLength().toJSNumber();
  let rnd: BigInteger.BigInteger;
  do {
    let buf = randBits(bitLen);
    rnd = fromBuffer(buf);
  } while (rnd.gt(interval));
  return rnd.plus(min);
}

function fromBuffer(buf: Uint8Array): BigInteger.BigInteger {
  let ret = BigInteger.zero;
  buf.forEach(i => {
    ret = ret.shiftLeft(8).plus(i);
  });
  return ret;
}
