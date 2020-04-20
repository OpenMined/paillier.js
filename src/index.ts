import BigInteger from "big-integer";
import * as random from "./random";

/**
 * Generates a pair private, public key for the Paillier cryptosystem.
 */
export function generateRandomKeys(bitLength = 3072, simpleVariant = false) {
  let p: BigInteger.BigInteger,
    q: BigInteger.BigInteger,
    n: BigInteger.BigInteger,
    phi: BigInteger.BigInteger,
    n2: BigInteger.BigInteger,
    g: BigInteger.BigInteger,
    lambda: BigInteger.BigInteger,
    mu: BigInteger.BigInteger;
  // if p and q are bitLength/2 long ->  2**(bitLength - 2) <= n < 2**(bitLength)
  do {
    p = random.prime(Math.floor(bitLength / 2) + 1);
    q = random.prime(Math.floor(bitLength / 2));
    n = p.times(q);
  } while (q.eq(p) || n.bitLength().neq(bitLength));

  phi = p.minus(1).times(q.minus(1));

  n2 = n.square();

  if (simpleVariant) {
    //If using p,q of equivalent length, a simpler variant of the key
    // generation steps would be to set
    // g=n+1, lambda=(p-1)(q-1), mu=lambda.invertm(n)
    g = n.plus(1);
    lambda = phi;
    mu = lambda.modInv(n);
  } else {
    g = getGenerator(n, n2);
    lambda = BigInteger.lcm(p.minus(1), q.minus(1));
    mu = L(g.modPow(lambda, n2), n).modInv(n);
  }

  const publicKey = new PublicKey(n, g);
  const privateKey = new PrivateKey(lambda, mu, publicKey, p, q);
  return { publicKey, privateKey };
}

function toBigInteger(num: BigInteger.BigNumber) {
  // ts compiler doesn't seem to like this very much...
  if (typeof num == "number") {
    return BigInteger(num);
  }
  if (typeof num == "string") {
    return BigInteger(num);
  }
  if (typeof num == "bigint") {
    return BigInteger(num);
  }
  return num;
}

/**
 * Class for a Paillier public key
 */
export class PublicKey {
  public n2: BigInteger.BigInteger;
  /**
   * Creates an instance of class PaillierPublicKey
   */
  constructor(
    public n: BigInteger.BigInteger,
    public g: BigInteger.BigInteger
  ) {
    this.n2 = n.square();
  }

  /**
   * Get the bit length of the public modulo
   */
  get bitLength() {
    return this.n.bitLength().toJSNumber();
  }

  /**
   * Paillier public-key encryption
   */
  encrypt(m: BigInteger.BigNumber) {
    return this.g
      .modPow(m, this.n2)
      .times(random.randBetween(this.n).modPow(this.n, this.n2))
      .mod(this.n2);
  }

  /**
   * Homomorphic addition
   */
  addition(...ciphertexts: BigInteger.BigNumber[]) {
    // ciphertexts of numbers
    return ciphertexts.reduce(
      (sum: BigInteger.BigInteger, next) => sum.times(next).mod(this.n2),
      BigInteger.one
    );
  }

  /**
   * Pseudo-homomorphic Paillier multiplication
   */
  multiply(c: BigInteger.BigNumber, k: BigInteger.BigNumber) {
    // Insecure naive multiplication: c^0 % n^2 === 1
    // Ensures we return an encrypted 0
    if (k.toString() === '0') {
      return this.encrypt(BigInteger.zero);
    }
    // // Insecure naive multiplication: c^1 % n^2 === c
    // // Ensures we return a different encrypted c
    if (k.toString() === '1') {
      const encryptedZero = this.encrypt(BigInteger.zero);
      return this.addition(toBigInteger(c), encryptedZero);
    }
    
    // c is ciphertext. k is either a cleartext message (number) or a scalar
    return toBigInteger(c).modPow(k, this.n2);
  }
}

/**
 * Class for Paillier private keys.
 */
export class PrivateKey {
  /**
   * Creates an instance of class PaillierPrivateKey
   */
  constructor(
    public lambda: BigInteger.BigInteger,
    public mu: BigInteger.BigInteger,
    public publicKey: PublicKey,
    public p: BigInteger.BigInteger | null = null,
    public q: BigInteger.BigInteger | null = null
  ) {}

  /**
   * Get the bit length of the public modulo
   */
  get bitLength() {
    return this.publicKey.n.bitLength().toJSNumber();
  }

  /**
   * Get the public modulo n=p?q
   */
  get n() {
    return this.publicKey.n;
  }

  /**
   * Paillier private-key decryption
   */
  decrypt(c: BigInteger.BigNumber) {
    return L(
      toBigInteger(c).modPow(this.lambda, this.publicKey.n2),
      this.publicKey.n
    )
      .times(this.mu)
      .mod(this.publicKey.n);
  }
}

function L(a: BigInteger.BigInteger, n: BigInteger.BigInteger) {
  return a.minus(1).divide(n);
}

function getGenerator(n: BigInteger.BigInteger, n2: BigInteger.BigInteger) {
  const alpha = random.randBetween(n);
  const beta = random.randBetween(n);
  const left = alpha.times(n).plus(1);
  const mp = beta.modPow(n, n2);
  return left.times(mp).mod(n2);
}
