import BigInteger from "big-integer";
import "jest";
import * as paillierBigint from "./index";

describe('Paillier', () => {
  test('should return a cipher when multiplied by a plain 0', () => {
    const keyPair = paillierBigint.generateRandomKeys(1024);
    const number = BigInteger(10)
    const cipher = keyPair.publicKey.encrypt(number);
    const encMul = keyPair.publicKey.multiply(cipher, 0);
    expect(encMul).not.toEqual(BigInteger(1))
    const d = keyPair.privateKey.decrypt(encMul);
    expect(d).toEqual(BigInteger(0));
  })
  test('should return a different cipher when multiplied by a plain 1', () => {
    const keyPair = paillierBigint.generateRandomKeys(1024);
    const number = BigInteger(10)
    const cipher = keyPair.publicKey.encrypt(number);
    const encMul = keyPair.publicKey.multiply(cipher, 1);
    expect(encMul).not.toEqual(cipher)
    const d = keyPair.privateKey.decrypt(encMul);
    expect(d).toEqual(number);
  })
  test.each([1024, 2048, 3072])('Paillier keys with bitLength %p', bitLength => {
    const tests = 8;
    let numbers: BigInteger.BigInteger[] = [];
    let ciphertexts: BigInteger.BigInteger[] = [];
  
    const keyPair = paillierBigint.generateRandomKeys(bitLength);
    expect(keyPair.publicKey).toBeInstanceOf(paillierBigint.PublicKey);
    expect(keyPair.privateKey).toBeInstanceOf(paillierBigint.PrivateKey);
    expect(keyPair.publicKey.bitLength).toEqual(bitLength);
  
    for (let i = 0; i < tests; i++) {
      numbers[i] = BigInteger.randBetween(1, keyPair.publicKey.n);
      ciphertexts[i] = keyPair.publicKey.encrypt(numbers[i]);
      const decrypted = keyPair.privateKey.decrypt(ciphertexts[i]);
      expect(numbers[i]).toEqual(decrypted);
    }
  
    const encSum = keyPair.publicKey.addition(...ciphertexts);
    let d = keyPair.privateKey.decrypt(encSum);
    const sumNumbers = numbers.reduce((sum, next) =>
      sum.plus(next).mod(keyPair.publicKey.n)
    );
    expect(d).toEqual(sumNumbers);
  
    for (let i = 0; i < numbers.length; i++) {
      const encMul = keyPair.publicKey.multiply(ciphertexts[i], numbers[i]);
      const d = keyPair.privateKey.decrypt(encMul);
      expect(d).toEqual(numbers[i].modPow(2, keyPair.publicKey.n));
    }
  })
})
