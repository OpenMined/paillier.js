import BigInteger from "big-integer";
import "jest";
import * as paillierBigint from "./index";

test.each([1024, 2048, 3072])("Paillier keys", bitLength => {
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
});
