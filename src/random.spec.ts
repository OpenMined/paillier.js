import BigInteger from "big-integer";
import "jest";
import * as random from "./random";

test.each([256, 512, 1024, 2048, 3072, 4096])("prime", bitLength => {
  expect(
    random
      .prime(bitLength, 1)
      .bitLength()
      .toJSNumber()
  ).toEqual(bitLength);
});

test("randBetween", () => {
  const x = random.randBetween(BigInteger(1000000)).toJSNumber();
  const y = random.randBetween(BigInteger(1000000)).toJSNumber();
  expect(x).not.toEqual(y);
  expect(x).toBeLessThan(1000000);
  expect(y).toBeLessThan(1000000);
});
