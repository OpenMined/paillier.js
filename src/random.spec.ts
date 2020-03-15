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
