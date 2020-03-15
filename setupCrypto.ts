import crypto from "crypto";

Object.defineProperty(self, "crypto", {
  value: {
    getRandomValues(arr: Uint8Array) {
      crypto.randomFillSync(arr);
    }
  }
});
