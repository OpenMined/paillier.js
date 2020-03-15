# paillier-pure

This is a pure JS implementation of [paillier-bigint](https://github.com/juanelas/paillier-bigint). This version has no dependencies on `bigint` or `worker`, making it suitable for use in React Native or other constrained environments.

**NOTE: The tradeoff of using this library over the bigint is that this library is relatively slow.**

## Installing

Install a [getRandomValues()](https://github.com/LinusU/react-native-get-random-values#readme) polyfill if necessary.

Then install the library

```
npm install paillier-pure
```
