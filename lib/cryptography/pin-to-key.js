'use strict';

const crypto = require('node:crypto');
const {
  keyLength: keyLengthDefault,
  pinToKeyDigest,
  pinToKeyIterations,
} = require('./constants.js');

function pinToKey(
  pin,
  pinSalt,
  iterations = pinToKeyIterations,
  keyLength = keyLengthDefault,
  digest = pinToKeyDigest,
) {
  return new Promise((resolve, reject) => {
    const normalizedPin = pin.normalize();
    crypto.pbkdf2(normalizedPin, pinSalt, iterations, keyLength, digest, (err, derivedKey) => {
      if (err) {
        reject(err);
      } else {
        resolve(derivedKey);
      }
    });
  });
}

module.exports = {
  pinToKey,
};
