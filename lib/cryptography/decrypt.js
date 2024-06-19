'use strict';

const crypto = require('node:crypto');
const { holdCryptoAlgorithm } = require('./constants.js');
const { pinToKey } = require('./pin-to-key.js');
const { Readable } = require('node:stream');

async function decrypt({ encryptedSource, masterKey, pin, pinSalt, iv, pinTag, masterTag }) {
  const keyFromPin = await pinToKey(pin, pinSalt);
  const decipherPin = crypto.createDecipheriv(holdCryptoAlgorithm, keyFromPin, iv);
  const decipherMaster = crypto.createDecipheriv(holdCryptoAlgorithm, masterKey, iv);
  decipherPin.setAuthTag(pinTag);
  decipherMaster.setAuthTag(masterTag);
  const dataStream =
    encryptedSource instanceof Readable ? encryptedSource : Readable.from(encryptedSource);
  return dataStream.pipe(decipherMaster).pipe(decipherPin);
}

module.exports = {
  decrypt,
};
