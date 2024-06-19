'use strict';

const crypto = require('node:crypto');
const { holdCryptoAlgorithm } = require('./constants.js');
const { pinToKey } = require('./pin-to-key.js');
const { Readable } = require('node:stream');

async function encrypt({ source, masterKey, pin, iv, pinSalt }) {
  const keyFromPin = await pinToKey(pin, pinSalt);
  const cipherPin = crypto.createCipheriv(holdCryptoAlgorithm, keyFromPin, iv);
  const cipherMaster = crypto.createCipheriv(holdCryptoAlgorithm, masterKey, iv);
  const pinTagPromise = new Promise((resolve, reject) => {
    cipherPin.on('end', () => resolve(cipherPin.getAuthTag()));
    cipherPin.on('error', reject);
  });
  const masterTagPromise = new Promise((resolve, reject) => {
    cipherMaster.on('end', () => resolve(cipherMaster.getAuthTag()));
    cipherMaster.on('error', reject);
  });
  const dataStream = source instanceof Readable ? source : Readable.from(source);

  return {
    encryptedStream: dataStream.pipe(cipherPin).pipe(cipherMaster),
    pinTagPromise,
    masterTagPromise,
  };
}

module.exports = {
  encrypt,
};
