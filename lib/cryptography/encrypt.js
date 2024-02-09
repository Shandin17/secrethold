'use strict';

const crypto = require('node:crypto');
const { holdCryptoAlgorithm, saltLength } = require('./constants.js');
const { pinToKey } = require('./pin-to-key.js');

async function encrypt(data, masterKey, pin, pinSalt, secretsEncoding) {
  // Master key layer
  const ivMaster = crypto.randomBytes(saltLength);
  const cipherMaster = crypto.createCipheriv(holdCryptoAlgorithm, masterKey, ivMaster);
  let encryptedWithMK = cipherMaster.update(data, secretsEncoding, 'base64url');
  encryptedWithMK += cipherMaster.final('base64url');
  encryptedWithMK = ivMaster.toString('base64url') + ':' + encryptedWithMK;

  // Pin code layer
  const keyFromPin = await pinToKey(pin, pinSalt);
  // Input data encoding is utf8 because data is encrypted in '123f:32f' format
  const iv = crypto.randomBytes(saltLength);
  const cipher = crypto.createCipheriv(holdCryptoAlgorithm, keyFromPin, iv);
  let encrypted = cipher.update(encryptedWithMK, 'utf8', 'base64url');
  encrypted += cipher.final('base64url');
  encrypted = iv.toString('base64url') + ':' + encrypted;
  return pinSalt.toString('base64url') + ':' + encrypted;
}

module.exports = {
  encrypt,
};
