'use strict';

const crypto = require('node:crypto');
const { holdCryptoAlgorithm } = require('./constants.js');
const { pinToKey } = require('./pin-to-key.js');

async function decrypt(encryptedData, masterKey, pin, secretsEncoding) {
  // Pin code layer
  const [pinSalt, ivPin, encryptedPin] = encryptedData.split(':');
  const keyFromPin = await pinToKey(pin, Buffer.from(pinSalt, 'base64'));
  const decipherWithPin = crypto.createDecipheriv(
    holdCryptoAlgorithm,
    keyFromPin,
    Buffer.from(ivPin, 'base64'),
  );

  // Decrypted data encoding is utf8 because encrypted data in '123f:32f' format
  let decryptedWithPin = decipherWithPin.update(encryptedPin, 'base64', 'utf8');
  decryptedWithPin += decipherWithPin.final('utf8');

  // Master key layer
  const [iv, encrypted] = decryptedWithPin.split(':');
  const decipherWithMasterKey = crypto.createDecipheriv(
    holdCryptoAlgorithm,
    masterKey,
    Buffer.from(iv, 'base64'),
  );
  let decrypted = decipherWithMasterKey.update(encrypted, 'base64', secretsEncoding);
  decrypted += decipherWithMasterKey.final(secretsEncoding);
  return decrypted;
}

module.exports = {
  decrypt,
};
