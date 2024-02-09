'use strict';

const { test } = require('tap');
const { pinToKey } = require('../../lib/cryptography/pin-to-key');
const crypto = require('node:crypto');

test('generateDerivedKey - should reject if an error occurs in pbkdf2', async ({ equal }) => {
  // Mocking crypto.pbkdf2 to simulate an error
  const pbkdf2Mock = (pin, pinSalt, iterations, keyLength, digest, callback) => {
    callback(new Error('Mocked error'));
  };

  const originalPbkdf2 = crypto.pbkdf2;
  crypto.pbkdf2 = pbkdf2Mock;

  const pin = '123456';
  const pinSalt = 'somesalt';

  let error;
  try {
    await pinToKey(pin, pinSalt);
  } catch (e) {
    error = e;
  }
  equal(error.message, 'Mocked error');
  // Restore the original implementation of crypto.pbkdf2
  crypto.pbkdf2 = originalPbkdf2;
});
