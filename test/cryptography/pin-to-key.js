'use strict';

const crypto = require('node:crypto');
const { test } = require('tap');
const { pinToKey } = require('../../lib/cryptography/pin-to-key');
const { pinToKeyIterations, keyLength } = require('../../lib/cryptography/constants');

test('should derive a cryptographic key from a password using PBKDF2', async (t) => {
  const pin = '123456';
  const salt = crypto.randomBytes(16);
  const iterations = pinToKeyIterations;
  const digest = 'sha256';

  const derivedKey = await pinToKey(pin, salt, iterations, keyLength, digest);
  const expectedKey = crypto.pbkdf2Sync(pin.normalize(), salt, iterations, keyLength, digest);

  t.same(derivedKey, expectedKey);
});

test('throws error when invalid digest', async (t) => {
  const pin = '123456';
  const salt = '0xabcdef';
  const iterations = 1;
  const digest = 'invalidDigest';
  let error;
  try {
    await pinToKey(pin, salt, iterations, keyLength, digest);
  } catch (e) {
    error = e;
  }
  t.ok(error);
});
