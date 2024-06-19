'use strict';

const { test } = require('tap');
const stream = require('node:stream');
const crypto = require('node:crypto');
const { encrypt } = require('../../lib/cryptography/encrypt');
const { CryptoConstants } = require('../../');
const { decrypt } = require('../../lib/cryptography/decrypt');

function* charGenerator(char, times) {
  for (let i = 0; i < times; i++) {
    yield char;
  }
}

test('encryption function should work with readable stream', async ({ equal }) => {
  const char = 'A';
  const times = 10_000;
  const expectedString = char.repeat(times);
  const source = stream.Readable.from(charGenerator(char, times));
  const masterKey = crypto.randomBytes(CryptoConstants.keyLength);
  const iv = crypto.randomBytes(CryptoConstants.saltLength);
  const pinSalt = crypto.randomBytes(CryptoConstants.saltLength);
  const pin = '123456';

  // encrypting
  const { pinTagPromise, masterTagPromise, encryptedStream } = await encrypt({
    source,
    masterKey,
    iv,
    pinSalt,
    pin,
  });
  const encryptedBuffs = [];
  for await (const chunk of encryptedStream) {
    encryptedBuffs.push(chunk);
  }
  const [masterTag, pinTag] = await Promise.all([masterTagPromise, pinTagPromise]);
  const encryptedSource = stream.Readable.from(Buffer.concat(encryptedBuffs));

  // decrypting
  const decryptedStream = await decrypt({
    encryptedSource,
    iv,
    pinSalt,
    pin,
    masterKey,
    masterTag,
    pinTag,
  });
  const decryptedBuffs = [];
  for await (const chunk of decryptedStream) {
    decryptedBuffs.push(chunk);
  }
  const decryptedData = Buffer.concat(decryptedBuffs).toString();
  equal(decryptedData, expectedString);
});
