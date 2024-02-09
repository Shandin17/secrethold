'use strict';

const { test } = require('tap');
const crypto = require('node:crypto');
const { setTimeout: delay } = require('node:timers/promises');
const { SecretHold, ErrorCodes } = require('..');
const { decrypt } = require('../lib/cryptography/decrypt');

const secret = 'secret message';
const masterKey = crypto.randomBytes(32);
const userId = 12345678;
const pin = '123456abcdef';

const secrethold = new SecretHold({
  masterKey,
  cacheTimeMs: 0,
});

test('constructor', async (t) => {
  t.throws(() => new SecretHold({ masterKey: crypto.randomBytes(1) }));
});

test('should provide set and get methods', async (t) => {
  await secrethold.setSecret({ userId, decryptedSecret: secret, pin });
  const saved = await secrethold.getSecret(userId, pin);
  t.ok(await secrethold.cached(userId.toString()));
  t.not(saved, null);
  t.same(saved, secret);
});

test('should fetch data from encryptedStorage after cache cleaned', async (t) => {
  await secrethold.setSecret({ userId, decryptedSecret: secret, pin });
  await delay(1);
  t.equal(await secrethold.cached(userId.toString()), false);
  const saved = await secrethold.getSecret(userId, pin);
  t.not(saved, null);
  t.same(saved, secret);
});

test('getSecret with invalid userId', async (t) => {
  const userId = 1234;
  const secret = await secrethold.getSecret(userId, pin);
  t.equal(secret, null);
});

test('getAccount with invalid pin', async (t) => {
  const invalidPin = 'invalidPin';
  let error;
  try {
    await secrethold.setSecret({ userId, decryptedSecret: secret, pin });
    await delay(1);
    await secrethold.getSecret(userId, invalidPin);
  } catch (e) {
    error = e;
  }
  t.equal(error.code, ErrorCodes.WRONG_PIN);
});

test(`set new pin`, async ({ same }) => {
  const newPin = 'new_pin';
  await secrethold.setSecret({ userId, decryptedSecret: secret, pin });
  const secretFromOldKey = await secrethold.getSecret(userId, pin);
  await secrethold.changePin({
    userId,
    oldPin: pin,
    newPin,
  });
  const secretFromNewPing = await secrethold.getSecret(userId, newPin);
  same(secretFromOldKey, secretFromNewPing);
});

test('should return wrapped secret', async ({ same }) => {
  const secretWrapper = (secret) => ({
    secret,
  });
  const secretHoldWithWrapper = new SecretHold({
    masterKey,
    secretWrapper,
    cacheTimeMs: 0,
  });
  await secretHoldWithWrapper.setSecret({ userId, decryptedSecret: secret, pin });
  const wrappedSecret = await secretHoldWithWrapper.getSecret(userId, pin);
  same(secretWrapper(secret), wrappedSecret);
  await secretHoldWithWrapper.cleanCache();
});

test('should wrap operation into transaction', async ({ equal }) => {
  let savedData;
  const mockedTxClient = {
    set: (userId, encryptedData) => {
      savedData = encryptedData;
    },
  };
  // saving encrypted secret to savedData
  await secrethold.setSecret(
    {
      userId,
      decryptedSecret: secret,
      pin,
    },
    mockedTxClient,
  );
  const decryptedSavedData = await decrypt(savedData, masterKey, pin, 'utf8');
  await delay(1);
  const secretFromKK = await secrethold.getSecret(userId, pin);
  equal(decryptedSavedData, secretFromKK);
});

test('should save objects in different encodings', async ({ equal }) => {
  const encodings = ['base64', 'base64url', 'utf8', 'hex'];
  for (const secretEncoding of encodings) {
    const masterKey = crypto.randomBytes(32);
    const decryptedSecret = crypto.randomBytes(32).toString(secretEncoding);
    const sh = new SecretHold({
      masterKey,
      secretEncoding,
      cacheTimeMs: 0,
    });
    await sh.setSecret({
      userId,
      decryptedSecret,
      pin,
    });
    await delay(1);
    const secretFromKK = await sh.getSecret(userId, pin);
    equal(secretFromKK, decryptedSecret);
    await sh.cleanCache();
  }
});

test('change pin throw if unknown userId', async ({ equal }) => {
  let error;
  try {
    await secrethold.changePin({
      userId: 99999999,
      oldPin: pin,
      newPin: 'new_pin',
    });
  } catch (e) {
    error = e;
  }
  equal(error.code, ErrorCodes.WRONG_USER_ID);
});

test('change pin throw if wrong old pin provided', async ({ equal }) => {
  let error;
  try {
    await secrethold.changePin({
      userId,
      oldPin: 'wrong_old_pin',
      newPin: 'new_pin',
    });
  } catch (e) {
    error = e;
  }
  equal(error.code, ErrorCodes.WRONG_PIN);
});

test('pin can be any utf8 string', async ({ equal }) => {
  const secretMessage = 'secret message';
  const pin = 'qwerty123';
  await secrethold.setSecret({
    userId,
    pin,
    decryptedSecret: secretMessage,
  });
  await delay(1);
  const received = await secrethold.getSecret(userId, pin);
  equal(secretMessage, received);
});
