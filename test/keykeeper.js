'use strict';

const { test } = require('tap');
const crypto = require('node:crypto');
const { setTimeout: delay } = require('node:timers/promises');
const { KeyKeeper, ErrorCodes } = require('..');
const { decrypt } = require('../lib/cryptography/decrypt');

const secret = 'secret message';
const masterKey = crypto.randomBytes(32);
const userId = 12345678;
const pin = '123456abcdef';

const keyKeeper = new KeyKeeper({
  masterKey,
  cacheTimeMs: 0,
});

test('constructor', async (t) => {
  t.throws(() => new KeyKeeper({ masterKey: crypto.randomBytes(1) }));
});

test('should provide set and get methods', async (t) => {
  await keyKeeper.setSecret({ userId, decryptedSecret: secret, pin });
  const saved = await keyKeeper.getSecret(userId, pin);
  t.ok(await keyKeeper.cached(userId.toString()));
  t.not(saved, null);
  t.same(saved, secret);
});

test('should fetch data from encryptedStorage after cache cleaned', async (t) => {
  await keyKeeper.setSecret({ userId, decryptedSecret: secret, pin });
  await delay(1);
  t.equal(await keyKeeper.cached(userId.toString()), false);
  const saved = await keyKeeper.getSecret(userId, pin);
  t.not(saved, null);
  t.same(saved, secret);
});

test('getSecret with invalid userId', async (t) => {
  const userId = 1234;
  const secret = await keyKeeper.getSecret(userId, pin);
  t.equal(secret, null);
});

test('getAccount with invalid pin', async (t) => {
  const invalidPin = 'invalidPin';
  let error;
  try {
    await keyKeeper.setSecret({ userId, decryptedSecret: secret, pin });
    await delay(1);
    await keyKeeper.getSecret(userId, invalidPin);
  } catch (e) {
    error = e;
  }
  t.equal(error.code, ErrorCodes.WRONG_PIN);
});

test(`set new pin`, async ({ same }) => {
  const newPin = 'new_pin';
  await keyKeeper.setSecret({ userId, decryptedSecret: secret, pin });
  const secretFromOldKey = await keyKeeper.getSecret(userId, pin);
  await keyKeeper.changePin({
    userId,
    oldPin: pin,
    newPin,
  });
  const secretFromNewPing = await keyKeeper.getSecret(userId, newPin);
  same(secretFromOldKey, secretFromNewPing);
});

test('should return wrapped secret', async ({ same }) => {
  const secretWrapper = (secret) => ({
    secret,
  });
  const keyKeeperWithWrapper = new KeyKeeper({
    masterKey,
    secretWrapper,
  });
  await keyKeeperWithWrapper.setSecret({ userId, decryptedSecret: secret, pin });
  const wrappedSecret = await keyKeeperWithWrapper.getSecret(userId, pin);
  same(secretWrapper(secret), wrappedSecret);
  await keyKeeperWithWrapper.cleanCache();
});

test('should wrap operation into transaction', async ({ equal }) => {
  let savedData;
  const mockedTxClient = {
    set: (userId, encryptedData) => {
      savedData = encryptedData;
    },
  };
  // saving encrypted secret to savedData
  await keyKeeper.setSecret(
    {
      userId,
      decryptedSecret: secret,
      pin,
    },
    mockedTxClient,
  );
  const decryptedSavedData = await decrypt(savedData, masterKey, pin, 'utf8');
  await delay(1);
  const secretFromKK = await keyKeeper.getSecret(userId, pin);
  equal(decryptedSavedData, secretFromKK);
});

test('should save objects in different encodings', async ({ equal }) => {
  const encodings = ['base64', 'base64url', 'utf8', 'hex'];
  for (const secretEncoding of encodings) {
    const masterKey = crypto.randomBytes(32);
    const decryptedSecret = crypto.randomBytes(32).toString(secretEncoding);
    const kk = new KeyKeeper({
      masterKey,
      secretEncoding,
    });
    await kk.setSecret({
      userId,
      decryptedSecret,
      pin,
    });
    await delay(1);
    const secretFromKK = await kk.getSecret(userId, pin);
    equal(secretFromKK, decryptedSecret);
    await kk.cleanCache();
  }
});

test('change pin throw if unknown userId', async ({ equal }) => {
  let error;
  try {
    await keyKeeper.changePin({
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
    await keyKeeper.changePin({
      userId,
      oldPin: 'wrong_old_pin',
      newPin: 'new_pin',
    });
  } catch (e) {
    error = e;
  }
  equal(error.code, ErrorCodes.WRONG_PIN);
});
