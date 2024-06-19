'use strict';

const { test } = require('tap');
const crypto = require('node:crypto');
const { setTimeout: delay } = require('node:timers/promises');
const { Secrethold, ErrorCodes } = require('..');
const { decrypt } = require('../lib/cryptography/decrypt');
const localStorage = require('../lib/local-encrypted-storage');
const stream = require('node:stream');

const secret = 'secret message';
const masterKey = crypto.randomBytes(32);
const id = 12345678;
const pin = '123456abcdef';

const encryptedStorage = localStorage();
const secretEncoding = 'utf8';
const encryptedDataEncoding = 'base64url';

const secrethold = new Secrethold({
  masterKey,
  encryptedStorage,
  secretEncoding,
  encryptedDataEncoding,
});

test('constructor', async (t) => {
  t.throws(() => new Secrethold({ masterKey: crypto.randomBytes(1) }));
});

test('should provide set and get methods', async (t) => {
  await secrethold.setSecret({ id, decryptedSecret: secret, pin });
  const saved = await secrethold.getSecret(id, pin);
  t.same(saved, secret);
});

test('getSecret with invalid id', async (t) => {
  const id = 1234;
  const secret = await secrethold.getSecret(id, pin);
  t.equal(secret, null);
});

test('getAccount with invalid pin', async (t) => {
  const invalidPin = 'invalidPin';
  let error;
  try {
    await secrethold.setSecret({ id, decryptedSecret: secret, pin });
    await delay(1);
    const secret1 = await secrethold.getSecret(id, invalidPin);
    console.log(secret1);
  } catch (e) {
    error = e;
  }
  t.equal(error.code, ErrorCodes.WRONG_PIN);
});

test(`set new pin`, async ({ same }) => {
  const newPin = 'new_pin';
  await secrethold.setSecret({ id, decryptedSecret: secret, pin });
  const secretFromOldKey = await secrethold.getSecret(id, pin);
  await secrethold.changePin({
    id,
    oldPin: pin,
    newPin,
  });
  const secretFromNewPing = await secrethold.getSecret(id, newPin);
  same(secretFromOldKey, secretFromNewPing);
});

test('should wrap setting new pin into transaction', async ({ equal }) => {
  await secrethold.setSecret({
    id,
    decryptedSecret: secret,
    pin,
  });
  const newPin = 'new_pin';
  let savedData;
  const mockedTxClient = {
    set: (id, encryptedData) => {
      savedData = encryptedData;
    },
  };
  await secrethold.changePin(
    {
      id,
      oldPin: pin,
      newPin,
    },
    mockedTxClient,
  );
  const decryptedDataWithNewPin = await secrethold.getSecret(id, newPin);
  const [pinSalt, iv, masterTag, pinTag, encryptedSecret] = savedData.split(':');
  const decryptedStream = await decrypt({
    encryptedSource: Buffer.from(encryptedSecret, encryptedDataEncoding),
    masterKey,
    pin: newPin,
    pinSalt: Buffer.from(pinSalt, encryptedDataEncoding),
    iv: Buffer.from(iv, encryptedDataEncoding),
    pinTag: Buffer.from(pinTag, encryptedDataEncoding),
    masterTag: Buffer.from(masterTag, encryptedDataEncoding),
  });
  const decryptedBuffs = [];
  for await (const chunk of decryptedStream) {
    decryptedBuffs.push(chunk);
  }
  const decryptedSavedData = Buffer.concat(decryptedBuffs).toString(secretEncoding);
  equal(decryptedDataWithNewPin, decryptedSavedData);
});

test('should return wrapped secret', async ({ same }) => {
  const secretWrapper = (secret) => ({
    secret,
  });
  const secretHoldWithWrapper = new Secrethold({
    masterKey,
    secretWrapper,
    cacheTimeMs: 0,
  });
  await secretHoldWithWrapper.setSecret({ id, decryptedSecret: secret, pin });
  const wrappedSecret = await secretHoldWithWrapper.getSecret(id, pin);
  same(secretWrapper(secret), wrappedSecret);
});

test('should wrap operation into transaction', async ({ equal }) => {
  let savedData;
  const mockedTxClient = {
    set: (id, encryptedData) => {
      savedData = encryptedData;
    },
  };
  // saving encrypted secret to savedData
  await secrethold.setSecret(
    {
      id,
      decryptedSecret: secret,
      pin,
    },
    mockedTxClient,
  );
  const encryptedSecret = await encryptedStorage.getEncryptedData(id);
  equal(encryptedSecret, savedData);
});

test('should save objects in different encodings', async ({ equal }) => {
  const encodings = ['base64', 'base64url', 'utf8', 'hex'];
  for (const secretEncoding of encodings) {
    const masterKey = crypto.randomBytes(32);
    const decryptedSecret = crypto.randomBytes(32).toString(secretEncoding);
    const sh = new Secrethold({
      masterKey,
      secretEncoding,
      cacheTimeMs: 0,
    });
    await sh.setSecret({
      id,
      decryptedSecret,
      pin,
    });
    await delay(1);
    const secretFromKK = await sh.getSecret(id, pin);
    equal(secretFromKK, decryptedSecret);
    const newPin = 'new_pin';
    await sh.changePin({
      id,
      oldPin: pin,
      newPin,
    });
    const secretFromNewPin = await sh.getSecret(id, newPin);
    equal(secretFromNewPin, secretFromKK);
  }
});

test('change pin throw if unknown id', async ({ equal }) => {
  let error;
  try {
    await secrethold.changePin({
      id: 99999999,
      oldPin: pin,
      newPin: 'new_pin',
    });
  } catch (e) {
    error = e;
  }
  equal(error.code, ErrorCodes.WRONG_ID);
});

test('change pin throw if wrong old pin provided', async ({ equal }) => {
  let error;
  try {
    await secrethold.changePin({
      id,
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
    id,
    pin,
    decryptedSecret: secretMessage,
  });
  await delay(1);
  const received = await secrethold.getSecret(id, pin);
  equal(secretMessage, received);
});

test('should delete secret', async ({ equal }) => {
  const secrethold = new Secrethold({
    masterKey,
  });
  await secrethold.setSecret({
    id,
    decryptedSecret: secret,
    pin,
  });
  await secrethold.delSecret(id);
  equal(await secrethold.getSecret(id, pin), null);
});

test('should wrap delete in transaction', async ({ equal }) => {
  let savedData;
  const mockedTxClient = {
    set: (id, encryptedData) => {
      savedData = encryptedData;
    },
    del: () => {
      savedData = null;
    },
  };
  // saving encrypted secret to savedData
  await secrethold.setSecret(
    {
      id,
      decryptedSecret: secret,
      pin,
    },
    mockedTxClient,
  );
  await secrethold.delSecret(id, mockedTxClient);
  equal(savedData, null);
});

test('should encrypt/decrypt stream', async ({ equal }) => {
  function* charGenerator(char, times) {
    for (let i = 0; i < times; i++) {
      yield char;
    }
  }
  const char = 'A';
  const times = 100;
  const expectedString = char.repeat(times);
  const source = stream.Readable.from(charGenerator(char, times));

  // encrypting
  const { pinTagPromise, masterTagPromise, encryptedStream, iv, pinSalt } =
    await secrethold.createEncryptionStream({
      source,
      pin,
    });
  const encryptedBuffs = [];
  for await (const chunk of encryptedStream) {
    encryptedBuffs.push(chunk);
  }
  const [masterTag, pinTag] = await Promise.all([masterTagPromise, pinTagPromise]);
  const encryptedSource = stream.Readable.from(Buffer.concat(encryptedBuffs));

  // decrypting
  const decryptedStream = await secrethold.createDecryptionStream({
    encryptedSource,
    pin,
    pinSalt,
    iv,
    masterTag,
    pinTag,
  });
  const decryptedBuffs = [];
  for await (const chunk of decryptedStream) {
    decryptedBuffs.push(chunk);
  }
  const decryptedData = Buffer.concat(decryptedBuffs).toString();
  equal(decryptedData, expectedString);

  // decrypting with buffers
  const encryptedSource2 = stream.Readable.from(Buffer.concat(encryptedBuffs));
  const decryptedStream2 = await secrethold.createDecryptionStream({
    encryptedSource: encryptedSource2,
    pin,
    pinSalt: Buffer.from(pinSalt, encryptedDataEncoding),
    iv: Buffer.from(iv, encryptedDataEncoding),
    masterTag: Buffer.from(masterTag, encryptedDataEncoding),
    pinTag: Buffer.from(pinTag, encryptedDataEncoding),
  });
  const decryptedBuffs2 = [];
  for await (const chunk of decryptedStream2) {
    decryptedBuffs2.push(chunk);
  }
  const decryptedData2 = Buffer.concat(decryptedBuffs2).toString();
  equal(decryptedData2, expectedString);
});

test('decrypting stream should throw if wrong pin provided', async ({ rejects }) => {
  const source = stream.Readable.from('secret message');
  // encrypting
  const { pinTagPromise, masterTagPromise, encryptedStream, iv, pinSalt } =
    await secrethold.createEncryptionStream({
      source,
      pin,
    });
  const encryptedBuffs = [];
  for await (const chunk of encryptedStream) {
    encryptedBuffs.push(chunk);
  }
  const [masterTag, pinTag] = await Promise.all([masterTagPromise, pinTagPromise]);
  const encryptedSource = stream.Readable.from(Buffer.concat(encryptedBuffs));

  // decrypting
  const decryptedStream = await secrethold.createDecryptionStream({
    encryptedSource,
    pin: 'wrong_pin',
    pinSalt,
    iv,
    masterTag,
    pinTag,
  });
  async function readStream(stream) {
    const buffs = [];
    for await (const chunk of stream) {
      buffs.push(chunk);
    }
    return Buffer.concat(buffs).toString();
  }

  await rejects(readStream(decryptedStream), {
    message: 'Unsupported state or unable to authenticate data',
  });
});
