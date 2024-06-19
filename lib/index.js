'use strict';

const { Error } = require('metautil');
const { randomBytes } = require('node:crypto');
const { decrypt } = require('./cryptography/decrypt.js');
const { encrypt } = require('./cryptography/encrypt.js');
const { keyLength, saltLength } = require('./cryptography/constants');
const { WRONG_ID, WRONG_PIN } = require('./errors');
const localStorage = require('./local-encrypted-storage');
const localCache = require('./local-cache');

class Secrethold {
  #encryptedStorage;
  #cache;
  #masterKey;
  #secretWrapper;
  #cacheTimeMs;
  #secretEncoding;
  #encryptedDataEncoding;

  constructor({
    masterKey,
    encryptedStorage = localStorage(),
    cache = localCache(),
    cacheTimeMs = 600000,
    secretWrapper = (secret) => Promise.resolve(secret),
    secretEncoding = 'utf8',
    encryptedDataEncoding = 'base64url',
  }) {
    if (masterKey.length !== keyLength) {
      throw new Error(`Wrong master key provided. Master key size must be ${keyLength} bytes`);
    }
    this.#masterKey = masterKey;
    this.#encryptedStorage = encryptedStorage;
    this.#cache = cache;
    this.#cacheTimeMs = cacheTimeMs;
    this.#secretWrapper = secretWrapper;
    this.#secretEncoding = secretEncoding;
    this.#encryptedDataEncoding = encryptedDataEncoding;
  }

  async getSecret(id, pin) {
    let decryptedSecret = await this.#cache.get(id.toString());
    if (decryptedSecret !== null) {
      return await this.#secretWrapper(decryptedSecret);
    }
    const encryptedData = await this.#encryptedStorage.getEncryptedData(id);
    if (encryptedData === null) return encryptedData;
    try {
      decryptedSecret = await this.#decrypt({ encryptedData, pin });
    } catch {
      throw new Error(`Secrethold error: wrong pin provided`, {
        code: WRONG_PIN,
      });
    }
    await this.#cache.set(id.toString(), decryptedSecret, this.#cacheTimeMs);
    return await this.#secretWrapper(decryptedSecret);
  }

  async changePin({ oldPin, newPin, id }, tx = null) {
    const encryptedData = await this.#encryptedStorage.getEncryptedData(id);
    if (!encryptedData) {
      throw new Error(`Secrethold error: unknown id provided.`, {
        code: WRONG_ID,
      });
    }
    let decryptedSecret;
    let newEncryptedData;
    try {
      decryptedSecret = await this.#decrypt({ encryptedData, pin: oldPin });
      newEncryptedData = await this.#encrypt({
        decryptedSecret,
        pin: newPin,
      });
    } catch (e) {
      throw new Error(`Secrethold error: wrong pin provided`, {
        code: WRONG_PIN,
      });
    }
    await Promise.all([
      this.#encryptedStorage.setEncryptedData(id, newEncryptedData, tx),
      this.#cache.set(id.toString(), decryptedSecret, this.#cacheTimeMs),
    ]);
  }

  async setSecret({ id, decryptedSecret, pin }, tx = null) {
    const encryptedSecret = await this.#encrypt({ decryptedSecret, pin });
    await Promise.all([
      this.#encryptedStorage.setEncryptedData(id, encryptedSecret, tx),
      this.#cache.set(id.toString(), decryptedSecret, this.#cacheTimeMs),
    ]);
  }

  async delSecret(id, tx = null) {
    await Promise.all([
      this.#encryptedStorage.delEncryptedData(id, tx),
      this.#cache.del(id.toString()),
    ]);
  }

  async cleanCache() {
    await this.#cache.cleanCache();
  }

  async deleteCachedSecret(id) {
    await this.#cache.del(id.toString());
  }

  async cached(id) {
    return await this.#cache.cached(id.toString());
  }

  async #encrypt({ decryptedSecret, pin }) {
    const [pinSalt, iv] = [randomBytes(saltLength), randomBytes(saltLength)];
    const { encryptedStream, masterTagPromise, pinTagPromise } = await encrypt({
      masterKey: this.#masterKey,
      pin,
      source: Buffer.from(decryptedSecret, this.#secretEncoding),
      pinSalt,
      iv,
    });
    const encryptedBuffs = [];
    for await (const chunk of encryptedStream) {
      encryptedBuffs.push(chunk);
    }
    const [masterTag, pinTag] = await Promise.all([masterTagPromise, pinTagPromise]);
    const encryptedSecret = Buffer.concat(encryptedBuffs).toString(this.#encryptedDataEncoding);
    return `${pinSalt.toString(this.#encryptedDataEncoding)}:
    ${iv.toString(this.#encryptedDataEncoding)}:
    ${masterTag.toString(this.#encryptedDataEncoding)}:
    ${pinTag.toString(this.#encryptedDataEncoding)}:
    ${encryptedSecret}`;
  }

  async #decrypt({ encryptedData, pin }) {
    const [pinSalt, iv, masterTag, pinTag, encryptedSecret] = encryptedData.split(':');
    const encryptedStream = await decrypt({
      masterKey: this.#masterKey,
      pin,
      encryptedSource: Buffer.from(encryptedSecret, this.#encryptedDataEncoding),
      pinSalt: Buffer.from(pinSalt, this.#encryptedDataEncoding),
      iv: Buffer.from(iv, this.#encryptedDataEncoding),
      masterTag: Buffer.from(masterTag, this.#encryptedDataEncoding),
      pinTag: Buffer.from(pinTag, this.#encryptedDataEncoding),
    });
    const decryptedBuffs = [];
    for await (const chunk of encryptedStream) {
      decryptedBuffs.push(chunk);
    }
    const decryptedSecret = Buffer.concat(decryptedBuffs).toString(this.#secretEncoding);
    return decryptedSecret;
  }
}

module.exports = Secrethold;
