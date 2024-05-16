'use strict';

const { Error } = require('metautil');
const { randomBytes } = require('node:crypto');
const { decrypt } = require('./cryptography/decrypt.js');
const { encrypt } = require('./cryptography/encrypt.js');
const { keyLength, saltLength } = require('./cryptography/constants');
const { WRONG_ID, WRONG_PIN } = require('./errors');
const localStorage = require('./local-encrypted-storage');
const localCache = require('./local-cache');

class SecretHold {
  #encryptedStorage;
  #cache;
  #masterKey;
  cacheTimeMs;
  secretWrapper;
  secretEncoding;
  constructor({
    masterKey,
    encryptedStorage = localStorage(),
    cache = localCache(),
    cacheTimeMs = 600000,
    secretWrapper = null,
    secretEncoding = 'utf8',
  }) {
    if (masterKey.length !== keyLength) {
      throw new Error(`Wrong master key provided. Master key size must be ${keyLength} bytes`);
    }
    this.#masterKey = masterKey;
    this.#encryptedStorage = encryptedStorage;
    this.#cache = cache;
    this.cacheTimeMs = cacheTimeMs;
    this.secretWrapper = secretWrapper;
    this.secretEncoding = secretEncoding;
  }
  async getSecret(id, pin) {
    let decryptedSecret = await this.#cache.get(id.toString());
    if (!decryptedSecret) {
      const encryptedSecret = await this.#encryptedStorage.getEncryptedData(id);
      if (encryptedSecret) {
        try {
          decryptedSecret = await decrypt(
            encryptedSecret,
            this.#masterKey,
            pin,
            this.secretEncoding,
          );
        } catch (e) {
          throw new Error(`SecretHold error: wrong pin provided`, {
            code: WRONG_PIN,
          });
        }
      }
    }
    if (decryptedSecret) {
      await this.#cache.set(id.toString(), decryptedSecret, this.cacheTimeMs);
      decryptedSecret = this.secretWrapper
        ? await this.secretWrapper(decryptedSecret)
        : decryptedSecret;
    }
    return decryptedSecret;
  }
  async changePin({ oldPin, newPin, id }, tx = null) {
    const encryptedKey = await this.#encryptedStorage.getEncryptedData(id);
    if (!encryptedKey) {
      throw new Error(`SecretHold error: unknown id provided.`, {
        code: WRONG_ID,
      });
    }
    let decryptedKey;
    let newEncryptedKey;
    try {
      decryptedKey = await decrypt(encryptedKey, this.#masterKey, oldPin);
      const newPinSalt = randomBytes(saltLength);
      newEncryptedKey = await encrypt(decryptedKey, this.#masterKey, newPin, newPinSalt);
    } catch (e) {
      throw new Error(`SecretHold error: wrong pin provided`, {
        code: WRONG_PIN,
      });
    }
    await Promise.all([
      this.#encryptedStorage.setEncryptedData(id, newEncryptedKey, tx),
      this.#cache.set(id.toString(), decryptedKey, this.cacheTimeMs),
    ]);
  }

  async setSecret({ id, decryptedSecret, pin }, tx = null) {
    const pinSalt = randomBytes(saltLength);
    const encryptedSecret = await encrypt(
      decryptedSecret,
      this.#masterKey,
      pin,
      pinSalt,
      this.secretEncoding,
    );
    await Promise.all([
      this.#encryptedStorage.setEncryptedData(id, encryptedSecret, tx),
      this.#cache.set(id.toString(), decryptedSecret, this.cacheTimeMs),
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
    return this.#cache.del(id.toString());
  }

  async cached(id) {
    return this.#cache.cached(id.toString());
  }
}

module.exports = SecretHold;
