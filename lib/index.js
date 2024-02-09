'use strict';

const { Error } = require('metautil');
const { randomBytes } = require('node:crypto');
const { decrypt } = require('./cryptography/decrypt.js');
const { encrypt } = require('./cryptography/encrypt.js');
const { keyLength, saltLength } = require('./cryptography/constants');
const { WRONG_USER_ID, WRONG_PIN } = require('./errors');
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
    secretWrapper = (secret) => secret,
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
  async getSecret(userId, pin) {
    let decryptedSecret = await this.#cache.get(userId.toString());
    if (!decryptedSecret) {
      const encryptedSecret = await this.#encryptedStorage.getEncryptedData(userId);
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
      await this.#cache.set(userId.toString(), decryptedSecret, this.cacheTimeMs);
      decryptedSecret = await this.secretWrapper(decryptedSecret);
    }
    return decryptedSecret;
  }
  async changePin({ oldPin, newPin, userId }) {
    const encryptedKey = await this.#encryptedStorage.getEncryptedData(userId);
    if (!encryptedKey) {
      throw new Error(`SecretHold error: unknown userId provided.`, {
        code: WRONG_USER_ID,
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
      this.#encryptedStorage.setEncryptedData(userId, newEncryptedKey),
      this.#cache.set(userId.toString(), decryptedKey, this.cacheTimeMs),
    ]);
  }

  async setSecret({ userId, decryptedSecret, pin }, tx = null) {
    const pinSalt = randomBytes(saltLength);
    const encryptedSecret = await encrypt(
      decryptedSecret,
      this.#masterKey,
      pin,
      pinSalt,
      this.secretEncoding,
    );
    await Promise.all([
      this.#encryptedStorage.setEncryptedData(userId, encryptedSecret, tx),
      this.#cache.set(userId.toString(), decryptedSecret, this.cacheTimeMs),
    ]);
  }

  async cleanCache() {
    await this.#cache.cleanCache();
  }

  async cached(key) {
    return this.#cache.cached(key);
  }
}

module.exports = SecretHold;
