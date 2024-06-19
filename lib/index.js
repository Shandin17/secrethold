'use strict';

const { Error } = require('./error');
const { randomBytes } = require('node:crypto');
const { decrypt } = require('./cryptography/decrypt.js');
const { encrypt } = require('./cryptography/encrypt.js');
const { keyLength, saltLength } = require('./cryptography/constants');
const { WRONG_ID, WRONG_PIN } = require('./error-codes');
const localStorage = require('./local-encrypted-storage');

class Secrethold {
  #encryptedStorage;
  #masterKey;
  #secretWrapper;
  #secretEncoding;
  #encryptedDataEncoding;

  constructor({
    masterKey,
    encryptedStorage = localStorage(),
    secretWrapper = (secret) => Promise.resolve(secret),
    secretEncoding = 'utf8',
    encryptedDataEncoding = 'base64url',
  }) {
    if (masterKey.length !== keyLength) {
      throw new Error(`Wrong master key provided. Master key size must be ${keyLength} bytes`);
    }
    this.#masterKey = masterKey;
    this.#encryptedStorage = encryptedStorage;
    this.#secretWrapper = secretWrapper;
    this.#secretEncoding = secretEncoding;
    this.#encryptedDataEncoding = encryptedDataEncoding;
  }

  async getSecret(id, pin) {
    const encryptedData = await this.#encryptedStorage.getEncryptedData(id);
    if (encryptedData === null) return encryptedData;
    let decryptedSecret;
    try {
      decryptedSecret = await this.#decrypt({ encryptedData, pin });
    } catch (e) {
      throw new Error(`Secrethold error: ${e.message}`, {
        code: WRONG_PIN,
      });
    }
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
      throw new Error(`Secrethold error: ${e.message}`, {
        code: WRONG_PIN,
      });
    }
    await this.#encryptedStorage.setEncryptedData(id, newEncryptedData, tx);
  }

  async setSecret({ id, decryptedSecret, pin }, tx = null) {
    const encryptedSecret = await this.#encrypt({ decryptedSecret, pin });
    await this.#encryptedStorage.setEncryptedData(id, encryptedSecret, tx);
  }

  async delSecret(id, tx = null) {
    await this.#encryptedStorage.delEncryptedData(id, tx);
  }

  /**
   * @return {Promise<import('../').EncryptedData>}
   */
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
    return Buffer.concat(decryptedBuffs).toString(this.#secretEncoding);
  }
}

module.exports = Secrethold;
