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
  #helpers;

  constructor({
    masterKey,
    encryptedStorage = localStorage(), // todo: localstorage/map compatible
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
    this.#helpers = this.#initHelpers();
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
    if (encryptedData === null) {
      throw new Error(`Secrethold error: unknown id provided.`, {
        code: WRONG_ID,
      });
    }
    let decryptedSecret;
    let newEncryptedData;
    try {
      // todo: pipe data from decrypted to encrypted stream
      // todo: create method for changing pin for streams
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

  async createEncryptionStream({ source, pin }) {
    const [pinSalt, iv] = [randomBytes(saltLength), randomBytes(saltLength)];
    const { encryptedStream, masterTagPromise, pinTagPromise } = await encrypt({
      masterKey: this.#masterKey,
      pin,
      source,
      pinSalt,
      iv,
    });
    const toString = this.#helpers.encryptedBufferToString;
    return {
      pinSalt: toString(pinSalt),
      iv: toString(iv),
      encryptedStream,
      masterTagPromise: masterTagPromise.then((tag) => toString(tag)),
      pinTagPromise: pinTagPromise.then((tag) => toString(tag)),
    };
  }

  async createDecryptionStream({ encryptedSource, pin, pinSalt, iv, masterTag, pinTag }) {
    const toBuf = this.#helpers.encryptedDataToBuffer;
    const decryptStream = await decrypt({
      masterKey: this.#masterKey,
      pin,
      encryptedSource,
      pinSalt: toBuf(pinSalt),
      iv: toBuf(iv),
      masterTag: toBuf(masterTag),
      pinTag: toBuf(pinTag),
    });
    return decryptStream;
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
    const encryptedSecret = Buffer.concat(encryptedBuffs);
    const toString = this.#helpers.encryptedBufferToString;
    return `${toString(pinSalt)}:
    ${toString(iv)}:
    ${toString(masterTag)}:
    ${toString(pinTag)}:
    ${toString(encryptedSecret)}`;
  }

  async #decrypt({ encryptedData, pin }) {
    const [pinSalt, iv, masterTag, pinTag, encryptedSecret] = encryptedData.split(':');
    const toBuf = this.#helpers.encryptedStringToBuffer;
    const decryptedStream = await decrypt({
      masterKey: this.#masterKey,
      pin,
      encryptedSource: toBuf(encryptedSecret),
      pinSalt: toBuf(pinSalt),
      iv: toBuf(iv),
      masterTag: toBuf(masterTag),
      pinTag: toBuf(pinTag),
    });
    const decryptedBuffs = [];
    for await (const chunk of decryptedStream) {
      decryptedBuffs.push(chunk);
    }
    return Buffer.concat(decryptedBuffs).toString(this.#secretEncoding);
  }

  #initHelpers() {
    return {
      encryptedBufferToString: (buffer) => buffer.toString(this.#encryptedDataEncoding),
      encryptedStringToBuffer: (string) => Buffer.from(string, this.#encryptedDataEncoding),
      encryptedDataToBuffer: (data) =>
        data instanceof Buffer ? data : Buffer.from(data, this.#encryptedDataEncoding),
    };
  }
}

module.exports = Secrethold;
