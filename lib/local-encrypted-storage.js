'use strict';

module.exports = () =>
  new (class {
    encryptedLocalStorage = new Map();
    async getEncryptedData(userId) {
      return this.encryptedLocalStorage.get(userId) || null;
    }
    async setEncryptedData(userId, encryptedData, tx = null) {
      if (tx?.set) {
        tx.set(userId, encryptedData);
      }
      this.encryptedLocalStorage.set(userId, encryptedData);
    }
  })();
