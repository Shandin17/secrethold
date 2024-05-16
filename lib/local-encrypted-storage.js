'use strict';

module.exports = () =>
  new (class {
    encryptedLocalStorage = new Map();
    async getEncryptedData(id) {
      return this.encryptedLocalStorage.get(id) || null;
    }
    async setEncryptedData(id, encryptedData, tx = null) {
      if (tx?.set) {
        tx.set(id, encryptedData);
      }
      this.encryptedLocalStorage.set(id, encryptedData);
    }

    async delEncryptedData(id, tx = null) {
      if (tx?.del) {
        tx.del(id);
      }
      this.encryptedLocalStorage.delete(id);
    }
  })();
