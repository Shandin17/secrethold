'use strict';

module.exports = () =>
  new (class {
    #localCache = new Map();
    #defaultCacheTimeMs = 600000;

    async get(key) {
      const cacheVal = this.#localCache.get(key);
      if (cacheVal) {
        clearTimeout(cacheVal.timeout);
        await this.set(key, cacheVal.value, cacheVal.ms);
      }
      return cacheVal?.value || null;
    }

    async set(key, value, ms = this.#defaultCacheTimeMs) {
      if (this.#localCache.has(key)) {
        clearTimeout(this.#localCache.get(key)?.timeout);
      }
      this.#localCache.set(key, {
        value,
        timeout: this.#getCacheClearTimeout(key, ms),
        ms,
      });
    }

    async cleanCache() {
      for (const [key, val] of this.#localCache) {
        clearTimeout(val.timeout);
        this.#localCache.delete(key);
      }
    }
    // eslint-disable-next-line class-methods-use-this
    buildKey(...args) {
      return args.map((arg) => arg.toString('utf8')).join(':');
    }

    async cached(key) {
      return this.#localCache.has(key);
    }

    #getCacheClearTimeout(key, ms = this.#defaultCacheTimeMs) {
      return setTimeout(() => {
        this.#localCache.delete(key);
      }, ms);
    }
  })();
