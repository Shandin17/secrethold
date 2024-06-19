'use strict';

// eslint-disable-next-line no-undef
class Error extends globalThis.Error {
  constructor(message, options = {}) {
    super(message);
    const hasOptions = typeof options === 'object';
    const { code, cause } = hasOptions ? options : { code: options };
    this.code = code;
    this.cause = cause;
  }
}

module.exports = { Error };
