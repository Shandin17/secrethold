'use strict';

const Secrethold = require('./lib');
const ErrorCodes = require('./lib/error-codes');
const CryptoConstants = require('./lib/cryptography/constants');

/**
 * Lightweight Node.js library designed to keep secrets.
 * @module Secrethold
 */
module.exports = {
  Secrethold,
  ErrorCodes,
  CryptoConstants,
};
