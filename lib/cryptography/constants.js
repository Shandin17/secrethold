'use strict';

/**
 * The encryption algorithm used for encrypting and decrypting data with 256-bit master key.
 *
 */
const holdCryptoAlgorithm = 'aes-256-cbc';

/**
 * The number of iterations for the PBKDF2 algorithm.
 */
const pinToKeyIterations = 100_000;

/**
 * The algorithm used for digesting a PIN to generate a key.
 */
const pinToKeyDigest = 'sha256';

/**
 * The length of a key in bytes.
 */
const keyLength = 32;

/**
 * The length of the salt in bytes.
 */
const saltLength = 16;

module.exports = {
  holdCryptoAlgorithm,
  pinToKeyIterations,
  pinToKeyDigest,
  keyLength,
  saltLength,
};
