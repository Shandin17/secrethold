# Changelog

## [Unreleased][unreleased]

## [2.2.0][] - 2025-05-22

- Depenencies updated
- Node.js 22, 23, 24 added to CI

## [2.1.0][] - 2024-06-19

- cache removed. Now `Secrethold` always reads data from persistent encrypted storage
- The Secrethold class now includes the `createEncryptionStream` and `createDecryptionStream` functions. These allow you to establish streams for encrypting and decrypting substantial amounts of data. Please note, if you choose to use these methods for encryption, you are responsible for ensuring the encrypted data is saved to a persistent storage.
- `metautil` dependency removed

## [2.0.0][] - 2024-06-19

- crypto algorithm changed to `aes-256-gcm`. Data authentication is now performed. _WARNING! It is not compatible with v1.\* versions!_
- `saltLength` changed to `12` bytes
- `encrypt` and `decrypt` functions are now compatible with streams. This allows for the encryption and decryption of large data sets without consuming excessive memory
- `SecretHold` name changed to `Secrehold`
- `encryptedDataEncoding` option added to `Secrehold` constructor. Now you can specify encoding for encrypted data. It will be stored to persistent storage in this encoding

## [1.3.1][] - 2024-05-24

### fixes

- imports for esm modules fix
- `SecretHold.changePin` fixed. Now, after the secret is decrypted using old pin, an additional data verification step is performed by the `secretWrapper` (if it is provided) to avoid data corruption. Also, secrets encodings are now checked.
