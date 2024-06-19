# Changelog

## [Unreleased][unreleased]

## [2.0.0][] - 2024-06-19

- crypto algorithm changed to `aes-256-gcm`. Data authentication is now performed
- `saltLength` changed to `12` bytes
- `encrypt` and `decrypt` functions are now compatible with streams. This allows for the encryption and decryption of large data sets without consuming excessive memory
- `SecretHold` name changed to `Secrehold`
- `encryptedDataEncoding` option added to `Secrehold` constructor. Now you can specify encoding for encrypted data. It will be stored to persistent storage in this encoding

## [1.3.1][] - 2024-05-24

### fixes

- imports for esm modules fix
- `SecretHold.changePin` fixed. Now, after the secret is decrypted using old pin, an additional data verification step is performed by the `secretWrapper` (if it is provided) to avoid data corruption. Also secrets encodings are now checked.
