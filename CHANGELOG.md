# Changelog

## [Unreleased][unreleased]

## [1.3.1][] - 2024-05-24

### fixes

- imports for esm modules fix
- `SecretHold.changePin` fixed. Now, after the secret is decrypted using old pin, an additional data verification step is performed by the `secretWrapper` (if it is provided) to avoid data corruption. Also secrets encodings are now checked.
