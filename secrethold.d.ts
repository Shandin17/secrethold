import type { Readable } from 'node:stream';
import type { CipherGCM } from 'node:crypto';

export type Id = number | bigint | string;
export type PinSalt = string;
export type Iv = string;
export type MasterTag = string;
export type PinTag = string;
export type EncryptedData = `${PinSalt}:${Iv}:${MasterTag}:${PinTag}:${string}`;

export interface EncryptedStorage {
  getEncryptedData: (id: Id) => Promise<EncryptedData | null>;
  setEncryptedData: (id: Id, encryptedKey: EncryptedData, tx?: unknown | null) => Promise<void>;
  delEncryptedData: (id: Id, tx?: unknown | null) => Promise<void>;
}

export interface SetSecretOptions {
  id: Id;
  decryptedSecret: string;
  pin: string;
}

export interface ChangePinOptions {
  id: Id;
  oldPin: string;
  newPin: string;
}



/**
 * SecretholdOptions interface represents the options for a Secrethold instance.
 *
 * @template T The type of the secret. Defaults to string. You can change
 * this behavior by providing a `secretWrapper` function.
 */
export interface SecretholdOptions<T> {
  /**
   * The master key for general encryption/decryption. This is a required field.
   */
  masterKey: Buffer;

  /**
   * The storage for encrypted data. This is an optional field.
   * If not provided, a default in-memory storage will be used (`localStorage`).
   * `localStorage` is not recommended for production use.
   */
  encryptedStorage?: EncryptedStorage;

  /**
   * A wrapper for the secret. This is an optional field.
   * Before returning the secret, the wrapper will be called with the secret string
   * and apply predefined logic to it.
   */
  secretWrapper?: (secret: string) => Promise<T> | T;

  /**
   * The encoding for the secret. This is an optional field.
   * If not provided, a default encoding (`utf8`) will be used.
   */
  secretEncoding?: BufferEncoding;

  /**
   * The encoding for the encrypted data. This is an optional field.
   * All data related to encryption (iv, pinSalt, masterTag, pinTag, secret itself)
   * will be stored in the storage
   * in this encoding.
   * If not provided, a default encoding (`base64url`) will be used.
   */
  encryptedDataEncoding?: BufferEncoding;
}

export interface CreateEncryptionStreamOptions {
  source: Readable;
  pin: string;
}

export interface CreateEncryptionStreamResult {
  pinTagPromise: Promise<PinTag>;
  masterTagPromise: Promise<MasterTag>;
  encryptedStream: CipherGCM;
  iv: Iv;
  pinSalt: PinSalt;
}

export interface CreateDecryptionStreamOptions {
  encryptedSource: CipherGCM | Readable;
  pin: string;
  pinSalt: PinSalt | Buffer;
  iv: Iv | Buffer;
  masterTag: MasterTag | Buffer;
  pinTag: PinTag | Buffer;
}

export type CreateDecryptionStreamResult = Readable;

/**
 * The `Secrethold` class provides methods for managing secrets
 *
 * @template T The type of the secret. Defaults to string. You can change
 * this behavior by providing a `secretWrapper` function in the `SecretholdOptions` object.
 */
export class Secrethold<T = string> {
  /**
   * Constructs a new `Secrethold` instance.
   *
   * @param {SecretholdOptions<T>} secretholdOptions The options for the `Secrethold` instance.
   */
  constructor(secretholdOptions: SecretholdOptions<T>);

  /**
   * Decrypts a secret using a pin and master password.
   * @param id The identifier of the secret.
   * @param pin The user-defined password for encryption/decryption.
   * @returns A promise that resolves to the decrypted secret or null if the secret does not exist.
   */
  getSecret(id: Id, pin: string): Promise<T | null>;

  /**
   * Changes the pin for a secret.
   * @param changePinOptions The options for changing the pin.
   * @param tx An optional transaction context.
   * @returns A promise that resolves when the pin has been changed.
   */
  changePin(changePinOptions: ChangePinOptions, tx?: unknown | null): Promise<void>;

  /**
   * Sets a secret.
   * @param setSecretOptions The options for setting the secret.
   * @param tx An optional transaction context.
   * @returns A promise that resolves when the secret has been set.
   */
  setSecret(setSecretOptions: SetSecretOptions, tx?: unknown | null): Promise<void>;

  /**
   * Deletes a secret.
   * @param id The identifier of the secret.
   * @param tx An optional transaction context.
   * @returns A promise that resolves when the secret has been deleted.
   */
  delSecret(id: Id, tx?: unknown | null): Promise<void>;

  /**
   * Creates an encryption stream.
   * @param opts The options for creating the encryption stream.
   * @returns A promise that resolves to the result of creating the encryption stream.
   */
  createEncryptionStream(
    opts: CreateEncryptionStreamOptions,
  ): Promise<CreateEncryptionStreamResult>;

  /**
   * Creates a decryption stream.
   * @param opts The options for creating the decryption stream.
   * @returns A promise that resolves to the result of creating the decryption stream.
   */
  createDecryptionStream(
    opts: CreateDecryptionStreamOptions,
  ): Promise<CreateDecryptionStreamResult>;
}

export declare const ErrorCodes: {
  /**
   * Will be thrown when the pin is incorrect.
   */
  WRONG_PIN: string;
  /**
   * Will be thrown when the secret does not exist, but you try to modify it somehow.
   */
  WRONG_ID: string;
};


export declare const CryptoConstants: {
  /**
   * The encryption algorithm used for encrypting and decrypting data with 256-bit master key.
   *
   */
  holdCryptoAlgorithm: 'aes-256-gcm';

  /**
   * The number of iterations for the PBKDF2 algorithm.
   */
  pinToKeyIterations: 100_000;

  /**
   * The algorithm used for digesting a PIN to generate a key.
   */
  pinToKeyDigest: 'sha256';

  /**
   * The length of a key in bytes.
   */
  keyLength: 32;

  /**
   * The length of the salt in bytes.
   */
  saltLength: 12;
};
