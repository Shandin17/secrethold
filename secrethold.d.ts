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
  decryptedSecret: unknown;
  pin: string;
}

export interface ChangePinOptions {
  id: Id;
  oldPin: string;
  newPin: string;
}

export interface SecretholdOptions<T> {
  masterKey: Buffer;
  encryptedStorage?: EncryptedStorage;
  secretWrapper?: (secret: string) => Promise<T> | T;
  secretEncoding?: BufferEncoding;
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

export class Secrethold<T = string> {
  constructor(secretholdOptions: SecretholdOptions<T>);
  getSecret(id: Id, pin: string): Promise<T | null>;
  changePin(changePinOptions: ChangePinOptions, tx?: unknown | null): Promise<void>;
  setSecret(setSecretOptions: SetSecretOptions, tx?: unknown | null): Promise<void>;
  delSecret(id: Id, tx?: unknown | null): Promise<void>;
  createEncryptionStream(
    opts: CreateEncryptionStreamOptions,
  ): Promise<CreateEncryptionStreamResult>;
  createDecryptionStream(
    opts: CreateDecryptionStreamOptions,
  ): Promise<CreateDecryptionStreamResult>;
}

export declare const ErrorCodes: {
  WRONG_PIN: string;
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
