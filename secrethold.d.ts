export type Id = number | bigint | string;
export type PinSalt = string;
export type AesSalt = string;
export type MasterTag = string;
export type PinTag = string;
export type EncryptedData = `${PinSalt}:${AesSalt}:${MasterTag}:${PinTag}:${string}`;

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

export class Secrethold<T = string> {
  constructor(secretholdOptions: SecretholdOptions<T>);
  getSecret(id: Id, pin: string): Promise<T | null>;
  changePin(changePinOptions: ChangePinOptions, tx?: unknown | null): Promise<void>;
  setSecret(setSecretOptions: SetSecretOptions, tx?: unknown | null): Promise<void>;
  delSecret(id: Id, tx?: unknown | null): Promise<void>;
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
  holdCryptoAlgorithm: 'aes-256-cbc';

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
  saltLength: 16;
};
