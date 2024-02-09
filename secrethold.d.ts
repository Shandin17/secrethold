export type UserId = number | bigint;
export type pinSalt = string;
export type aesSalt = string;
export type EncryptedData = `${pinSalt}:${aesSalt}:${string}`;
export type CacheKey = string | Buffer;
export type CacheValue = string | Buffer | number;

export interface Cache {
  get: (key: CacheKey) => Promise<CacheValue | null>;
  set: (key: CacheKey, val: CacheValue, ms?: number) => Promise<void>;
  buildKey: (...args: CacheKey[]) => CacheKey;
  cached: (key: CacheKey) => Promise<boolean>;
}

export interface EncryptedStorage {
  getEncryptedData: (userId: UserId) => Promise<EncryptedData | null>;
  setEncryptedData: (
    userId: UserId,
    encryptedKey: EncryptedData,
    tx?: unknown | null,
  ) => Promise<void>;
}

export interface SetSecretOptions {
  userId: UserId;
  decryptedSecret: unknown;
  pin: string;
}

export interface ChangePinOptions {
  userId: number;
  oldPin: string;
  newPin: string;
}

export interface SecretHoldOptions<T> {
  masterKey: Buffer;
  encryptedStorage?: EncryptedStorage;
  cache?: Cache;
  cacheTimeMs?: number;
  secretWrapper?: (secret: string) => Promise<T> | T;
  secretEncoding?: 'utf8' | 'base64' | 'base64url' | 'hex';
}

export class SecretHold<T> {
  constructor(secretHoldOptions: SecretHoldOptions<T>);
  getSecret(userId: UserId, pin: string): Promise<T | null>;
  changePin(changePinOptions: ChangePinOptions): Promise<void>;
  setSecret(setSecretOptions: SetSecretOptions, tx?: unknown | null): Promise<void>;
  cleanCache(): Promise<void>;
  cached(key: CacheKey): Promise<boolean>;
}

export declare const ErrorCodes: {
  WRONG_PIN: string;
  WRONG_USER_ID: string;
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
