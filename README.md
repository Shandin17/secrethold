# SecretHold

[![NPM version](https://img.shields.io/npm/v/secrethold.svg?style=flat)](https://www.npmjs.com/package/secrethold)
[![ci status](https://github.com/Shandin17/secrethold/workflows/Testing%20CI/badge.svg)](https://github.com/Shandin17/secrethold/actions/workflows/test.yml)
[![snyk](https://snyk.io/test/github/Shandin17/secrethold/badge.svg)](https://snyk.io/test/github/Shandin17/secrethold)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Shandin17/secrethold/blob/master/LICENSE)

Lightweight Node.js package designed to safeguard secrets. Each secret can be encrypted separately using a unique `pin` and then stored in a persistent storage. Later secrets can be retrieved and decrypted using their `id` and the corresponding `pin`.

The encryption process involves two stages:

1. Initially, the secret is encrypted with `aes-256-gcm` algorithm, using a key derived from the secret owner's pin via the `pbkdf2` algorithm.
2. The data is then encrypted again with a `masterKey` provided to the `Secrethold` constructor, using the `aes-256-gcm` algorithm.

The decision to store the secret owner's pin is left to the implementer. Not storing the pin enhances security, as only the secret owner will have access to their secrets, eliminating concerns about pin security. However, this approach means that if the secret owner forgets their pin, the secret cannot be recovered. Implementers can choose to allow secret owners to reset their pins through alternative methods, such as email or phone number verification, but this functionality must be developed separately.

A "secret owner" refers to any entity (such as a service, user, or other) that possesses a secret.

<a name="usage"></a>

## Usage

- Install: `npm install secrethold`
- Require: `const { Secrethold } = require('secrethold');`
- Import: `import { Secrethold } from 'secrethold';`

<a name="basic"></a>

### Basic example

```javascript
'use strict';

const { Secrethold, CryptoConstants } = require('secrethold');
const crypto = require('node:crypto');

const masterKey = crypto.randomBytes(CryptoConstants.keyLength);
const secrethold = new Secrethold({
  masterKey, // master key for general encryption
});

const secret = 'secret message';
const secretId = 'secret-id';
const pin = '5%us0Zs1@3!';
secrethold
  .setSecret({
    decryptedSecret: secret,
    id: secretId,
    pin,
  })
  .then(() => secrethold.getSecret(secretId, pin))
  .then((decryptedSecret) => {
    console.log('Decrypted secret:', decryptedSecret);
  });
```

<a name="wrapping-secrets"></a>

### Wrapping secrets

```javascript
'use strict';

const { Secrethold, CryptoConstants } = require('secrethold');
const crypto = require('node:crypto');

class Secret {
  constructor(secret) {
    this.secret = secret;
  }

  unwrap() {
    return this.secret;
  }
}

const masterKey = crypto.randomBytes(CryptoConstants.keyLength);
const secrethold = new Secrethold({
  masterKey, // master key for general encryption
  secretWrapper: (secret) => new Secret(secret), // secret wrapper
});

const secret = 'secret message';
const secretId = 'secret-id';
const pin = '5%us0Zs1@3!';
secrethold
  .setSecret({
    decryptedSecret: secret,
    id: secretId,
    pin,
  })
  .then(() => secrethold.getSecret(secretId, pin))
  .then((wrappedSecret) => {
    console.log('Unwrapped secret:', wrappedSecret.unwrap());
  });
```

<a name="change-pin"></a>

### Change pin

```javascript
'use strict';

const { Secrethold, CryptoConstants } = require('secrethold');
const crypto = require('node:crypto');

const masterKey = crypto.randomBytes(CryptoConstants.keyLength);
const secrethold = new Secrethold({
  masterKey, // master key for general encryption
});

const secret = 'secret message';
const secretId = 'secret-id';
const pin = '5%us0Zs1@3!';

async function changePin() {
  const newPin = 'new pin';
  await secrethold.setSecret({
    id: secretId,
    secret,
    pin,
    decryptedSecret: secret,
  });
  await secrethold.changePin({
    id: secretId,
    oldPin: pin,
    newPin,
  });
  const decryptedSecret = await secrethold.getSecret(secretId, pin);
  console.log(`Decrypted secret: ${decryptedSecret}`);
}

changePin();
```

<a name="encrypt-decrypt-streams"></a>

### Encrypt and decrypt streams

You can encrypt and decrypt streams using the `createEncryptionStream` and `createDecryptionStream` methods. These methods allow you to establish streams for encrypting and decrypting substantial amounts of data. If you choose to use these methods for encryption, you are responsible for ensuring the encrypted data is saved to a persistent storage.

```javascript
'use strict';

const { Secrethold, CryptoConstants } = require('secrethold');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { pipeline } = require('node:stream/promises');

const masterKey = crypto.randomBytes(CryptoConstants.keyLength);
const secrethold = new Secrethold({
  masterKey, // master key for general encryption
});

const secret = 'secret message';
const secretId = 'secret-id';
const pin = '5%us0Zs1@3!';

async function encryptDecryptStream() {
  const source = fs.createReadStream('package-lock.json');
  const destination = fs.createWriteStream('package-lock-encrypted');

  // encrypt
  const { encryptedStream, pinTagPromise, masterTagPromise, pinSalt, iv } =
    await secrethold.createEncryptionStream({
      source,
      pin,
    });
  await pipeline(encryptedStream, destination);

  // decrypt
  const encryptedSource = fs.createReadStream('package-lock-encrypted');
  const decryptedDestination = fs.createWriteStream('package-lock-decrypted.json');
  const [pinTag, masterTag] = await Promise.all([pinTagPromise, masterTagPromise]);
  const decryptedStream = await secrethold.createDecryptionStream({
    pin,
    pinTag,
    masterTag,
    encryptedSource,
    iv,
    pinSalt,
  });
  await pipeline(decryptedStream, decryptedDestination);
  console.log(require('./package-lock-decrypted.json'));
}

encryptDecryptStream().catch(console.error);
```

<a name="secrethold-prisma"></a>

### Secrethold with prisma

you can use `Secrethold` with `Prisma` to store secrets in a database.

```javascript
'use strict';

const { Secrethold, CryptoConstants } = require('secrethold');
const crypto = require('node:crypto');
const { PrismaClient } = require('@prisma/client');

const generatePrismaStorage = ({ prismaClient }) => ({
  async getEncryptedData(userId) {
    return prismaClient.encryptedStorage
      .findUnique({
        where: {
          userId,
        },
      })
      .then((data) => (data ? data.encryptedData : null));
  },
  async setEncryptedData(userId, encryptedData, tx = null) {
    const client = tx || prismaClient;
    await client.encryptedStorage.upsert({
      update: {
        encryptedData,
        userId,
      },
      where: {
        userId,
      },
      create: {
        encryptedData,
        userId,
      },
    });
  },
  async delEncryptedData(userId, tx = null) {
    const client = tx || prismaClient;
    await client.encryptedStorage.delete({
      where: {
        userId,
      },
    });
  },
});

const masterKey = crypto.randomBytes(CryptoConstants.keyLength);
const prismaClient = new PrismaClient();

const secrethold = new Secrethold({
  masterKey,
  encryptedStorage: generatePrismaStorage({ prismaClient }),
});

const secret = 'secret message';
const secretId = 'secret-id';
const pin = '5%us0Zs1@3!';
prismaClient
  .$connect()
  .then(() =>
    secrethold.setSecret({
      decryptedSecret: secret,
      id: secretId,
      pin,
    }),
  )
  .then(() => secrethold.getSecret(secretId, pin))
  .then((decryptedSecret) => {
    console.log('Decrypted secret:', decryptedSecret);
  });
```

<a name="secrethold-prisma-tx"></a>

### Wrapping into transaction

```javascript
'use strict';

const { Secrethold, CryptoConstants } = require('secrethold');
const crypto = require('node:crypto');
const { PrismaClient } = require('@prisma/client');

const generatePrismaStorage = ({ prismaClient }) => ({
  async getEncryptedData(userId) {
    return prismaClient.encryptedStorage
      .findUnique({
        where: {
          userId,
        },
      })
      .then((data) => (data ? data.encryptedData : null));
  },
  async setEncryptedData(userId, encryptedData, tx = null) {
    const client = tx || prismaClient;
    await client.encryptedStorage.upsert({
      update: {
        encryptedData,
        userId,
      },
      where: {
        userId,
      },
      create: {
        encryptedData,
        userId,
      },
    });
  },
  async delEncryptedData(userId, tx = null) {
    const client = tx || prismaClient;
    await client.encryptedStorage.delete({
      where: {
        userId,
      },
    });
  },
});

const masterKey = crypto.randomBytes(CryptoConstants.keyLength);
const prismaClient = new PrismaClient();

const secrethold = new Secrethold({
  masterKey,
  encryptedStorage: generatePrismaStorage({ prismaClient }),
});

const secret = 'secret message';
const secretId = 'secret-id';
const pin = '5%us0Zs1@3!';

async function prismaTransaction() {
  await prismaClient.$connect();
  await prismaClient.$transaction(async (tx) => {
    await secrethold.setSecret(
      {
        decryptedSecret: secret,
        id: secretId,
        pin,
      },
      tx,
    );
    const decryptedSecret = await secrethold.getSecret(secretId, pin);
    console.log('Decrypted secret:', decryptedSecret);
  });
}

prismaTransaction().catch(console.error);
```

<a name="license"></a>

## License

Licensed under [MIT](./LICENSE).
