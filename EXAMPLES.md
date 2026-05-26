# Examples

Practical, copy-paste examples for `@brashkie/signalis` v0.2.0.

---

## 📑 Table of Contents

- [Identity Management](#identity-management)
- [Digital Signatures](#digital-signatures)
- [Fingerprint Verification](#fingerprint-verification)
- [Serialization & Storage](#serialization--storage)
- [Network Exchange](#network-exchange)
- [Low-Level Crypto](#low-level-crypto)
- [Error Handling](#error-handling)
- [Real-World Patterns](#real-world-patterns)

---

## Identity Management

### Generate a new identity

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

// At user registration — do once, persist securely
const alice = IdentityKeyPair.generate();

console.log('Fingerprint:', alice.fingerprint());
console.log('Short:     ', alice.shortFingerprint());
```

### Load from existing key material

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

// If you have raw 32-byte buffers from another source
const alice = IdentityKeyPair.fromKeys(publicBuf, privateBuf);
```

### Get the public-only version

```typescript
const alice = IdentityKeyPair.generate();
const alicePub = alice.toPublic();

// alicePub is a PublicIdentityKey
// Safe to share with anyone
sendToContact(alicePub.toHex());
```

---

## Digital Signatures

### Sign a message

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

const alice = IdentityKeyPair.generate();
const message = Buffer.from('Authorize transfer of $100 to Bob');

const signature = alice.sign(message);
// signature.length === 64
```

### Verify a signature (throwing version)

```typescript
import { SignatureError } from '@brashkie/signalis';

try {
  alicePub.verify(message, signature);
  console.log('✅ Authentic');
} catch (e) {
  if (e instanceof SignatureError) {
    console.error('❌ Invalid signature:', e.message);
  }
}
```

### Verify a signature (boolean version)

```typescript
if (alicePub.verifyBool(message, signature)) {
  console.log('✅ Valid');
} else {
  console.log('❌ Invalid or tampered');
}
```

### Deterministic signing (for tests)

```typescript
const alice = IdentityKeyPair.generate();
const message = Buffer.from('test');
const random = Buffer.alloc(64, 0x42); // 64 bytes of randomness

const sig1 = alice.signWithRandom(message, random);
const sig2 = alice.signWithRandom(message, random);

console.log(sig1.equals(sig2)); // true — same input → same output
```

### Sign multiple messages

```typescript
const alice = IdentityKeyPair.generate();
const alicePub = alice.toPublic();

const messages = [
  Buffer.from('msg 1'),
  Buffer.from('msg 2'),
  Buffer.from('msg 3'),
];

const signatures = messages.map(m => alice.sign(m));

// Each must be verified against ITS message
messages.forEach((msg, i) => {
  alicePub.verify(msg, signatures[i]); // ok
});

// Cross-verification fails (sig[0] doesn't match msg[1])
console.log(alicePub.verifyBool(messages[1], signatures[0])); // false
```

---

## Fingerprint Verification

### Display fingerprints to users

```typescript
const alice = IdentityKeyPair.generate();

console.log('Verify this code with your contact:');
console.log(alice.shortFingerprint().match(/.{4}/g)?.join(' '));
// → "a1b2 c3d4 e5f6 0718"
```

### Compare two fingerprints

```typescript
function isSamePerson(
  myKey: IdentityKeyPair,
  theirKey: PublicIdentityKey,
): boolean {
  return myKey.fingerprint() === theirKey.fingerprint();
}
```

### Generate a QR-friendly safety number

```typescript
import { IdentityKeyPair, PublicIdentityKey } from '@brashkie/signalis';

function safetyNumber(
  me: IdentityKeyPair,
  them: PublicIdentityKey,
): string {
  // Combine both fingerprints to make a unique per-pair safety number
  const combined = me.fingerprint() + them.fingerprint();
  
  // Display as groups of 5 digits (like Signal does)
  return combined.match(/.{5}/g)?.slice(0, 12).join(' ') ?? combined;
}

console.log(safetyNumber(alice, bobPub));
// → "a1b2c c3d4e 5f607 18293 ..."
```

---

## Serialization & Storage

### Save identity to disk (encrypted)

```typescript
import { writeFile, readFile } from 'node:fs/promises';
import { IdentityKeyPair } from '@brashkie/signalis';

async function saveIdentity(identity: IdentityKeyPair, password: string) {
  const data = identity.serialize();
  const encrypted = await encryptWithPassword(JSON.stringify(data), password);
  await writeFile('./identity.enc', encrypted);
}

async function loadIdentity(password: string): Promise<IdentityKeyPair> {
  const encrypted = await readFile('./identity.enc');
  const decrypted = await decryptWithPassword(encrypted, password);
  const data = JSON.parse(decrypted.toString());
  return IdentityKeyPair.deserialize(data);
}
```

### Save to JSON-safe DB column

```typescript
// In: identity as text column in PostgreSQL/SQLite
async function saveToDB(identity: IdentityKeyPair, userId: string) {
  const data = identity.serialize();
  // → { publicKey: "hex", privateKey: "hex" }
  await db.query(
    'UPDATE users SET identity_key = $1 WHERE id = $2',
    [JSON.stringify(data), userId],
  );
}

async function loadFromDB(userId: string): Promise<IdentityKeyPair> {
  const result = await db.query(
    'SELECT identity_key FROM users WHERE id = $1',
    [userId],
  );
  const data = JSON.parse(result.rows[0].identity_key);
  return IdentityKeyPair.deserialize(data);
}
```

### Save to OS keychain (recommended)

```typescript
import * as keytar from 'keytar';

async function storeIdentity(identity: IdentityKeyPair) {
  const data = identity.serialize();
  await keytar.setPassword(
    'com.myapp',
    'identity-key',
    JSON.stringify(data),
  );
}

async function retrieveIdentity(): Promise<IdentityKeyPair | null> {
  const stored = await keytar.getPassword('com.myapp', 'identity-key');
  if (!stored) return null;
  return IdentityKeyPair.deserialize(JSON.parse(stored));
}
```

### ⚠️ What NOT to do

```typescript
// ❌ NEVER do this — leaks private key
fs.writeFileSync('./identity.json', JSON.stringify(identity.serialize()));

// ❌ NEVER do this — logs to console
console.log(identity.serialize());

// ❌ NEVER do this — sends private key over network
fetch('https://my-api.com/store', {
  body: JSON.stringify(identity.serialize()),
});
```

---

## Network Exchange

### Send public key to contact

```typescript
const alice = IdentityKeyPair.generate();
const alicePublicHex = alice.toPublic().toHex();

// Over HTTP, gRPC, WebSocket, whatever
await fetch('/api/keys/upload', {
  method: 'POST',
  body: JSON.stringify({ publicKey: alicePublicHex }),
});
```

### Receive and validate public key

```typescript
import { PublicIdentityKey, ValidationError } from '@brashkie/signalis';

async function receiveContactKey(userId: string): Promise<PublicIdentityKey> {
  const response = await fetch(`/api/keys/${userId}`);
  const { publicKey: hex } = await response.json();
  
  try {
    return PublicIdentityKey.fromHex(hex);
  } catch (e) {
    if (e instanceof ValidationError) {
      throw new Error(`Invalid public key from server: ${e.message}`);
    }
    throw e;
  }
}
```

### Sign and send message with authentication

```typescript
async function sendAuthenticatedMessage(
  alice: IdentityKeyPair,
  text: string,
  recipient: string,
) {
  const message = Buffer.from(text, 'utf-8');
  const signature = alice.sign(message);

  await fetch('/api/messages', {
    method: 'POST',
    body: JSON.stringify({
      from: alice.toPublic().toHex(),
      to: recipient,
      body: message.toString('base64'),
      signature: signature.toString('base64'),
    }),
  });
}
```

### Receive and verify

```typescript
async function receiveMessage(message: {
  from: string;
  body: string;
  signature: string;
}) {
  // Get trusted public key (out-of-band verified fingerprint!)
  const senderPub = await getTrustedKey(message.from);
  
  const body = Buffer.from(message.body, 'base64');
  const signature = Buffer.from(message.signature, 'base64');
  
  if (senderPub.verifyBool(body, signature)) {
    console.log('✅ Message:', body.toString('utf-8'));
  } else {
    console.error('❌ Tampered or forged!');
  }
}
```

---

## Low-Level Crypto

### Diffie-Hellman key exchange

```typescript
import { crypto } from '@brashkie/signalis';

const alice = crypto.generateKeyPair();
const bob = crypto.generateKeyPair();

const aliceShared = crypto.diffieHellman(alice.privateKey, bob.publicKey);
const bobShared = crypto.diffieHellman(bob.privateKey, alice.publicKey);

console.log(aliceShared.equals(bobShared)); // true — same shared secret
```

### Derive multiple keys from shared secret

```typescript
import { crypto } from '@brashkie/signalis';

const sharedSecret = crypto.diffieHellman(myPriv, theirPub);

// Derive root key (32 bytes) and chain key (32 bytes) from shared secret
const [rootKey, chainKey] = crypto.hkdfMultiple(
  Buffer.alloc(32),              // salt
  sharedSecret,                  // input keying material
  Buffer.from('MyApp_v1'),       // info / domain separator
  [32, 32],                      // sizes
);
```

### Encrypt with AAD (header binding)

```typescript
import { crypto } from '@brashkie/signalis';

const key = crypto.randomBytes(32);
const nonce = crypto.randomBytes(12);

const body = Buffer.from('Hello, this is the message body');
const header = Buffer.from(JSON.stringify({
  msg_id: 42,
  from: 'alice',
  to: 'bob',
  timestamp: Date.now(),
}));

// Encrypt body, authenticate header
const ciphertext = crypto.aesGcmEncryptWithAad(key, nonce, body, header);

// Recipient must pass SAME header to decrypt
const decrypted = crypto.aesGcmDecryptWithAad(key, nonce, ciphertext, header);
// decrypted.toString() === 'Hello, this is the message body'

// If anyone tampers with the header, decryption fails
const tamperedHeader = Buffer.from('{"msg_id":99}');
try {
  crypto.aesGcmDecryptWithAad(key, nonce, ciphertext, tamperedHeader);
} catch (e) {
  console.log('Header tampered, decryption blocked');
}
```

### Standard Ed25519 (separate signing key)

```typescript
import { crypto } from '@brashkie/signalis';

// Generate independent Ed25519 keypair
const ed = crypto.generateEd25519KeyPair();

// Sign (deterministic, RFC 8032)
const sig = crypto.signEd25519(ed.privateKey, Buffer.from('hello'));

// Verify
crypto.verifyEd25519(ed.publicKey, Buffer.from('hello'), sig); // ok
```

### Deterministic Ed25519 from seed

```typescript
import { crypto } from '@brashkie/signalis';

const seed = Buffer.from(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  'hex',
);

const ed = crypto.ed25519FromSeed(seed);
// Always produces the same keypair from this seed
```

---

## Error Handling

### Catch by error type

```typescript
import {
  SignalisError,
  ValidationError,
  SignatureError,
  SerializationError,
} from '@brashkie/signalis';

try {
  alicePub.verify(message, signature);
} catch (e) {
  if (e instanceof SignatureError) {
    console.error('Verification failed:', e.message);
    console.error('Context:', e.context);
  } else if (e instanceof ValidationError) {
    console.error('Bad input:', e.message);
  } else if (e instanceof SignalisError) {
    console.error('Signalis error:', e.code, e.message);
  } else {
    throw e; // re-throw unexpected
  }
}
```

### Use error codes

```typescript
import { ErrorCode } from '@brashkie/signalis';

try {
  // ...
} catch (e) {
  if (e instanceof SignalisError) {
    switch (e.code) {
      case ErrorCode.SIGNATURE_INVALID:
        // Handle invalid signature
        break;
      case ErrorCode.VALIDATION_WRONG_SIZE:
        // Handle wrong-size input
        break;
      // ...
    }
  }
}
```

### Serialize errors for logging/JSON

```typescript
try {
  // ...
} catch (e) {
  if (e instanceof SignalisError) {
    console.error(JSON.stringify(e.toJSON()));
    // → {"name":"SignatureError","message":"...","code":"SIGNATURE_INVALID","context":{...}}
  }
}
```

---

## Real-World Patterns

### Pattern 1: Application bootstrap

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';
import * as keytar from 'keytar';

async function initializeIdentity(): Promise<IdentityKeyPair> {
  const stored = await keytar.getPassword('myapp', 'identity-key');
  
  if (stored) {
    // Existing user
    return IdentityKeyPair.deserialize(JSON.parse(stored));
  }
  
  // First-time user — generate and persist
  const identity = IdentityKeyPair.generate();
  await keytar.setPassword(
    'myapp',
    'identity-key',
    JSON.stringify(identity.serialize()),
  );
  
  // Show fingerprint to user for verification with contacts
  console.log('Your safety code:', identity.shortFingerprint());
  
  return identity;
}
```

### Pattern 2: Contact trust system

```typescript
import { PublicIdentityKey, IdentityKeyPair } from '@brashkie/signalis';

interface Contact {
  id: string;
  name: string;
  publicKey: string; // hex
  fingerprint: string; // hex (SHA-256)
  verified: boolean;
  addedAt: number;
}

class ContactStore {
  private contacts = new Map<string, Contact>();
  
  async addContact(id: string, name: string, publicKeyHex: string) {
    const pub = PublicIdentityKey.fromHex(publicKeyHex);
    this.contacts.set(id, {
      id,
      name,
      publicKey: publicKeyHex,
      fingerprint: pub.fingerprint(),
      verified: false,
      addedAt: Date.now(),
    });
  }
  
  async markVerified(id: string) {
    const contact = this.contacts.get(id);
    if (contact) {
      contact.verified = true;
    }
  }
  
  getKey(id: string): PublicIdentityKey | null {
    const contact = this.contacts.get(id);
    return contact ? PublicIdentityKey.fromHex(contact.publicKey) : null;
  }
}
```

### Pattern 3: Authenticated request signing

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

async function signedFetch(
  identity: IdentityKeyPair,
  url: string,
  options: RequestInit = {},
) {
  const timestamp = Date.now().toString();
  const body = options.body?.toString() ?? '';
  
  // Sign request signature (method + url + timestamp + body)
  const toSign = Buffer.from(`${options.method ?? 'GET'}|${url}|${timestamp}|${body}`);
  const signature = identity.sign(toSign);
  
  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'X-Public-Key': identity.toPublic().toHex(),
      'X-Timestamp': timestamp,
      'X-Signature': signature.toString('base64'),
    },
  });
}

// Server side (Express-like)
function verifyRequest(req) {
  const publicKeyHex = req.headers['x-public-key'];
  const timestamp = req.headers['x-timestamp'];
  const signatureB64 = req.headers['x-signature'];
  
  // Reject old timestamps
  const age = Date.now() - parseInt(timestamp, 10);
  if (Math.abs(age) > 5 * 60 * 1000) {
    throw new Error('Request expired');
  }
  
  const pub = PublicIdentityKey.fromHex(publicKeyHex);
  const toVerify = Buffer.from(
    `${req.method}|${req.url}|${timestamp}|${req.body ?? ''}`,
  );
  const signature = Buffer.from(signatureB64, 'base64');
  
  if (!pub.verifyBool(toVerify, signature)) {
    throw new Error('Invalid signature');
  }
  
  return publicKeyHex; // Trust the user
}
```

### Pattern 4: Group invite tokens

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

async function createInviteToken(
  groupOwner: IdentityKeyPair,
  groupId: string,
  inviteeKey: PublicIdentityKey,
  expiresAt: number,
) {
  const payload = {
    groupId,
    invitee: inviteeKey.toHex(),
    expiresAt,
    issuer: groupOwner.toPublic().toHex(),
  };
  
  const payloadBuf = Buffer.from(JSON.stringify(payload), 'utf-8');
  const signature = groupOwner.sign(payloadBuf);
  
  return {
    payload,
    signature: signature.toString('base64'),
  };
}

async function verifyInviteToken(token: {
  payload: any;
  signature: string;
}) {
  const issuer = PublicIdentityKey.fromHex(token.payload.issuer);
  const payloadBuf = Buffer.from(JSON.stringify(token.payload), 'utf-8');
  const signature = Buffer.from(token.signature, 'base64');
  
  if (!issuer.verifyBool(payloadBuf, signature)) {
    throw new Error('Invalid invite signature');
  }
  
  if (Date.now() > token.payload.expiresAt) {
    throw new Error('Invite expired');
  }
  
  return token.payload;
}
```

---

🔐 + ❤️ [Hepein Oficial](https://github.com/Brashkie)
