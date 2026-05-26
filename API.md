# API Reference

Complete API documentation for `@brashkie/signalis` v0.2.0.

---

## 📑 Table of Contents

- [IdentityKeyPair](#identitykeypair)
- [PublicIdentityKey](#publicidentitykey)
- [Branded Types](#branded-types)
- [Type Guards](#type-guards)
- [Errors](#errors)
- [Constants](#constants)
- [Crypto Namespace](#crypto-namespace)

---

## IdentityKeyPair

A user's long-term identity key pair. Generated once at registration and never rotated.

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';
```

### Static Methods

#### `IdentityKeyPair.generate(): IdentityKeyPair`

Generate a new random identity key pair using OS randomness.

```typescript
const identity = IdentityKeyPair.generate();
```

#### `IdentityKeyPair.fromKeys(publicKey, privateKey): IdentityKeyPair`

Construct from existing key buffers. Use when loading from storage.

| Parameter | Type | Description |
|-----------|------|-------------|
| `publicKey` | `Buffer \| Uint8Array` | 32-byte public key |
| `privateKey` | `Buffer \| Uint8Array` | 32-byte private key |

**Throws:** `ValidationError` if keys are wrong size or wrong type.

```typescript
const identity = IdentityKeyPair.fromKeys(pubBuf, privBuf);
```

#### `IdentityKeyPair.deserialize(data): IdentityKeyPair`

Deserialize from the JSON-safe format produced by `serialize()`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `unknown` | `{ publicKey: string, privateKey: string }` (both hex) |

**Throws:** `SerializationError` on malformed input.

```typescript
const stored = await myDB.load('identity');
const identity = IdentityKeyPair.deserialize(stored);
```

### Instance Properties

| Property | Type | Description |
|----------|------|-------------|
| `publicKey` | `PublicKey` | 32-byte branded public key (read-only) |
| `privateKey` | `PrivateKey` | 32-byte branded private key (read-only) |

The instance is `Object.freeze`'d. Properties cannot be reassigned.

### Instance Methods — Signing (v0.2.0+)

#### `sign(message: Buffer): Signature`

Sign a message with this identity's private key using XEd25519.

**Non-deterministic** by default (uses OS randomness). Two calls with the same message produce different signatures.

```typescript
const alice = IdentityKeyPair.generate();
const sig = alice.sign(Buffer.from('hello'));
// sig.length === 64
```

**Throws:** `ValidationError` if `message` is not a Buffer.

#### `signWithRandom(message: Buffer, random: Buffer): Signature`

Deterministic signing — provide your own 64-byte randomness. Mostly for testing or reproducibility.

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | `Buffer` | Data to sign |
| `random` | `Buffer` | 64 bytes of randomness |

**Same input → same output.**

```typescript
const random = Buffer.alloc(64, 0x42);
const sig1 = alice.signWithRandom(msg, random);
const sig2 = alice.signWithRandom(msg, random);
// sig1.equals(sig2) === true
```

**Throws:** `ValidationError` on bad inputs.

#### `verify(message: Buffer, signature: Buffer): void`

Verify a signature against this identity's public key. **Throws on failure.**

```typescript
try {
  alice.verify(message, signature);
  // valid
} catch (e) {
  // e instanceof SignatureError
}
```

**Throws:** `SignatureError` if verification fails. `ValidationError` if inputs are wrong type.

#### `verifyBool(message: Buffer, signature: Buffer): boolean`

Verify and return a boolean (no throw).

```typescript
if (alice.verifyBool(message, signature)) {
  // valid
}
```

### Instance Methods — Serialization

#### `serialize(): SerializedKeyPair`

Returns `{ publicKey: string, privateKey: string }` (both hex-encoded).

> ⚠️ **WARNING:** Result contains the **private key**. Store in encrypted storage only.

```typescript
const data = identity.serialize();
// { publicKey: "a1b2...", privateKey: "c3d4..." }
```

### Instance Methods — Accessors

#### `toPublic(): PublicIdentityKey`

Get the public portion as a `PublicIdentityKey` instance.

```typescript
const pub = identity.toPublic();
sendToServer(pub.toHex());
```

#### `fingerprint(): string`

SHA-256 hash of the public key, as 64-char hex string. Use for visual verification.

```typescript
console.log(identity.fingerprint());
// "a1b2c3d4e5f607182939..."
```

#### `shortFingerprint(): string`

First 16 hex chars of the fingerprint, for casual display.

```typescript
console.log(identity.shortFingerprint());
// "a1b2c3d4e5f60718"
```

#### `equals(other): boolean`

Compare by public key only (private keys ignored).

```typescript
const a = IdentityKeyPair.generate();
const aPub = a.toPublic();
a.equals(aPub); // true
```

### Instance Methods — Safe Output

These do **NOT** leak the private key:

```typescript
console.log(identity.toString());
// "IdentityKeyPair(public=a1b2c3d4e5f60718...)"

console.log(JSON.stringify(identity));
// {"type":"IdentityKeyPair","publicKey":"..."}

console.log(identity);   // Uses Symbol.for('nodejs.util.inspect.custom')
// IdentityKeyPair(public=a1b2c3d4e5f60718...)
```

---

## PublicIdentityKey

The public portion of an identity key. Safe to share over the network.

```typescript
import { PublicIdentityKey } from '@brashkie/signalis';
```

### Constructor

```typescript
new PublicIdentityKey(publicKey: PublicKey | Buffer | Uint8Array)
```

**Throws:** `ValidationError` if input is not 32 bytes.

### Static Methods

#### `PublicIdentityKey.fromHex(hex: string): PublicIdentityKey`

```typescript
const pub = PublicIdentityKey.fromHex('a1b2c3...');
```

#### `PublicIdentityKey.fromBase64(b64: string): PublicIdentityKey`

```typescript
const pub = PublicIdentityKey.fromBase64('abc123...');
```

### Instance Methods — Verification (v0.2.0+)

#### `verify(message: Buffer, signature: Buffer): void`

Verify a signature. **Throws `SignatureError` on failure.**

```typescript
const alicePub = PublicIdentityKey.fromHex(receivedHex);
alicePub.verify(message, signature);
// throws SignatureError if invalid
```

#### `verifyBool(message: Buffer, signature: Buffer): boolean`

Boolean version (no throw).

```typescript
if (alicePub.verifyBool(message, signature)) {
  // valid
}
```

Returns `false` on any of:
- Invalid signature
- Non-Buffer inputs
- Signature of wrong size

### Instance Methods — Output

```typescript
pub.toHex();          // 64-char hex string
pub.toBase64();       // base64 string
pub.fingerprint();    // SHA-256 hex
pub.shortFingerprint(); // first 16 chars
pub.equals(other);    // compare by public key
pub.toString();       // safe
pub.toJSON();         // safe (no private key)
```

---

## Branded Types

These prevent mixing up similar-looking buffers at compile time.

```typescript
import type {
  PublicKey,
  PrivateKey,
  Signature,
  SharedSecret,
  ChainKey,
  MessageKey,
  RootKey,
  KeyPair,
  SerializedKeyPair,
  IdentityInfo,
} from '@brashkie/signalis';
```

| Type | Underlying | Size | Brand |
|------|-----------|------|-------|
| `PublicKey` | `Buffer` | 32 bytes | `'PublicKey'` |
| `PrivateKey` | `Buffer` | 32 bytes | `'PrivateKey'` |
| `Signature` | `Buffer` | 64 bytes | `'Signature'` |
| `SharedSecret` | `Buffer` | 32 bytes | `'SharedSecret'` |
| `ChainKey` | `Buffer` | 32 bytes | `'ChainKey'` |
| `MessageKey` | `Buffer` | 32 bytes | `'MessageKey'` |
| `RootKey` | `Buffer` | 32 bytes | `'RootKey'` |

### Conversion Helpers

```typescript
import { asPublicKey, asPrivateKey, asSignature, asSharedSecret, asChainKey, asMessageKey, asRootKey } from '@brashkie/signalis';

const pub: PublicKey = asPublicKey(rawBuffer);
const priv: PrivateKey = asPrivateKey(rawBuffer);
// All throw ValidationError if buffer is wrong size
```

---

## Type Guards

```typescript
import { isPublicKey, isPrivateKey, isSignature, isIdentityKeyPair, isPublicIdentityKey } from '@brashkie/signalis';

if (isPublicKey(value)) {
  // value is PublicKey
}

if (isIdentityKeyPair(value)) {
  // value is IdentityKeyPair
}
```

---

## Errors

```typescript
import {
  SignalisError,
  ValidationError,
  SignatureError,
  KeyError,
  PreKeyError,
  SerializationError,
  ProtocolError,
  SessionError,
  ErrorCode,
} from '@brashkie/signalis';
```

### Hierarchy

```
SignalisError
├── ValidationError       (bad input)
├── SignatureError        (verification failure) ← v0.2.0
├── KeyError              (key issues)
├── PreKeyError           (PreKey-specific) → Sprint 2
├── SerializationError    (encoding/decoding)
├── ProtocolError         (protocol violations)
└── SessionError          (session management) → Sprint 3+
```

### All errors have:

```typescript
interface SignalisError extends Error {
  readonly code: ErrorCodeType;
  readonly context: Readonly<Record<string, unknown>>;
  toJSON(): { name, message, code, context };
}
```

### Helper Constructors

```typescript
ValidationError.wrongSize('field', expected, actual);
ValidationError.wrongType('field', 'Buffer', actual);

PreKeyError.notFound(id);
PreKeyError.expired(id, age);
PreKeyError.alreadyUsed(id);

ProtocolError.unsupportedVersion(version);
```

---

## Constants

```typescript
import {
  VERSION,                       // '0.2.0'
  PROTOCOL_VERSION,              // 3

  // Key sizes
  PUBLIC_KEY_SIZE,               // 32
  PRIVATE_KEY_SIZE,              // 32
  SIGNATURE_SIZE,                // 64
  HASH_SIZE,                     // 32
  MAC_SIZE,                      // 32
  AES_KEY_SIZE,                  // 32
  AES_NONCE_SIZE,                // 12
  AES_TAG_SIZE,                  // 16

  // PreKey limits
  MAX_ONE_TIME_PREKEYS,          // 100
  MIN_ONE_TIME_PREKEYS,          // 10
  DEFAULT_PREKEY_BATCH,          // 100
  MAX_PREKEY_ID,                 // 0xFFFFFF
  MIN_PREKEY_ID,                 // 1

  // Rotation
  SIGNED_PREKEY_ROTATION_MS,     // 7 days
  SIGNED_PREKEY_MAX_AGE_MS,      // 30 days

  // Registration
  MAX_REGISTRATION_ID,           // 16380
  MIN_REGISTRATION_ID,           // 1
  DEFAULT_DEVICE_ID,             // 1
  MAX_DEVICE_ID,                 // 0x7FFFFFFF

  // Info strings (returns fresh Buffer)
  getX3DHInfo,                   // () => Buffer('Signalis_X3DH_Key')
  getRatchetInfo,                // () => Buffer('Signalis_Ratchet_Root')
  getChainInfo,                  // () => Buffer('Signalis_Chain_Key')
  getMessageInfo,                // () => Buffer('Signalis_Message_Key')
  getSignedPreKeyContext,        // () => Buffer('Signalis_SPK_Sig_v1')

  INFO_STRINGS,                  // { X3DH, RATCHET, CHAIN, MESSAGE, SIGNED_PREKEY }

  // Validators
  isValidPreKeyId,
  isValidRegistrationId,
  isValidDeviceId,
} from '@brashkie/signalis';
```

---

## Crypto Namespace

For advanced/low-level use, the `crypto` namespace exposes all primitives.

```typescript
import { crypto } from '@brashkie/signalis';
```

### Random

```typescript
crypto.randomBytes(size: number): Buffer
```

### Curve25519

```typescript
crypto.generateKeyPair(): KeyPair
crypto.diffieHellman(privateKey: PrivateKey, publicKey: PublicKey): Buffer
```

### XEd25519 (v0.2.0+)

```typescript
crypto.signXEd25519(privateKey: PrivateKey, message: Buffer): Signature
crypto.signXEd25519WithRandom(privateKey: PrivateKey, message: Buffer, random: Buffer): Signature
crypto.verifyXEd25519(publicKey: PublicKey, message: Buffer, signature: Signature): void
crypto.verifyXEd25519Bool(publicKey: PublicKey, message: Buffer, signature: Buffer): boolean
```

### Ed25519 (v0.2.0+)

```typescript
crypto.generateEd25519KeyPair(): { privateKey: Buffer, publicKey: Buffer }
crypto.ed25519FromSeed(seed: Buffer): { privateKey: Buffer, publicKey: Buffer }
crypto.signEd25519(privateKey: Buffer, message: Buffer): Signature
crypto.verifyEd25519(publicKey: Buffer, message: Buffer, signature: Buffer): void
crypto.verifyEd25519Bool(publicKey: Buffer, message: Buffer, signature: Buffer): boolean
```

### HKDF

```typescript
crypto.hkdf(salt: Buffer, ikm: Buffer, info: Buffer, outputLength: number): Buffer
crypto.hkdfMultiple(salt: Buffer, ikm: Buffer, info: Buffer, lengths: number[]): Buffer[]
```

### HMAC

```typescript
crypto.hmac(key: Buffer, data: Buffer): Buffer
crypto.hmacVerify(key: Buffer, data: Buffer, tag: Buffer): boolean
```

### SHA-256

```typescript
crypto.sha256(data: Buffer): Buffer
crypto.sha256Multiple(...buffers: Buffer[]): Buffer
```

### AES-GCM

```typescript
crypto.aesGcmEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer
crypto.aesGcmDecrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer): Buffer
```

### AES-GCM with AAD (v0.2.0+)

```typescript
crypto.aesGcmEncryptWithAad(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer
crypto.aesGcmDecryptWithAad(key: Buffer, nonce: Buffer, ciphertext: Buffer, aad: Buffer): Buffer
```

### Direct Access to Core Primitives

```typescript
crypto.Curve25519     // direct from signalis-core
crypto.Ed25519        // v0.2.0+
crypto.XEd25519       // v0.2.0+
crypto.HKDF
crypto.HMAC
crypto.SHA256
crypto.AES_GCM
```

---

🔐 + ❤️ [Hepein Oficial](https://github.com/Brashkie)
