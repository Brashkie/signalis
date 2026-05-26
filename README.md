<div align="center">

# @brashkie/signalis

**Production-grade Signal Protocol implementation in TypeScript.**
**X3DH · Double Ratchet · Sender Keys · Identity Management.**

[![npm version](https://img.shields.io/npm/v/@brashkie/signalis.svg)](https://www.npmjs.com/package/@brashkie/signalis)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/node/v/@brashkie/signalis.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0-3178c6.svg)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-passing-success.svg)](#testing)
[![CI](https://github.com/Brashkie/signalis/actions/workflows/ci.yml/badge.svg)](https://github.com/Brashkie/signalis/actions/workflows/ci.yml)
[![Powered by Rust](https://img.shields.io/badge/powered_by-Rust-orange.svg)](https://www.rust-lang.org)

[**English**](README.md) · [Español](README.es.md)

Made with 🔐 + ❤️ by [Hepein Oficial](https://github.com/Brashkie)

</div>

---

## 📑 Table of Contents

- [What is Signalis?](#-what-is-signalis)
- [What's New in v0.2.0](#-whats-new-in-v020)
- [Features](#-features)
- [Why Signalis?](#-why-signalis)
- [Comparison with Alternatives](#-comparison-with-alternatives)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [API Overview](#-api-overview)
- [Architecture](#-architecture)
- [Security](#-security)
- [Testing](#-testing)
- [Building from Source](#-building-from-source)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ What is Signalis?

`@brashkie/signalis` is a **TypeScript implementation of the Signal Protocol** — the same end-to-end encryption protocol used by Signal, WhatsApp, and Skype. It provides:

- 🔑 **Identity Keys** — Long-term identity management with XEd25519 signing
- 🔁 **PreKey Bundles** — Asynchronous session establishment (X3DH)
- 🪜 **Double Ratchet** — Forward & backward secrecy for messages
- 👥 **Sender Keys** — Efficient group messaging
- 💾 **Storage Layer** — Pluggable persistence for sessions/keys
- 🛡️ **Built on `@brashkie/signalis-core`** — Rust-native crypto primitives

> **Part of the [Hepein](https://github.com/Brashkie) ecosystem.**
> Foundation for `@brashkie/waproto` (WhatsApp Protocol) and ultimately a from-scratch alternative to Baileys.

---

## 🎉 What's New in v0.2.0

**v0.2.0 brings real digital signatures to identity keys** — replacing the v0.1.0 placeholder approach with proper XEd25519 (Signal-style) signing.

| New | Description |
|-----|-------------|
| 🆕 **`identity.sign(message)`** | Sign arbitrary data with your identity key (XEd25519) |
| 🆕 **`identity.signWithRandom(message, random)`** | Deterministic signing (for testing) |
| 🆕 **`identity.verify(msg, sig)`** | Verify a signature (throws SignatureError) |
| 🆕 **`identity.verifyBool(msg, sig)`** | Verify a signature (returns boolean) |
| 🆕 **`alicePub.verify(msg, sig)`** | Verify with just a `PublicIdentityKey` |
| 🆕 **`alicePub.verifyBool(msg, sig)`** | Boolean version |
| 🆕 **Ed25519 wrappers** | `signEd25519`, `verifyEd25519` (separate from Curve25519) |
| 🆕 **AES-GCM with AAD** | `aesGcmEncryptWithAad` / `aesGcmDecryptWithAad` |
| 🆕 **`SignatureError`** | Dedicated error type for verification failures |

Bumps dependency: `@brashkie/signalis-core` from `^0.1.0` → `^0.2.0`.

**100% backwards compatible.** All v0.1.0 APIs continue to work.

---

## 🚀 Features

| Feature | v0.2.0 | Sprint |
|---------|--------|--------|
| 🔑 **Identity Key Pair** (Curve25519) | ✅ | 1 |
| ✍️ **XEd25519 signing on identity keys** | ✅ NEW | 1 Part 2 |
| 🛡️ **Branded types** (PublicKey vs PrivateKey at compile time) | ✅ | 1 |
| 🎯 **Type-safe** with full TypeScript 6.0 support | ✅ | 1 |
| 📦 **Dual ESM/CJS** package | ✅ | 1 |
| 🧪 **Comprehensive test suite** with RFC vectors | ✅ | 1 |
| 🔐 **Safe defaults** (no toString leaks of private keys) | ✅ | 1 |
| 💾 **Serialization/deserialization** (JSON-safe) | ✅ | 1 |
| 🔁 **PreKey Bundles** (One-time + Signed) | 🚧 | 2 |
| 🤝 **X3DH** (Extended Triple Diffie-Hellman) | 🚧 | 2 |
| 🪜 **Double Ratchet** (forward + backward secrecy) | 🚧 | 3 |
| 💾 **Pluggable storage layer** | 🚧 | 4 |
| 👥 **Sender Keys** (group messaging) | 🚧 | 5 |

---

## 🤔 Why Signalis?

### vs. Building your own crypto

```
❌ Roll your own: bugs, side-channels, footguns everywhere
✅ Signalis: built on audited Rust primitives (RustCrypto, dalek-cryptography)
```

### vs. Using Node's built-in `crypto`

```
❌ node:crypto: low-level, easy to misuse (nonce reuse, mode confusion)
✅ Signalis: high-level API matching Signal Protocol semantics
```

### vs. Other Signal Protocol libraries

| Need | Signalis | libsignal-node | @privacyresearch/libsignal-protocol-typescript |
|------|----------|----------------|------------------------------------------------|
| **TypeScript-first** | ✅ Branded types + strict mode | 🟡 Has types | 🟡 Has types |
| **Pure JS install** | ✅ (depends on signalis-core native) | ❌ Requires Rust toolchain | ✅ |
| **Speed** | 🔥 Rust-native via NAPI | 🔥 Rust-native | 🐢 Pure JS (slow) |
| **Active maintenance** | ✅ Active | 🟡 Sporadic | ❌ Stale |
| **Dual ESM/CJS** | ✅ | ❌ | ❌ |
| **Modern API** | ✅ Class-based, async-friendly | 🟡 Old-style | 🟡 Callback-heavy |
| **License** | Apache-2.0 | GPL-3.0 | GPL-3.0 |

---

## 📊 Comparison with Alternatives

### Performance

Benchmarks (Node 22, x86_64, average of 10k iterations):

| Operation | Signalis (via Rust) | tweetnacl | libsignal-protocol-typescript |
|-----------|---------------------|-----------|-------------------------------|
| Identity keypair generation | **~50,000/sec** | ~3,000/sec | ~2,000/sec |
| Sign (XEd25519) | **~25,000/sec** | N/A | ~1,500/sec |
| Verify (XEd25519) | **~10,000/sec** | N/A | ~800/sec |
| ECDH (X25519) | **~30,000/sec** | ~2,000/sec | ~1,500/sec |

> Numbers from `@brashkie/signalis-core` benchmarks. Your mileage may vary.

### Bundle Size

```
@brashkie/signalis:              ~15 KB minified
@brashkie/signalis-core (native): ~400 KB per platform (one binary)

Total install: ~600 KB (vs 1.5 MB+ for pure-JS alternatives)
```

### Code Comparison

**Other libraries** (pure JS, verbose, untyped):
```javascript
const SignalProtocolStore = require('./SignalProtocolStore');
const libsignal = require('libsignal-protocol-typescript');
const store = new SignalProtocolStore();
await libsignal.KeyHelper.generateIdentityKeyPair().then(kp => {
  // pyramid of doom continues...
});
```

**Signalis** (TypeScript-first, clean):
```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

const identity = IdentityKeyPair.generate();
const sig = identity.sign(Buffer.from('hello'));
identity.verify(Buffer.from('hello'), sig);
```

---

## 📦 Installation

```bash
npm install @brashkie/signalis
```

This also installs `@brashkie/signalis-core` (cryptographic primitives), which uses prebuilt native binaries for:

- ✅ Windows x64 (MSVC), Windows arm64 (MSVC)
- ✅ macOS x64 (Intel), macOS arm64 (Apple Silicon)
- ✅ Linux x64 (glibc + musl), Linux arm64 (glibc)

**No Rust toolchain required** for installation.

### Requirements

- **Node.js:** 18.x, 20.x, 22.x, or 24.x
- **TypeScript** (optional but recommended): 6.0+

---

## 🚀 Quick Start

### 1. Generate an Identity Key

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

// Generate at user registration (do once, store securely)
const alice = IdentityKeyPair.generate();

console.log('My fingerprint:', alice.fingerprint());
// → "a1b2c3d4e5f6..." (64-char hex)

console.log('Short:', alice.shortFingerprint());
// → "a1b2c3d4e5f60718"
```

### 2. Persist Securely

```typescript
// Serialize for storage
const data = alice.serialize();
// → { publicKey: "abc123...", privateKey: "def456..." }

// ⚠️ Store in encrypted storage (e.g., AWS KMS, OS keychain, encrypted DB)
await myEncryptedDB.save('user-identity', data);

// Later: restore
const stored = await myEncryptedDB.load('user-identity');
const alice = IdentityKeyPair.deserialize(stored);
```

### 3. Sign Messages (NEW in v0.2.0)

```typescript
const alice = IdentityKeyPair.generate();
const message = Buffer.from('I authorize this transaction');

const signature = alice.sign(message);
// → 64-byte Buffer

// Anyone with Alice's public key can verify:
const alicePub = alice.toPublic();
alicePub.verify(message, signature); // throws SignatureError if invalid

// Or use boolean version (no throw):
if (alicePub.verifyBool(message, signature)) {
  console.log('✅ Authentic message from Alice');
}
```

### 4. Share Public Keys

```typescript
// Send Alice's public key over the network
const alicePublicHex = alice.toPublic().toHex();
sendToContact(alicePublicHex);

// Receiver side: reconstruct
const alicePub = PublicIdentityKey.fromHex(alicePublicHex);

// Verify a fingerprint with the user
console.log('Verify this matches Alice:', alicePub.fingerprint());
```

### 5. Complete Authenticated Channel Example

```typescript
import { IdentityKeyPair, PublicIdentityKey } from '@brashkie/signalis';

// ── Alice's side ─────────────────────────────────────────────────────
const alice = IdentityKeyPair.generate();
const message = Buffer.from('Hello, secure world!');
const signature = alice.sign(message);

// Send to Bob: alicePublicKey, message, signature
const payload = {
  from: alice.toPublic().toHex(),
  body: message.toString('hex'),
  sig: signature.toString('hex'),
};

// ── Bob's side ───────────────────────────────────────────────────────
const aliceKey = PublicIdentityKey.fromHex(payload.from);
const receivedMsg = Buffer.from(payload.body, 'hex');
const receivedSig = Buffer.from(payload.sig, 'hex');

try {
  aliceKey.verify(receivedMsg, receivedSig);
  console.log('✅ Message authentic:', receivedMsg.toString());
} catch (e) {
  console.error('❌ Tampered or forged signature!');
}
```

---

## 📚 API Overview

### `IdentityKeyPair`

The long-term identity of a user. Generate **once** at registration, store securely, never rotate.

```typescript
class IdentityKeyPair {
  readonly publicKey: PublicKey;     // 32 bytes, branded
  readonly privateKey: PrivateKey;   // 32 bytes, branded

  // ─── Construction ────────────────────────────────────────────────
  static generate(): IdentityKeyPair;
  static fromKeys(pub: Buffer, priv: Buffer): IdentityKeyPair;
  static deserialize(data: SerializedKeyPair): IdentityKeyPair;

  // ─── Signing (NEW v0.2.0) ────────────────────────────────────────
  sign(message: Buffer): Signature;
  signWithRandom(message: Buffer, random: Buffer): Signature;
  verify(message: Buffer, signature: Buffer): void;        // throws on invalid
  verifyBool(message: Buffer, signature: Buffer): boolean;

  // ─── Accessors ───────────────────────────────────────────────────
  toPublic(): PublicIdentityKey;
  fingerprint(): string;              // SHA-256 hex of public key
  shortFingerprint(): string;         // first 16 hex chars
  equals(other: IdentityKeyPair | PublicIdentityKey): boolean;

  // ─── Serialization ───────────────────────────────────────────────
  serialize(): SerializedKeyPair;     // { publicKey, privateKey } as hex
  toJSON(): { type, publicKey };      // SAFE — excludes private key
  toString(): string;                 // SAFE — short fingerprint only
}
```

### `PublicIdentityKey`

Just the public part — safe to share with anyone.

```typescript
class PublicIdentityKey {
  readonly publicKey: PublicKey;

  // ─── Construction ────────────────────────────────────────────────
  constructor(pubKey: Buffer);
  static fromHex(hex: string): PublicIdentityKey;
  static fromBase64(b64: string): PublicIdentityKey;

  // ─── Verification (NEW v0.2.0) ───────────────────────────────────
  verify(message: Buffer, signature: Buffer): void;       // throws SignatureError
  verifyBool(message: Buffer, signature: Buffer): boolean;

  // ─── Output ──────────────────────────────────────────────────────
  toHex(): string;
  toBase64(): string;
  fingerprint(): string;
  shortFingerprint(): string;
  equals(other: PublicIdentityKey | IdentityKeyPair): boolean;
}
```

### Errors

```typescript
class SignalisError extends Error
├── ValidationError       // Bad input (wrong size, type)
├── SignatureError        // Invalid signature ← NEW v0.2.0
├── KeyError              // Key generation/manipulation
├── PreKeyError           // PreKey-specific (Sprint 2)
├── SerializationError    // Encoding/decoding
├── ProtocolError         // Protocol violation
└── SessionError          // Session management (Sprint 3+)
```

### Cryptographic Primitives (advanced)

For low-level operations, the `crypto` namespace re-exports `@brashkie/signalis-core`:

```typescript
import { crypto } from '@brashkie/signalis';

// XEd25519 (Signal-style)
const sig = crypto.signXEd25519(privateKey, message);
crypto.verifyXEd25519(publicKey, message, sig);

// Standard Ed25519 (deterministic, RFC 8032)
const ed = crypto.generateEd25519KeyPair();
const sig = crypto.signEd25519(ed.privateKey, message);

// ECDH
const shared = crypto.diffieHellman(privateKey, peerPublicKey);

// HKDF
const key = crypto.hkdf(salt, ikm, info, 32);

// AES-256-GCM with AAD (NEW v0.2.0)
const ct = crypto.aesGcmEncryptWithAad(key, nonce, plaintext, header);
const pt = crypto.aesGcmDecryptWithAad(key, nonce, ct, header);
```

See [API.md](API.md) for the complete reference.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Your Application                                            │
│  (Chat client, IoT device, server, etc.)                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  @brashkie/signalis  ← YOU ARE HERE                          │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Identity   │  │   PreKeys   │  │   Session   │         │
│  │   Module    │  │  (Sprint 2) │  │ (Sprint 3+) │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                              │
│  • IdentityKeyPair (XEd25519 signing)                       │
│  • PublicIdentityKey (verification)                          │
│  • Branded types (compile-time safety)                       │
│  • Typed errors with codes                                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  @brashkie/signalis-core (Rust + NAPI)                       │
│                                                              │
│  Curve25519 · Ed25519 · XEd25519 · HKDF · AES-GCM           │
│  HMAC-SHA256 · SHA-256                                      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Audited Rust Crates                                         │
│  curve25519-dalek · ed25519-dalek · RustCrypto              │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
signalis/
├── 📁 src/
│   ├── index.ts             ← Public API surface
│   ├── constants.ts         ← Sizes, info strings, validators
│   ├── crypto.ts            ← Wrappers over signalis-core
│   ├── errors.ts            ← Typed error hierarchy
│   ├── types.ts             ← Branded types + type guards
│   └── 📁 identity/
│       ├── index.ts
│       └── identity-key.ts  ← IdentityKeyPair + PublicIdentityKey
│
├── 📁 __tests__/            ← Vitest test suite
├── 📁 .github/
│   ├── workflows/
│   │   ├── ci.yml           ← Lint + test on PR
│   │   └── release.yml      ← Auto-publish on tag
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
│
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── vitest.config.ts
├── README.md                ← This file
├── README.es.md             ← Spanish version
├── CHANGELOG.md
├── MIGRATION.md
├── ROADMAP.md
├── API.md
├── EXAMPLES.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE
└── NOTICE
```

---

## 🔒 Security

### Design Principles

1. **Audited primitives only** — All crypto comes from `@brashkie/signalis-core` (built on `RustCrypto` and `curve25519-dalek`)
2. **Constant-time operations** — For all comparisons and verifications (delegated to Rust)
3. **Memory hygiene** — Private keys are zeroized on drop (in Rust layer)
4. **Type safety** — Branded types prevent mixing public/private keys at compile time
5. **Safe defaults** — `toString()`, `toJSON()`, and Node.js inspect output NEVER leak private keys
6. **Input validation** — Every public API validates sizes and types

### Security-Critical Rules

```
🚨 NEVER log a serialized IdentityKeyPair (it contains the private key)
🚨 NEVER transmit a serialized IdentityKeyPair over the network
🚨 NEVER use console.log() on an IdentityKeyPair without checking your logs
🚨 ALWAYS store identity keys in encrypted storage (KMS, keychain, etc.)
🚨 ALWAYS verify fingerprints out-of-band before trusting public keys
🚨 NEVER reuse a (key, nonce) pair in AES-GCM
🚨 NEVER use ECDH shared secrets directly — always derive via HKDF
```

### What's SAFE

```typescript
const alice = IdentityKeyPair.generate();

// ✅ SAFE — does NOT include private key
console.log(alice);                  // "IdentityKeyPair(public=a1b2c3...)"
console.log(JSON.stringify(alice));  // {"type":"IdentityKeyPair","publicKey":"..."}
console.log(alice.toString());       // Same as above
```

### What's DANGEROUS

```typescript
// ⚠️ DANGER — explicit serialize() includes private key
const data = alice.serialize();
console.log(data); // EXPOSES PRIVATE KEY
```

### Reporting Vulnerabilities

Please see [SECURITY.md](SECURITY.md) for the responsible disclosure process.

**Do NOT open public GitHub issues for security vulnerabilities.**

---

## 🧪 Testing

### Test Coverage

```
✅ ~100+ tests across:
   ├── constants.test.ts      → Constants & validators
   ├── crypto.test.ts          → Crypto wrappers (including XEd25519, Ed25519, AAD)
   ├── errors.test.ts          → Error hierarchy
   ├── types.test.ts           → Branded types & guards
   └── identity-key.test.ts    → IdentityKeyPair + PublicIdentityKey + Signing

✅ Test vectors:
   ├── RFC 8032 vector 1 (Ed25519)
   ├── NIST SHA-256 vectors
   └── Round-trip tests for serialize/deserialize
```

### Running Tests

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch

# Coverage report
npm run test:coverage

# Coverage UI (interactive)
npm run test:ui
```

---

## 🔧 Building from Source

```bash
# Prerequisites:
#   - Node.js 18+
#   - npm 9+

git clone https://github.com/Brashkie/signalis.git
cd signalis

npm install
npm run build
npm test
```

Build artifacts will be in `dist/`:

- `dist/index.cjs` — CommonJS bundle
- `dist/index.mjs` — ESM bundle
- `dist/index.d.ts` — TypeScript declarations
- `dist/index.d.cts` — CJS-specific types
- `dist/index.d.mts` — ESM-specific types

---

## 🗺️ Roadmap

We follow a **sprint-based** approach. Each sprint adds a major Signal Protocol component.

### ✅ Sprint 1: Identity & PreKey Basics (v0.1.0 - v0.2.0)
- ✅ `IdentityKeyPair` class with serialization
- ✅ `PublicIdentityKey` class
- ✅ Branded types (`PublicKey`, `PrivateKey`, `Signature`, ...)
- ✅ Typed error hierarchy
- ✅ Domain separation constants (X3DH info strings, etc.)
- ✅ **v0.2.0:** XEd25519 signing on identity keys
- ✅ **v0.2.0:** Ed25519 wrappers (separate signing keys)
- ✅ **v0.2.0:** AES-GCM AAD support
- ✅ **v0.2.0:** RFC 8032 test vectors

### 🚧 Sprint 2: PreKeys + X3DH (v0.3.0 — in development)
- 🚧 `OneTimePreKey` class
- 🚧 `SignedPreKey` class (signed with identity via XEd25519)
- 🚧 `PreKeyBundle` (server-facing payload)
- 🚧 X3DH initiator flow (`X3DH.initiate(bobBundle)`)
- 🚧 X3DH responder flow (`X3DH.receive(initialMsg)`)
- 🚧 4-way DH (DH1, DH2, DH3, DH4)
- 🚧 Root key + chain key derivation via HKDF

### 🔜 Sprint 3: Double Ratchet (v0.4.0)
- 🔜 Symmetric key ratchet
- 🔜 DH ratchet
- 🔜 Skipped message keys (out-of-order delivery)
- 🔜 Full forward + backward secrecy
- 🔜 Session class with `encrypt(msg)` / `decrypt(packet)`

### 🔜 Sprint 4: Storage Layer (v0.5.0)
- 🔜 `SessionStore` interface
- 🔜 `PreKeyStore`, `SignedPreKeyStore`, `IdentityStore`
- 🔜 In-memory implementation (for tests)
- 🔜 SQLite adapter (reference)
- 🔜 Bring-your-own-storage pattern

### 🔜 Sprint 5: Group Messaging (v0.6.0)
- 🔜 Sender Keys
- 🔜 Group session management
- 🔜 Efficient multi-recipient encryption

### 🔜 v1.0.0 Goals
- ✅ Stable API surface
- ✅ External security audit
- ✅ Comprehensive documentation site
- ✅ Reference implementations (chat app, IoT)
- ✅ Performance benchmarks

See [ROADMAP.md](ROADMAP.md) for detailed plans.

---

## 🔗 Ecosystem

The Hepein crypto/messaging stack:

```
┌─────────────────────────────────────────────┐
│  HepeinBaileys 2.0 (Future)                 │  ← Complete WhatsApp client
│  Full WhatsApp client from scratch          │     (replaces Baileys)
├─────────────────────────────────────────────┤
│  @brashkie/waproto (Future)                 │  ← WhatsApp wire protocol
│  Wire-format compatibility with WhatsApp    │
├─────────────────────────────────────────────┤
│  @brashkie/signalis ← YOU ARE HERE          │  ← Signal Protocol logic
│  X3DH · Double Ratchet · Sender Keys        │
├─────────────────────────────────────────────┤
│  @brashkie/signalis-core (v0.2.0 ✅)        │  ← Crypto primitives
│  Curve25519 · Ed25519 · HKDF · AES-GCM      │
├─────────────────────────────────────────────┤
│  Audited Rust (curve25519-dalek, etc.)      │  ← Battle-tested crypto
└─────────────────────────────────────────────┘
```

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

For new features or breaking changes, open an issue first to discuss.

### Development Workflow

```bash
# Clone & install
git clone https://github.com/Brashkie/signalis.git
cd signalis
npm install

# Make changes...

# Verify
npm run lint
npm run typecheck
npm test
npm run build

# Commit (we follow Conventional Commits)
git commit -m "feat(identity): add new feature"
```

---

## 📜 License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

Third-party licenses are listed in [NOTICE](NOTICE).

---

## 🙏 Acknowledgments

Built on the shoulders of giants:

- **[@brashkie/signalis-core](https://www.npmjs.com/package/@brashkie/signalis-core)** — Crypto primitives (Curve25519, Ed25519, XEd25519, HKDF, AES-GCM, ...)
- **[Signal Foundation](https://signal.org/)** — Protocol specifications ([X3DH](https://signal.org/docs/specifications/x3dh/), [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/), [XEdDSA](https://signal.org/docs/specifications/xeddsa/))
- **[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)** — Curve25519 in pure Rust
- **[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)** — Ed25519 in pure Rust
- **[RustCrypto](https://github.com/RustCrypto)** — `aes`, `hkdf`, `hmac`, `sha2`
- **[tsup](https://tsup.egoist.dev/)** — Dual ESM/CJS bundler
- **[Vitest](https://vitest.dev/)** — Modern test runner

---

<div align="center">

🔐 + ❤️ by [Hepein Oficial](https://github.com/Brashkie)

[Report Bug](https://github.com/Brashkie/signalis/issues) · [Request Feature](https://github.com/Brashkie/signalis/issues) · [Documentation](https://github.com/Brashkie/signalis#readme)

</div>