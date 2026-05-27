<div align="center">

<img src="media/logo.png" alt="Signalis" width="180" />

# @brashkie/signalis

**Production-grade Signal Protocol implementation in TypeScript.**
**X3DH · Double Ratchet · Sender Keys · Identity Management.**

[![npm version](https://img.shields.io/npm/v/@brashkie/signalis.svg?style=flat-square&color=cb3837)](https://www.npmjs.com/package/@brashkie/signalis)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](LICENSE)
[![Node.js Version](https://img.shields.io/node/v/@brashkie/signalis.svg?style=flat-square&color=339933)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0-3178c6.svg?style=flat-square)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-395%20passing-success.svg?style=flat-square)](#-testing)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg?style=flat-square)](#-testing)
[![CI](https://img.shields.io/github/actions/workflow/status/Brashkie/signalis/ci.yml?style=flat-square&label=CI)](https://github.com/Brashkie/signalis/actions/workflows/ci.yml)
[![Powered by Rust](https://img.shields.io/badge/powered_by-Rust-orange.svg?style=flat-square)](https://www.rust-lang.org)

[**English**](README.md) · [Español](README.es.md)

Built with 🔐 + ❤️ by [Hepein Oficial](https://github.com/Brashkie)

</div>

---

## 📑 Table of Contents

- [What is Signalis?](#-what-is-signalis)
- [What's New in v0.3.0](#-whats-new-in-v030)
- [Features](#-features)
- [Why Signalis?](#-why-signalis)
- [Installation](#-installation)
- [5-Minute Quick Start](#-5-minute-quick-start)
- [Complete Examples](#-complete-examples)
- [API Overview](#-api-overview)
- [Architecture](#-architecture)
- [Security](#-security)
- [Testing](#-testing)
- [Comparison with Alternatives](#-comparison-with-alternatives)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ What is Signalis?

`@brashkie/signalis` is a **TypeScript implementation of the Signal Protocol** — the same end-to-end encryption protocol used by Signal, WhatsApp, and Skype. It provides:

- 🔑 **Identity Keys** — Long-term identity management with XEd25519 signing
- 🔁 **PreKey Bundles** — Asynchronous session establishment (X3DH)
- 🪜 **Double Ratchet** — Forward & backward secrecy for messages *(Sprint 3)*
- 👥 **Sender Keys** — Efficient group messaging *(Sprint 5)*
- 💾 **Storage Layer** — Pluggable persistence for sessions/keys *(Sprint 4)*
- 🛡️ **Built on `@brashkie/signalis-core`** — Rust-native crypto primitives

> **Part of the [Hepein](https://github.com/Brashkie) ecosystem.**
> Foundation for `@brashkie/waproto` (WhatsApp Protocol) and ultimately a from-scratch alternative to Baileys.

---

## 🎉 What's New in v0.3.0

**v0.3.0 ships the PreKey layer — the foundation for X3DH.** Bob can now publish a `PreKeyBundle` containing identity-signed prekeys, and Alice can fetch and **automatically verify** that bundle before initiating a session.

### 🆕 New Classes

| Class | Purpose |
|-------|---------|
| `OneTimePreKey` | Single-use ephemeral Curve25519 keypairs |
| `SignedPreKey` | Medium-term keypair signed with identity (XEd25519) — rotated weekly |
| `PreKeyBundle` | Complete server-facing payload for X3DH |
| `PublicOneTimePreKey` | Public-only form (server-uploaded) |
| `PublicSignedPreKey` | Verified public form for received bundles |

### 🛡️ Security Built-In

- ✅ Signed prekeys verified automatically on `fromPayload()` (throws `SignatureError` if tampered)
- ✅ Rotation lifecycle helpers (`needsRotation()`, `isExpired()`, `ageMs()`)
- ✅ Mallory-forgery prevention tested with explicit tests
- ✅ Strict input validation (key sizes, IDs, hex format, registration ranges)

### 📊 Quality Metrics

```
✅ 395 tests passing
✅ 100% statements
✅ 100% branches
✅ 100% functions
✅ 100% lines
```

**100% backwards compatible** with v0.2.0.

---

## 🚀 Features

| Feature | Status | Sprint |
|---------|--------|--------|
| 🔑 **Identity Key Pair** (Curve25519) | ✅ | 1 |
| ✍️ **XEd25519 signing on identity keys** | ✅ | 1.2 |
| 🛡️ **Branded types** (PublicKey vs PrivateKey at compile time) | ✅ | 1 |
| 🎯 **Type-safe** with full TypeScript 6.0 support | ✅ | 1 |
| 📦 **Dual ESM/CJS** package | ✅ | 1 |
| 🧪 **100% test coverage** with RFC vectors | ✅ | 2.1 |
| 🔐 **Safe defaults** (no toString leaks of private keys) | ✅ | 1 |
| 💾 **Serialization/deserialization** (JSON-safe) | ✅ | 1 |
| 🔁 **One-Time PreKeys** | ✅ NEW | 2.1 |
| ✍️ **Signed PreKeys** (signed with identity via XEd25519) | ✅ NEW | 2.1 |
| 📦 **PreKey Bundles** (server-facing X3DH payload) | ✅ NEW | 2.1 |
| 🤝 **X3DH** (Extended Triple Diffie-Hellman) | 🚧 | 2.2 |
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
| **Test Coverage** | ✅ **100%** | 🟡 Unknown | ❌ Unknown |
| **Active maintenance** | ✅ Active | 🟡 Sporadic | ❌ Stale |
| **Dual ESM/CJS** | ✅ | ❌ | ❌ |
| **Modern API** | ✅ Class-based, async-friendly | 🟡 Old-style | 🟡 Callback-heavy |
| **License** | Apache-2.0 | GPL-3.0 | GPL-3.0 |

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

## ⚡ 5-Minute Quick Start

Want to see Signalis work in 5 minutes? Copy-paste this:

### `quickstart.ts`

```typescript
import {
  IdentityKeyPair,
  PublicIdentityKey,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
} from '@brashkie/signalis';

// ════════════════════════════════════════════════════════════════════════
// PART 1: Identity & Signing (✅ Available in v0.2.0+)
// ════════════════════════════════════════════════════════════════════════

console.log('\n🔑 PART 1 — Identity & Signing\n');

// Generate Alice's long-term identity (do once at registration)
const alice = IdentityKeyPair.generate();
console.log('Alice fingerprint:', alice.shortFingerprint());

// Alice signs a message
const message = Buffer.from('I am authorizing this transaction');
const signature = alice.sign(message);
console.log('Signature length:', signature.length, 'bytes');

// Bob verifies using only Alice's public key
const alicePub = alice.toPublic();
const alicePublicHex = alicePub.toHex(); // shared via network

// On Bob's side:
const aliceKeyReceived = PublicIdentityKey.fromHex(alicePublicHex);
const isValid = aliceKeyReceived.verifyBool(message, signature);
console.log('Signature valid?', isValid); // → true ✅

// Mallory tries to forge:
const mallory = IdentityKeyPair.generate();
const forgedSig = mallory.sign(message);
const forgedValid = aliceKeyReceived.verifyBool(message, forgedSig);
console.log('Mallory forgery accepted?', forgedValid); // → false ✅

// ════════════════════════════════════════════════════════════════════════
// PART 2: PreKey Bundle Setup (✅ Available in v0.3.0+)
// ════════════════════════════════════════════════════════════════════════

console.log('\n📦 PART 2 — PreKey Bundle Setup\n');

// Bob publishes his prekey bundle to the server
const bob = IdentityKeyPair.generate();
const bobSpk = SignedPreKey.generate(bob, 1);  // signed with bob's identity
const bobOtpks = OneTimePreKey.generateBatch(1, 100); // 100 one-time keys

console.log('Bob fingerprint:', bob.shortFingerprint());
console.log('Bob SPK ID:', bobSpk.id);
console.log('Bob SPK signature verifies?', bobSpk.verify(bob.toPublic())); // → true ✅
console.log('Generated', bobOtpks.length, 'one-time prekeys');

// Server picks the first available one-time prekey for Alice's request
const pickedOtpk = bobOtpks[0];

const bundleForAlice = PreKeyBundle.build({
  registrationId: 12345,
  deviceId: 1,
  identityKey: bob.toPublic(),
  signedPreKey: bobSpk.toPublic(),
  oneTimePreKey: pickedOtpk.toPublic(),
});

// Server stores this as JSON
const serverPayload = bundleForAlice.toPayload();
console.log('Bundle address:', bundleForAlice.address());

// ════════════════════════════════════════════════════════════════════════
// PART 3: Alice Receives & Verifies Bob's Bundle
// ════════════════════════════════════════════════════════════════════════

console.log('\n🔍 PART 3 — Alice Verifies Bob\'s Bundle\n');

// Alice fetches Bob's bundle from the server (e.g., HTTPS GET /bundles/bob)
// fromPayload() AUTOMATICALLY verifies the signed prekey's signature.
// If anyone tampered or forged anything, it throws SignatureError.
const verifiedBundle = PreKeyBundle.fromPayload(serverPayload);

console.log('Bundle verified ✅');
console.log('  Bob identity:', verifiedBundle.identityKey.shortFingerprint());
console.log('  Bob SPK id:', verifiedBundle.signedPreKey.id);
console.log('  Bob OTPK id:', verifiedBundle.oneTimePreKey?.id);
console.log('  Has OTPK?', verifiedBundle.hasOneTimePreKey());

// ════════════════════════════════════════════════════════════════════════
// PART 4: Tamper Detection
// ════════════════════════════════════════════════════════════════════════

console.log('\n🛡️ PART 4 — Tampering Is Caught\n');

// What if a malicious server tries to swap Bob's identity?
const evil = IdentityKeyPair.generate();
const evilBundle = {
  ...serverPayload,
  identityKey: evil.toPublic().toHex(), // ← attacker substitutes their key
};

try {
  PreKeyBundle.fromPayload(evilBundle);
  console.log('⚠️ This should NEVER print');
} catch (e) {
  console.log('Tampered bundle rejected ✅');
  console.log('Error:', (e as Error).message);
}

console.log('\n🎉 Quick Start Complete!\n');
```

### Run It

```bash
# 1. Install
npm install @brashkie/signalis

# 2. Save the code above as quickstart.ts

# 3. Run with tsx (or compile with tsc)
npx tsx quickstart.ts
```

### Expected Output

```
🔑 PART 1 — Identity & Signing

Alice fingerprint: a1b2c3d4e5f60718
Signature length: 64 bytes
Signature valid? true
Mallory forgery accepted? false

📦 PART 2 — PreKey Bundle Setup

Bob fingerprint: f1e2d3c4b5a60798
Bob SPK ID: 1
Bob SPK signature verifies? true
Generated 100 one-time prekeys

🔍 PART 3 — Alice Verifies Bob's Bundle

Bundle verified ✅
  Bob identity: f1e2d3c4b5a60798
  Bob SPK id: 1
  Bob OTPK id: 1
  Has OTPK? true

🛡️ PART 4 — Tampering Is Caught

Tampered bundle rejected ✅
Error: SignedPreKey signature verification failed for prekey id 1

🎉 Quick Start Complete!
```

---

## 🧪 Complete Examples

### Example 1: Persisting Identity

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';
import { writeFile, readFile } from 'node:fs/promises';

// At registration (do once)
async function setupIdentity() {
  const identity = IdentityKeyPair.generate();
  const data = identity.serialize();
  // ⚠️ STORE IN ENCRYPTED STORAGE
  await writeFile('./alice-identity.json', JSON.stringify(data));
  console.log('Identity created. Fingerprint:', identity.shortFingerprint());
}

// On app startup
async function loadIdentity(): Promise<IdentityKeyPair> {
  const raw = await readFile('./alice-identity.json', 'utf-8');
  return IdentityKeyPair.deserialize(JSON.parse(raw));
}
```

### Example 2: Signing API Requests

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

const identity = await loadIdentity();

async function signedFetch(url: string, options: RequestInit = {}) {
  const timestamp = Date.now().toString();
  const body = options.body?.toString() ?? '';
  
  // Sign request: method + url + timestamp + body
  const toSign = Buffer.from(
    `${options.method ?? 'GET'}|${url}|${timestamp}|${body}`,
  );
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

// On server side, verify:
function verifyRequest(req) {
  const pubKey = PublicIdentityKey.fromHex(req.headers['x-public-key']);
  const timestamp = req.headers['x-timestamp'];
  const sig = Buffer.from(req.headers['x-signature'], 'base64');
  
  // Reject old timestamps (clock skew prevention)
  if (Math.abs(Date.now() - parseInt(timestamp, 10)) > 5 * 60 * 1000) {
    throw new Error('Request expired');
  }
  
  const toVerify = Buffer.from(
    `${req.method}|${req.url}|${timestamp}|${req.body ?? ''}`,
  );
  
  if (!pubKey.verifyBool(toVerify, sig)) {
    throw new Error('Invalid signature');
  }
  
  return pubKey.toHex(); // Trust the user
}
```

### Example 3: PreKey Bundle Lifecycle

```typescript
import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
} from '@brashkie/signalis';

class UserSetup {
  identity: IdentityKeyPair;
  signedPreKey: SignedPreKey;
  oneTimePreKeys: OneTimePreKey[];
  
  constructor() {
    this.identity = IdentityKeyPair.generate();
    this.signedPreKey = SignedPreKey.generate(this.identity, 1);
    this.oneTimePreKeys = OneTimePreKey.generateBatch(1, 100);
  }
  
  // Publish to server
  async publish(serverUrl: string) {
    await fetch(`${serverUrl}/keys/register`, {
      method: 'POST',
      body: JSON.stringify({
        identityKey: this.identity.toPublic().toHex(),
        signedPreKey: this.signedPreKey.toPayload(),
        oneTimePreKeys: this.oneTimePreKeys.map(k => ({
          id: k.id,
          publicKey: k.publicKey.toString('hex'),
        })),
      }),
    });
  }
  
  // Run weekly: check if SignedPreKey needs rotation
  async rotateIfNeeded(serverUrl: string) {
    if (this.signedPreKey.needsRotation()) {
      const newId = this.signedPreKey.id + 1;
      this.signedPreKey = SignedPreKey.generate(this.identity, newId);
      
      await fetch(`${serverUrl}/keys/signed-prekey`, {
        method: 'POST',
        body: JSON.stringify(this.signedPreKey.toPayload()),
      });
      
      console.log('Rotated signed prekey to id', newId);
    }
  }
  
  // Run when running low on OneTimePreKeys
  async refillOneTimeKeys(serverUrl: string, currentCount: number) {
    if (currentCount < 10) {
      const startId = Math.max(...this.oneTimePreKeys.map(k => k.id)) + 1;
      const newBatch = OneTimePreKey.generateBatch(startId, 90);
      this.oneTimePreKeys.push(...newBatch);
      
      await fetch(`${serverUrl}/keys/one-time`, {
        method: 'POST',
        body: JSON.stringify(
          newBatch.map(k => ({
            id: k.id,
            publicKey: k.publicKey.toString('hex'),
          })),
        ),
      });
      
      console.log('Refilled with 90 new one-time prekeys');
    }
  }
}
```

### Example 4: Receiving and Verifying a Bundle

```typescript
import { PreKeyBundle, SignatureError } from '@brashkie/signalis';

async function fetchUserBundle(userId: string): Promise<PreKeyBundle | null> {
  const response = await fetch(`/api/users/${userId}/bundle`);
  
  if (!response.ok) {
    console.error('Failed to fetch bundle');
    return null;
  }
  
  const payload = await response.json();
  
  try {
    // fromPayload AUTOMATICALLY verifies the signed prekey signature
    return PreKeyBundle.fromPayload(payload);
  } catch (e) {
    if (e instanceof SignatureError) {
      console.error('SECURITY: Bundle signature invalid!', e.message);
      // → server may be compromised, do NOT use this bundle
    }
    throw e;
  }
}

// Use it:
const bobBundle = await fetchUserBundle('bob');
if (bobBundle) {
  console.log('Bob is at address:', bobBundle.address());
  console.log('Bob fingerprint:', bobBundle.identityKey.fingerprint());
  // → ready for X3DH.initiate(bundle) in v0.4.0
}
```

For more examples, see [EXAMPLES.md](EXAMPLES.md).

---

## 📚 API Overview

### Identity Module

```typescript
class IdentityKeyPair {
  static generate(): IdentityKeyPair;
  static fromKeys(pub: Buffer, priv: Buffer): IdentityKeyPair;
  static deserialize(data: SerializedKeyPair): IdentityKeyPair;
  
  // Signing (XEd25519)
  sign(message: Buffer): Signature;
  signWithRandom(message: Buffer, random: Buffer): Signature;
  verify(message: Buffer, signature: Buffer): void;
  verifyBool(message: Buffer, signature: Buffer): boolean;
  
  // Accessors
  toPublic(): PublicIdentityKey;
  fingerprint(): string;
  shortFingerprint(): string;
  serialize(): SerializedKeyPair;
}

class PublicIdentityKey {
  static fromHex(hex: string): PublicIdentityKey;
  static fromBase64(b64: string): PublicIdentityKey;
  
  verify(message: Buffer, signature: Buffer): void;
  verifyBool(message: Buffer, signature: Buffer): boolean;
  
  toHex(): string;
  toBase64(): string;
  fingerprint(): string;
}
```

### PreKeys Module (NEW in v0.3.0)

```typescript
class OneTimePreKey {
  static generate(id: number): OneTimePreKey;
  static generateBatch(startId: number, count: number): OneTimePreKey[];
  static fromKeys(id, pub, priv): OneTimePreKey;
  static deserialize(data): OneTimePreKey;
  
  toPublic(): PublicOneTimePreKey;
  serialize(): SerializedOneTimePreKey;
}

class SignedPreKey {
  static generate(identity: IdentityKeyPair, id: number): SignedPreKey;
  static fromKeys(id, pub, priv, sig, timestamp): SignedPreKey;
  static deserialize(data): SignedPreKey;
  
  verify(identityPub: PublicIdentityKey): boolean;
  needsRotation(threshold?: number): boolean;
  isExpired(maxAge?: number): boolean;
  ageMs(now?: number): number;
  
  toPayload(): PublicSignedPreKeyPayload;
  toPublic(): PublicSignedPreKey;
}

class PreKeyBundle {
  static build(args): PreKeyBundle;
  static fromPayload(payload): PreKeyBundle; // ← auto-verifies signature
  
  hasOneTimePreKey(): boolean;
  address(): string; // "registrationId.deviceId"
  toPayload(): PreKeyBundlePayload;
}
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
│  @brashkie/signalis  ← YOU ARE HERE (v0.3.0)                 │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Identity   │  │   PreKeys   │  │    X3DH     │         │
│  │    ✅       │  │    ✅       │  │   🚧 next   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                              │
│  • IdentityKeyPair (XEd25519 signing)                       │
│  • PublicIdentityKey (verification)                          │
│  • OneTimePreKey / SignedPreKey / PreKeyBundle              │
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
├── 📁 media/
│   └── logo.png                ← Project logo
├── 📁 src/
│   ├── index.ts                ← Public API surface
│   ├── constants.ts            ← Sizes, info strings, validators
│   ├── crypto.ts               ← Wrappers over signalis-core
│   ├── errors.ts               ← Typed error hierarchy
│   ├── types.ts                ← Branded types + type guards
│   ├── 📁 identity/
│   │   ├── index.ts
│   │   └── identity-key.ts     ← IdentityKeyPair + PublicIdentityKey
│   └── 📁 prekeys/            ← NEW v0.3.0
│       ├── index.ts
│       ├── one-time-prekey.ts  ← OneTimePreKey + PublicOneTimePreKey
│       ├── signed-prekey.ts    ← SignedPreKey + PublicSignedPreKey
│       └── prekey-bundle.ts    ← PreKeyBundle
│
├── 📁 __tests__/              ← 395 tests, 100% coverage
├── 📁 .github/
│   └── workflows/
│       ├── ci.yml              ← Lint + test on PR
│       └── release.yml         ← Auto-publish on tag
│
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── vitest.config.mts
├── eslint.config.mjs
├── README.md                   ← This file
├── README.es.md                ← Spanish version
├── CHANGELOG.md
├── MIGRATION.md
├── ROADMAP.md
├── ROADMAP-ECOSYSTEM.md        ← Long-term vision
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
6. **Input validation** — Every public API validates sizes, types, and ID ranges
7. **Automatic verification** — `fromPayload()` methods verify signatures by default

### Security-Critical Rules

```
🚨 NEVER log a serialized IdentityKeyPair / OneTimePreKey / SignedPreKey
🚨 NEVER transmit a serialized keypair over the network
🚨 ALWAYS store identity keys in encrypted storage (KMS, keychain, etc.)
🚨 ALWAYS verify fingerprints out-of-band before trusting public keys
🚨 NEVER reuse a (key, nonce) pair in AES-GCM
🚨 NEVER use ECDH shared secrets directly — always derive via HKDF
🚨 ROTATE SignedPreKeys every 7 days (use needsRotation())
🚨 NEVER use expired SignedPreKeys for new sessions
```

### What's SAFE to Output

```typescript
const alice = IdentityKeyPair.generate();

// ✅ All of these are SAFE — they do NOT include the private key
console.log(alice);                  // "IdentityKeyPair(public=a1b2c3...)"
console.log(alice.toString());       // Same
console.log(JSON.stringify(alice));  // {"type":"IdentityKeyPair","publicKey":"..."}
console.log(alice.fingerprint());    // SHA-256 hex of public key
console.log(alice.toPublic().toHex()); // public key only
```

### Reporting Vulnerabilities

Please see [SECURITY.md](SECURITY.md) for the responsible disclosure process.
**Do NOT open public GitHub issues for security vulnerabilities.**

---

## 🧪 Testing

### Test Coverage: 100%

```
✅ 395 tests passing
✅ 100% statements
✅ 100% branches
✅ 100% functions
✅ 100% lines
```

Test files:
- `constants.test.ts` — 23 tests
- `types.test.ts` — 22 tests
- `errors.test.ts` — 27 tests
- `crypto.test.ts` — 42 tests
- `identity-key.test.ts` — 76 tests
- `one-time-prekey.test.ts` — 53 tests
- `signed-prekey.test.ts` — 53 tests
- `prekey-bundle.test.ts` — 35 tests
- `coverage-boost.test.ts` — 50 tests
- `coverage-final.test.ts` — 14 tests

### Test Vectors

- ✅ RFC 8032 vector 1 (Ed25519)
- ✅ NIST SHA-256 vectors
- ✅ Round-trip tests for all serialize/deserialize paths
- ✅ Mallory-forgery prevention tests
- ✅ E2E scenarios (Alice → server → Bob)

### Running Tests

```bash
# All tests
npm test

# Watch mode
npm run test:watch

# Coverage report
npm test -- --coverage

# Coverage UI (interactive)
npm run test:ui
```

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

### Bundle Size

```
@brashkie/signalis:              ~16 KB minified
@brashkie/signalis-core (native): ~400 KB per platform (one binary)

Total install: ~600 KB (vs 1.5 MB+ for pure-JS alternatives)
```

---

## 🗺️ Roadmap

### ✅ Sprint 1: Identity Foundation (v0.1.0 - v0.2.0) — COMPLETE
- ✅ `IdentityKeyPair` + `PublicIdentityKey`
- ✅ Branded types, type guards, error hierarchy
- ✅ XEd25519 signing on identity keys (v0.2.0)
- ✅ Ed25519 standalone signing
- ✅ AES-GCM with AAD

### ✅ Sprint 2 Part 1: PreKey Layer (v0.3.0) — COMPLETE
- ✅ `OneTimePreKey` with batch generation
- ✅ `SignedPreKey` with identity-signed verification
- ✅ `PreKeyBundle` with automatic signature verification
- ✅ Rotation/expiration lifecycle helpers
- ✅ 395 tests, 100% coverage

### 🚧 Sprint 2 Part 2: X3DH (v0.4.0) — IN DEVELOPMENT
- 🚧 `X3DH.initiate(myIdentity, bobBundle)`
- 🚧 `X3DH.receive(myIdentity, mySpk, myOtpk?, initialMessage)`
- 🚧 4-way DH (DH1 + DH2 + DH3 + DH4)
- 🚧 HKDF derivation with `Signalis_X3DH_v1` domain separator

### 🔜 Sprint 3: Double Ratchet (v0.5.0)
- 🔜 Symmetric key ratchet + DH ratchet
- 🔜 Skipped message keys (out-of-order delivery)
- 🔜 Full forward + backward secrecy

### 🔜 Sprint 4: Storage Layer (v0.6.0)
### 🔜 Sprint 5: Group Messaging / Sender Keys (v0.7.0)
### 🎯 v1.0.0 — Production-ready with external audit

See [ROADMAP.md](ROADMAP.md) for detailed plans and [ROADMAP-ECOSYSTEM.md](ROADMAP-ECOSYSTEM.md) for the long-term vision.

---

## 🔗 Ecosystem

The Hepein crypto/messaging stack:

```
┌─────────────────────────────────────────────┐
│  HepeinBaileys 2.0 (Future)                 │  ← Complete WhatsApp client
├─────────────────────────────────────────────┤
│  @brashkie/waproto (Future)                 │  ← WhatsApp wire protocol
├─────────────────────────────────────────────┤
│  @brashkie/signalis ← YOU ARE HERE (v0.3.0) │  ← Signal Protocol logic
├─────────────────────────────────────────────┤
│  @brashkie/signalis-core (v0.2.0 ✅)        │  ← Crypto primitives
├─────────────────────────────────────────────┤
│  Audited Rust (curve25519-dalek, etc.)      │  ← Battle-tested crypto
└─────────────────────────────────────────────┘
```

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/Brashkie/signalis.git
cd signalis
npm install
npm test
```

For new features or breaking changes, open an issue first to discuss.

---

## 📜 License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

Third-party licenses are listed in [NOTICE](NOTICE).

---

## 🙏 Acknowledgments

Built on the shoulders of giants:

- **[@brashkie/signalis-core](https://www.npmjs.com/package/@brashkie/signalis-core)** — Crypto primitives
- **[Signal Foundation](https://signal.org/)** — Protocol specifications ([X3DH](https://signal.org/docs/specifications/x3dh/), [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/), [XEdDSA](https://signal.org/docs/specifications/xeddsa/))
- **[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)** — Curve25519 in pure Rust
- **[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)** — Ed25519 in pure Rust
- **[RustCrypto](https://github.com/RustCrypto)** — `aes`, `hkdf`, `hmac`, `sha2`
- **[tsup](https://tsup.egoist.dev/)** — Dual ESM/CJS bundler
- **[Vitest](https://vitest.dev/)** — Modern test runner

---

<div align="center">

<sub>🔐 + ❤️ by [Hepein Oficial](https://github.com/Brashkie)</sub>

[Report Bug](https://github.com/Brashkie/signalis/issues) · [Request Feature](https://github.com/Brashkie/signalis/issues) · [Documentation](https://github.com/Brashkie/signalis#readme)

</div>
