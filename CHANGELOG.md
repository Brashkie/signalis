# Changelog

All notable changes to `@brashkie/signalis` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-05-25

### ✨ Added — Sprint 1 Part 2: Real XEd25519 Signing

- **`IdentityKeyPair.sign(message)`** — Sign arbitrary data with XEd25519 (Signal Protocol style)
- **`IdentityKeyPair.signWithRandom(message, random)`** — Deterministic signing for testing
- **`IdentityKeyPair.verify(message, signature)`** — Verify signature (throws `SignatureError` on failure)
- **`IdentityKeyPair.verifyBool(message, signature)`** — Verify signature returning boolean
- **`PublicIdentityKey.verify(message, signature)`** — Verify with just a public key
- **`PublicIdentityKey.verifyBool(message, signature)`** — Boolean version
- **`crypto.signXEd25519` / `verifyXEd25519` / `verifyXEd25519Bool`** — Low-level XEd25519 access
- **`crypto.signXEd25519WithRandom`** — Deterministic XEd25519
- **`crypto.generateEd25519KeyPair`** — Generate standard Ed25519 keypair
- **`crypto.ed25519FromSeed`** — Deterministic Ed25519 from 32-byte seed
- **`crypto.signEd25519` / `verifyEd25519` / `verifyEd25519Bool`** — Standard Ed25519 (RFC 8032)
- **`crypto.aesGcmEncryptWithAad` / `aesGcmDecryptWithAad`** — AES-GCM with Additional Authenticated Data
- New tests:
  - `~30` tests for `IdentityKeyPair` signing/verification
  - `~25` tests for crypto wrappers (XEd25519, Ed25519, AAD)
  - RFC 8032 test vector 1 (empty message)
  - Mallory forgery prevention tests
  - End-to-end Signal Protocol identity authentication scenario

### 🔄 Changed

- **`VERSION`** constant bumped to `'0.2.0'`
- **Dependency:** `@brashkie/signalis-core` from `^0.1.0` → `^0.2.0`
- **Removed** stale note in `crypto.ts` about "AAD not supported in v0.1.0"
- `package.json` keywords expanded: `ed25519`, `xed25519`, `curve25519`, `digital-signatures`, `hepein`
- Description updated to include "Identity Keys + PreKeys + X3DH + Double Ratchet"

### 🔒 Security

- All signing operations use audited `ed25519-dalek` (via `signalis-core`)
- XEd25519 follows the [Signal XEdDSA specification](https://signal.org/docs/specifications/xeddsa/)
- Constant-time verification (delegated to Rust layer)
- Branded `Signature` type prevents mixing with arbitrary buffers

### 🧪 Testing

- Total tests: **~100+** (was ~50 in v0.1.0)
- New test files: `__tests__/crypto.test.ts` includes XEd25519, Ed25519, AAD sections
- Updated `__tests__/identity-key.test.ts` with signing & verification suites

### ✅ Compatibility

**100% backwards compatible with v0.1.0.** Every existing API works unchanged:

- All `IdentityKeyPair` static methods (`generate`, `fromKeys`, `deserialize`) — unchanged
- All `IdentityKeyPair` instance methods (`serialize`, `fingerprint`, `equals`, `toPublic`) — unchanged
- All `PublicIdentityKey` methods (except new `verify`/`verifyBool`) — unchanged
- All exports from `index.ts` — preserved
- All constants — preserved
- All error classes — preserved

The only observable change is `VERSION === '0.2.0'`.

---

## [0.1.0] — 2026-05-18

### ✨ Initial Sprint 1 Release

- **`IdentityKeyPair`** class — Long-term identity key pair
  - `generate()`, `fromKeys()`, `deserialize()`
  - `serialize()`, `toPublic()`, `equals()`, `fingerprint()`, `shortFingerprint()`
  - Safe `toString()` / `toJSON()` (no private key leak)
- **`PublicIdentityKey`** class — Just the public portion
  - `fromHex()`, `fromBase64()`
  - `toHex()`, `toBase64()`, `equals()`, `fingerprint()`, `shortFingerprint()`
- **Branded types:**
  - `PublicKey`, `PrivateKey`, `Signature`, `SharedSecret`
  - `ChainKey`, `MessageKey`, `RootKey`
  - Conversion helpers: `asPublicKey`, `asPrivateKey`, etc.
  - Type guards: `isPublicKey`, `isPrivateKey`, `isSignature`
- **Error hierarchy:**
  - `SignalisError` (base)
  - `ValidationError`, `SignatureError`, `KeyError`
  - `PreKeyError`, `SerializationError`, `ProtocolError`, `SessionError`
- **Constants module:**
  - Key sizes, prekey limits, rotation intervals
  - HKDF info strings (X3DH, Ratchet, Chain, Message)
  - Validators: `isValidPreKeyId`, `isValidRegistrationId`, `isValidDeviceId`
- **Crypto wrappers** over `@brashkie/signalis-core`:
  - Random, Curve25519, HKDF, HMAC, SHA-256, AES-GCM (no AAD)
- Type guards: `isIdentityKeyPair`, `isPublicIdentityKey`
- Dual ESM/CJS package with TypeScript definitions

[0.2.0]: https://github.com/Brashkie/signalis/releases/tag/v0.2.0
[0.1.0]: https://github.com/Brashkie/signalis/releases/tag/v0.1.0
