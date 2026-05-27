# Changelog

All notable changes to `@brashkie/signalis` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] — 2026-05-26

### ✨ Added — Sprint 2 Part 1: PreKey Layer

The foundation for X3DH. Bob can now publish a `PreKeyBundle` that
authenticates his identity-signed prekeys, and Alice can fetch + verify
that bundle before initiating a handshake.

- **`OneTimePreKey`** — Single-use ephemeral Curve25519 keypair
  - `generate(id)` — Generate one key
  - `generateBatch(startId, count)` — Generate a batch (e.g., 100 keys)
  - `fromKeys(id, pub, priv)` — Reconstruct from stored material
  - `serialize() / deserialize(data)` — JSON-safe storage
  - `toPublic()` — Get server-shareable public form
  - `equals(other)`, `fingerprint()`
- **`PublicOneTimePreKey`** — Public-only form for server payloads
- **`SignedPreKey`** — Medium-term keypair signed with the identity (XEd25519)
  - `generate(identity, id, timestamp?)` — Sign with identity key
  - `verify(identityPub)` — Verify the signature
  - `needsRotation(threshold?)` — Past 7-day rotation threshold
  - `isExpired(maxAge?)` — Past 30-day hard expiration
  - `ageMs(now?)` — Age in milliseconds
  - `toPayload()` — Server-facing wire format
- **`PublicSignedPreKey`** — Verified public form
  - `fromPayload(identityPub, payload)` — Verify on deserialize (throws SignatureError on failure)
- **`PreKeyBundle`** — The complete server payload for X3DH
  - `build({...})` — Construct locally
  - `fromPayload(payload)` — Parse + verify signed prekey signature
  - `hasOneTimePreKey()` — Check OTPK availability
  - `address()` — Format as `"registrationId.deviceId"`
  - `toPayload()` — Serialize for network transport
- **`PreKeyError.invalidId(id, min, max)`** — Helper for invalid prekey IDs
- **New ErrorCode:** `PREKEY_INVALID_ID`
- **New tests:**
  - 50+ tests for `OneTimePreKey` (generation, batch, serialization, type guards)
  - 50+ tests for `SignedPreKey` (signing, verification, Mallory forgery prevention, rotation, expiration)
  - 40+ tests for `PreKeyBundle` (build, fromPayload security, roundtrip, E2E)
  - E2E scenarios: Alice publishes → Bob verifies via server

### 🔄 Changed

- **`VERSION`** constant bumped to `'0.3.0'`
- `package.json` description updated
- New exports added to `index.ts` (PreKey classes, types, type guards)

### 🔒 Security

- All `SignedPreKey` signatures use the `IdentityKeyPair.sign()` (XEd25519) added in v0.2.0
- `PublicSignedPreKey.fromPayload()` and `PreKeyBundle.fromPayload()` **verify signatures by default** — receiving untrusted payloads requires no extra step
- Mallory-forgery tests confirm signatures cannot be forged by a different identity
- Tampered public keys / signatures in payloads are rejected with `SignatureError`
- Bundle layer enforces `registrationId`, `deviceId`, prekey ID ranges

### 🧪 Testing

- Total tests: **~240+** (was ~100+ in v0.2.0)
- New test files: `one-time-prekey.test.ts`, `signed-prekey.test.ts`, `prekey-bundle.test.ts`

### ✅ Compatibility

**100% backwards compatible with v0.2.0.** Every existing API works unchanged.

The new exports are purely additive:
- `OneTimePreKey`, `PublicOneTimePreKey`, `isOneTimePreKey`, `isPublicOneTimePreKey`, `SerializedOneTimePreKey`
- `SignedPreKey`, `PublicSignedPreKey`, `isSignedPreKey`, `isPublicSignedPreKey`, `SerializedSignedPreKey`, `PublicSignedPreKeyPayload`
- `PreKeyBundle`, `isPreKeyBundle`, `PreKeyBundlePayload`, `PublicOneTimePreKeyPayload`

The only observable change is `VERSION === '0.3.0'`.

### 📋 What's Next

Sprint 2 Part 2 (v0.4.0): the X3DH handshake itself.
- `X3DH.initiate(myIdentity, bobBundle)` → derived shared secret
- `X3DH.receive(myIdentity, mySpk, myOptionalOtpk, initialMessage)` → same secret
- 4-way DH (DH1 + DH2 + DH3 + DH4)
- HKDF derivation with `Signalis_X3DH_v1` domain separator

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
- New tests: ~30 tests for signing, ~25 for crypto wrappers, RFC 8032 test vector 1

### 🔄 Changed

- **`VERSION`** constant bumped to `'0.2.0'`
- **Dependency:** `@brashkie/signalis-core` from `^0.1.0` → `^0.2.0`
- **Removed** stale note in `crypto.ts` about "AAD not supported in v0.1.0"

### 🔒 Security

- All signing operations use audited `ed25519-dalek` (via `signalis-core`)
- XEd25519 follows the [Signal XEdDSA specification](https://signal.org/docs/specifications/xeddsa/)

### ✅ Compatibility

**100% backwards compatible with v0.1.0.**

---

## [0.1.0] — 2026-05-18

### ✨ Initial Sprint 1 Release

- **`IdentityKeyPair`** class — Long-term identity key pair
- **`PublicIdentityKey`** class — Just the public portion
- **Branded types:** `PublicKey`, `PrivateKey`, `Signature`, `SharedSecret`, `ChainKey`, `MessageKey`, `RootKey`
- **Error hierarchy:** `SignalisError` → `ValidationError`, `SignatureError`, `KeyError`, `PreKeyError`, `SerializationError`, `ProtocolError`, `SessionError`
- **Constants module** with sizes, prekey limits, rotation intervals, HKDF info strings
- **Crypto wrappers** over `@brashkie/signalis-core`
- Dual ESM/CJS package with TypeScript definitions

[0.3.0]: https://github.com/Brashkie/signalis/releases/tag/v0.3.0
[0.2.0]: https://github.com/Brashkie/signalis/releases/tag/v0.2.0
[0.1.0]: https://github.com/Brashkie/signalis/releases/tag/v0.1.0
