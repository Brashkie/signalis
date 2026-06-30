# Changelog

All notable changes to `@brashkie/signalis` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.0] — 2026-06-26

### ✨ Added — Sprint 4: Storage Layer

The piece that separates a "Signal Protocol library" from a "WhatsApp-style
end-to-end-encrypted messaging app". v0.6.0 gave you `Session` and you had
to BYO persistence. v0.7.0 ships the canonical 4-store contracts + two
bundled implementations + a `SessionBuilder` that orchestrates everything.

**Before (v0.6.0): persistence is your problem.**
**After (v0.7.0): 5 lines and you're done.**

```typescript
import { StoreBundle, SessionBuilder, ProtocolAddress } from '@brashkie/signalis';

const stores = StoreBundle.file('~/.myapp/signalis');
const builder = new SessionBuilder(stores);

// First time: requires bundle (X3DH bootstrap)
const msg = await builder.encrypt(
  new ProtocolAddress('bob', 1),
  Buffer.from('Hola Bob'),
  bobBundle,
);

// Subsequent times: no bundle needed
const msg2 = await builder.encrypt(bobAddr, Buffer.from('me again'));
```

#### 🆕 New types
- **`ProtocolAddress`** — `(userId, deviceId)` pair, multi-device support
  - Filesystem-safe userId (rejects path separators, control chars)
  - Stable string form: `"alice@example.com.1"`
  - `equals()`, `toJSON()`, `inspect()`, type guard `isProtocolAddress()`

#### 🆕 4 store interfaces
- **`IdentityStore`** — own identity, registration id, trusted-peer fingerprints (TOFU)
- **`PreKeyStore`** — one-time prekeys (Signal one-shot semantics)
- **`SignedPreKeyStore`** — medium-term signed prekeys + active pointer
- **`SessionStore`** — per-peer Double Ratchet sessions

#### 🆕 2 bundled implementations
- **`Memory*Store`** — in-process `Map`s. For tests + ephemeral apps.
- **`File*Store`** — JSON-on-disk with atomic writes (tmp + fsync + rename).
  - Safe against partial writes from crashes
  - `chmod 600` on identity files (owner-only)
  - File layout: `<rootDir>/{identity.json, registration-id.json, trusted/, prekeys/, signed-prekeys/, sessions/}`

#### 🆕 `StoreBundle` facade
- `StoreBundle.memory()` — all-memory bundle in one call
- `StoreBundle.file('/path')` — all-file bundle in one call
- Custom mixes: `new StoreBundle({ identity: ..., preKeys: ..., ... })`

#### 🆕 `SessionBuilder` high-level API
- `builder.encrypt(recipient, plaintext, bundle?)` — auto-handles X3DH bootstrap
- `builder.decrypt(sender, message)` — auto-handles X3DH receive + session save
- `builder.resetSession(peer)` — "reset secure session" UX flow
- Automatic TOFU + identity-change detection
- Automatic one-time-prekey consumption after first decrypt
- Returns/accepts discriminated union `WireMessage = PreKey | Whisper`

#### 🆕 New tests (~90)
- ProtocolAddress validation, parse, equality
- Memory store interface contracts (4 stores)
- File store atomic writes + persistence + concurrent writes
- StoreBundle mix-and-match
- SessionBuilder full flow (validation, X3DH bootstrap, TOFU, replay rejection)
- E2E: full conversation + app restart with FileStore

### 🔄 Changed
- `VERSION` bumped to `'0.7.0'`
- `src/index.ts` exports the new storage module
- Zero deps added — `node:fs` + `node:crypto` + `node:path` only

### 🔒 Security
- Atomic writes prevent file corruption from crashes
- File mode 0o600 on identity files (owner read/write only)
- `userId` validation rejects path-traversal characters
- TOFU pattern with explicit `isTrustedIdentity` check (apps can warn users)
- One-time prekeys consumed and DELETED after first use (no replay)
- Replay detection: re-using a prekey message throws

### ✅ Compatibility
**100% backwards compatible with v0.6.0.** All v0.6.0 APIs (`Session.initiateFromX3DH`,
`session.encrypt`, etc.) work unchanged. Storage is opt-in.

### 📋 What's Next

Sprint 5 (v0.8.0): Sender Keys for group messaging.
- `SenderKeyDistributionMessage`
- `GroupSession` class
- Group encrypt/decrypt with shared chain key

---

## [0.6.0] — 2026-06-04

### ✨ Added — Sprint 3 Part 2: Session Class

The high-level encrypt/decrypt API. All the v0.5.0 ratchet primitives are
now wrapped in a clean `Session` class that handles all state automatically.

**Before (v0.5.0): ~200 lines of manual ratchet state management.**
**After (v0.6.0): 5 lines.**

```typescript
// Alice
const aliceSession = Session.initiateFromX3DH({ sharedSecret, ... });
const packet = aliceSession.encrypt(Buffer.from('Hola Bob'));

// Bob
const bobSession = Session.receiveFromX3DH({ sharedSecret, ... });
const plain = bobSession.decrypt(packet);  // → "Hola Bob"
```

- **`Session.initiateFromX3DH(args)`** — Alice's first session with Bob
  - Generates ratchet DH pair, runs initial DH ratchet step
  - Seeds sending chain ready for first encrypt()
- **`Session.receiveFromX3DH(args)`** — Bob's first session with Alice
  - Stores Bob's signed-prekey as initial DH state
  - Receiving chain seeded on first decrypt()
  - Sending chain triggered automatically on first encrypt() reply
- **`session.encrypt(plaintext)`** — Encrypt a message
  - Auto-handles DH rotation when peer's key changes
  - Returns `{ header, ciphertext, mac }` as hex strings (JSON-safe)
- **`session.decrypt(packet)`** — Decrypt + verify a message
  - Handles out-of-order delivery via skipped-keys cache
  - Detects DH rotation from peer and ratchets accordingly
  - Rejects replays (counter going backwards with no cached key)
  - Anti-DoS cap on skipped key derivation (default 2000)
- **`session.serialize()` / `Session.deserialize(data)`** — Full session persistence
  - JSON-safe snapshot including skipped-keys cache
  - Versioned format for forward compatibility (`version: 1`)
- **Diagnostics:** `sendingCounterValue()`, `receivingCounterValue()`, `skippedKeysCount()`
- **Safe output:** `toString()`, `toJSON()`, `util.inspect()` never leak key material

**New types:**
- `EncryptedMessage` — the over-the-wire packet shape
- `SessionInitiateArgs`, `SessionReceiveArgs` — factory params
- `SerializedSession` — JSON snapshot type

**New tests (~80):**
- Single + multi-message round-trips
- Bidirectional flow with DH ratchet rotation
- Out-of-order delivery (skip cache works across rotations)
- Replay detection
- Anti-DoS cap enforcement
- Serialize/deserialize round-trips (including with cached skipped keys)
- 20-message conversation E2E
- App-restart-mid-conversation E2E

### 🔄 Changed

- **`VERSION`** bumped to `'0.6.0'`
- `src/index.ts` exports the new `Session` module

### 🔒 Security

- MAC verified before decryption (no padding oracle)
- Counter-based replay protection
- Anti-DoS cap on skipped key derivation (default 2000, configurable)
- Constant-time MAC compare via `timingSafeEqual`
- Serialized state contains key material — encrypt at rest

### ✅ Compatibility

**100% backwards compatible with v0.5.0.** Existing `deriveRootKey` /
`advanceChainKey` / `MessageHeader` / `SkippedMessageKeys` APIs untouched.

### 📋 What's Next

Sprint 4 (v0.7.0): Storage layer interfaces.
- `IdentityStore` / `PreKeyStore` / `SessionStore` interfaces
- In-memory + file-based implementations bundled

---

## [0.5.0] — 2026-06-02

### ✨ Added — Sprint 3 Part 1: Double Ratchet Primitives

Low-level building blocks for the Double Ratchet algorithm. The high-level
`Session` class arrives in v0.6.0 (Sprint 3 Part 2).

- **`deriveRootKey(rk, myPriv, theirPub)`** — DH ratchet step
  - HKDF-SHA256 with salt=oldRK, info="Signalis_RatchetRoot_v1"
  - Returns new RootKey + new ChainKey
- **`advanceChainKey(ck, counter)`** — symmetric chain advance
  - HMAC-SHA256(ck, 0x01) → MessageKey seed
  - HMAC-SHA256(ck, 0x02) → next ChainKey
- **`advanceChainKeyN(ck, start, target)`** — skip-forward N steps
  - Returns all intermediate MessageKeys (for skipped-key recovery)
- **`expandMessageKey(mk)`** — HKDF to (AES-256 key, HMAC-SHA256 key, IV)
  - 80-byte output split as 32 + 32 + 16
- **`encryptWithMessageKey(mk, plaintext, ad)`** — Encrypt-then-MAC
  - AES-256-CBC with PKCS#7 padding
  - HMAC-SHA256 truncated to 8 bytes (Signal classic spec)
- **`decryptWithMessageKey(mk, ct, mac, ad)`** — Verify-MAC-then-Decrypt
  - MAC verified BEFORE decrypt (prevents padding-oracle attacks)
  - Constant-time comparison via timingSafeEqual
- **`MessageHeader`** class — 40-byte binary header
  - `toBytes()`/`fromBytes()` for MAC computation + wire format
  - `toPayload()`/`fromPayload()` for JSON storage
  - Fields: dhPublicKey (32 bytes), n (uint32), pn (uint32)
- **`SkippedMessageKeys`** class — anti-DoS cache for out-of-order messages
  - Capped at 2000 keys by default (libsignal value)
  - FIFO eviction at capacity
  - `set()`/`take()`/`has()`/`assertCanAdd()` API
  - Configurable maxKeys per instance
- **New AES-CBC primitives in `crypto.ts`**
  - `aesCbcEncrypt(key, iv, plaintext)` — uses `node:crypto` OpenSSL backend
  - `aesCbcDecrypt(key, iv, ciphertext)` — unauthenticated; pair with MAC
- **New constants:**
  - `ROOT_KEY_SIZE = 32`, `CHAIN_KEY_SIZE = 32`
  - `MESSAGE_KEY_MATERIAL_SIZE = 80`
  - `MAC_TRUNCATE_SIZE = 8`
  - `MAX_SKIPPED_MESSAGE_KEYS = 2000`
  - `KDF_CK_NEXT_INPUT = 0x02`, `KDF_CK_MESSAGE_INPUT = 0x01`
  - `getRatchetRootInfo()` → `'Signalis_RatchetRoot_v1'`
  - `getMessageKeyInfo()` → `'Signalis_MessageKeys_v1'`
- **New tests (~95):**
  - 11 tests for `deriveRootKey` (E2E both sides match, forward secrecy, validation)
  - 22 tests for `advanceChainKey` + `advanceChainKeyN`
  - 14 tests for `expandMessageKey` + AES-CBC + HMAC encrypt/decrypt
  - 15 tests for `MessageHeader` (binary + JSON wire format)
  - 16 tests for `SkippedMessageKeys` (FIFO eviction, anti-DoS, etc.)
  - 11 tests for AES-CBC primitive (round-trip, edge cases)
  - 2 E2E tests: manual session simulation across DH ratchet rotation

### 🔄 Changed

- **`VERSION`** bumped to `'0.5.0'`

### 🔒 Security

- AES-CBC + HMAC follows Signal's "classic" encryption pattern (audited for >10 years)
- MAC verification is constant-time (`timingSafeEqual`)
- MAC verified BEFORE attempting decryption (mitigates padding-oracle)
- `SkippedMessageKeys` capped at 2000 entries to prevent DoS via large `header.n`

### ✅ Compatibility

**100% backwards compatible with v0.4.0.** All existing APIs unchanged.

### 📋 What's Next

Sprint 3 Part 2 (v0.6.0): the high-level `Session` class.
- `Session.initiateFromX3DH({...})` — Alice's first session
- `Session.receiveFromX3DH({...})` — Bob's first session
- `session.encrypt(plaintext)` / `session.decrypt(packet)`
- `session.serialize()` / `Session.deserialize(data)`
- Wires together: X3DH → RootKey → ChainKey → MessageKey → AES-CBC + HMAC

---

## [0.4.0] — 2026-05-28

### ✨ Added — Sprint 2 Part 2: X3DH Handshake

The complete Extended Triple Diffie-Hellman protocol from the Signal spec.
Alice and Bob now derive the same 32-byte shared secret asynchronously,
ready to seed the Double Ratchet in v0.5.0.

- **`X3DH.initiate(myIdentity, theirBundle, options)`** — Initiator (Alice) flow
  - Generates a fresh ephemeral keypair
  - Performs 4 ECDH operations (DH1, DH2, DH3, DH4)
  - Derives shared secret via HKDF-SHA256 with `Signalis_X3DH_v1` info
  - Returns `{ sharedSecret, initialMessage, ephemeralPublicKey }`
  - Rejects expired SignedPreKeys by default (configurable)
- **`X3DH.receive(myIdentity, mySpk, myOpk, initialMessage)`** — Responder (Bob) flow
  - Looks up his prekeys by ID from the initial message
  - Performs the mirror 4 ECDH operations
  - Derives the same shared secret Alice computed
  - Returns `{ sharedSecret, oneTimePreKeyId }` so caller can delete consumed OPK
- **`InitialMessage`** class — Structured wire format for the X3DH initial payload
- **`computeInitiatorSharedSecret(...)`** — Low-level primitive (advanced use)
- **`computeResponderSharedSecret(...)`** — Low-level primitive (advanced use)
- New constants:
  - `X3DH_SECRET_SIZE = 32`
  - `X3DH_INITIAL_MESSAGE_MAX_AGE_MS = 30 days`
  - `getX3DHSalt()` — 32 zero bytes (per X3DH spec)
  - `getX3DHPrefix()` — 32 0xFF bytes (per X3DH spec)
- Updated `getX3DHInfo()` returns `'Signalis_X3DH_v1'` (was `'Signalis_X3DH_Key'`)
- New types: `InitialMessagePayload`, `X3DHInitiateResult`, `X3DHReceiveResult`, `X3DHInitiateOptions`
- 50+ new tests including E2E, Mallory attacks, wire-format roundtrip

### 🔄 Changed

- **`VERSION`** constant bumped to `'0.4.0'`
- `X3DH_INFO_STR` changed to `'Signalis_X3DH_v1'` for explicit version identifier (Signal spec compliant)

### 🔒 Security

- `X3DH.initiate` refuses to use expired SignedPreKeys by default (30-day max)
- Mismatched SPK/OPK IDs between initial message and Bob's stored keys throw `PreKeyError`
- Implementation matches the [Signal X3DH spec](https://signal.org/docs/specifications/x3dh/) exactly:
  - F = 0xFF × 32 prefix
  - HKDF salt = 32 zero bytes
  - DH order: DH1=IK_A·SPK_B, DH2=EK_A·IK_B, DH3=EK_A·SPK_B, DH4=EK_A·OPK_B

### ✅ Compatibility

**100% backwards compatible with v0.3.0.**

### 📋 What's Next

Sprint 3 (v0.5.0): the Double Ratchet algorithm.

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
