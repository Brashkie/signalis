# Roadmap

This document outlines the planned evolution of `@brashkie/signalis` over the next 12-18 months.

The project follows a **sprint-based** development model. Each sprint adds a major component of the Signal Protocol stack.

---

## 🗺️ High-Level Vision

```
v0.1 ─ Identity Keys + PreKey scaffolding              ✅ Released
v0.2 ─ Real XEd25519 signing (Sprint 1 Part 2)         ✅ Released  ← we are here
v0.3 ─ Sprint 2: PreKey Bundles + X3DH                 🚧 Active
v0.4 ─ Sprint 3: Double Ratchet                        🔜 Planned
v0.5 ─ Sprint 4: Storage Layer                         🔜 Planned
v0.6 ─ Sprint 5: Group messaging (Sender Keys)         🔜 Planned
v0.7 ─ Performance & API polish
v0.8 ─ Beta — Production hardening
v0.9 ─ RC — External audit
v1.0 ─ Stable API + Production-ready
```

---

## ✅ Sprint 1 (v0.1.0 → v0.2.0): Identity Foundation

**Status:** Complete

### Delivered

- ✅ `IdentityKeyPair` class with serialization/deserialization
- ✅ `PublicIdentityKey` class with hex/base64 import/export
- ✅ Branded types (`PublicKey`, `PrivateKey`, `Signature`, `ChainKey`, `RootKey`, etc.)
- ✅ Type guards and validation helpers
- ✅ Typed error hierarchy with codes & context
- ✅ Constants module (sizes, info strings, validators)
- ✅ Cryptographic wrappers over `@brashkie/signalis-core`
- ✅ Safe `toString()` / `toJSON()` (no private key leak)
- ✅ Fingerprint generation (SHA-256 of public key)

### Sprint 1 Part 2 (v0.2.0) — Added

- ✅ `identity.sign(message)` — XEd25519 signing
- ✅ `identity.verify(message, sig)` / `verifyBool(...)`
- ✅ `pub.verify(message, sig)` / `verifyBool(...)`
- ✅ `signWithRandom` for deterministic testing
- ✅ Standard `Ed25519` wrappers (separate from Curve25519)
- ✅ AES-GCM AAD support
- ✅ RFC 8032 test vectors
- ✅ Mallory forgery prevention tests

---

## 🚧 Sprint 2 (v0.3.0): PreKey Bundles + X3DH

**Status:** Part 1 complete (v0.3.0 published)

### Part 1: PreKey Layer ✅ DONE (v0.3.0)

- ✅ `OneTimePreKey` class with batch generation
- ✅ `PublicOneTimePreKey` for server payloads
- ✅ `SignedPreKey` class — signed with identity (XEd25519)
- ✅ `PublicSignedPreKey.fromPayload()` with automatic verification
- ✅ `PreKeyBundle` class — complete X3DH payload
- ✅ `PreKeyBundle.fromPayload()` with automatic verification
- ✅ Rotation/expiration helpers (`needsRotation`, `isExpired`, `ageMs`)
- ✅ 140+ tests including Mallory forgery prevention

### Part 2: X3DH Handshake 🚧 IN DEVELOPMENT

**Target:** ~2-3 weeks after v0.3.0

### Goals

Implement the **Extended Triple Diffie-Hellman (X3DH)** handshake protocol, allowing two parties to establish an initial shared secret asynchronously (without both being online).

### Scope

```typescript
// One-Time PreKeys (single-use)
class OneTimePreKey {
  readonly id: number;
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
  static generate(id: number): OneTimePreKey;
  static generateBatch(startId: number, count: number): OneTimePreKey[];
  serialize() / deserialize()
}

// Signed PreKey (rotated periodically)
class SignedPreKey {
  readonly id: number;
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
  readonly signature: Signature;     // ← Signed by IdentityKeyPair via XEd25519
  readonly timestamp: number;
  
  static generate(identity: IdentityKeyPair, id: number): SignedPreKey;
  verify(identityPub: PublicIdentityKey): boolean;
  needsRotation(maxAge?: number): boolean;
}

// PreKey Bundle (server-facing, includes everything for X3DH)
interface PreKeyBundle {
  registrationId: number;
  deviceId: number;
  identityKey: PublicIdentityKey;
  signedPreKey: { id, publicKey, signature };
  oneTimePreKey?: { id, publicKey };  // Optional: server picks one
}

// X3DH Handshake
namespace X3DH {
  // Alice initiates a session with Bob
  function initiate(
    aliceIdentity: IdentityKeyPair,
    bobBundle: PreKeyBundle,
  ): {
    sharedSecret: SharedSecret;
    initialMessage: InitialMessage;
  };
  
  // Bob receives Alice's initial message and derives the same secret
  function receive(
    bobIdentity: IdentityKeyPair,
    bobSignedPreKey: SignedPreKey,
    bobOneTimePreKey: OneTimePreKey | undefined,
    initialMessage: InitialMessage,
  ): SharedSecret;
}
```

### Technical Details

- **4-way Diffie-Hellman:** DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B)
- **HKDF derivation:** `SK = HKDF(salt, DH1 || DH2 || DH3 || DH4, "Signalis_X3DH_v1", 32)`
- **Signed prekey verification:** `XEd25519.verify(bobIdentity.publicKey, bobSpk.publicKey, bobSpk.signature)`
- **Reference:** https://signal.org/docs/specifications/x3dh/

### Acceptance Criteria

- ✅ Round-trip test: Alice and Bob derive identical `SharedSecret`
- ✅ Tampered bundles fail verification
- ✅ Missing OneTimePreKey path works (with reduced FS guarantees)
- ✅ Replay protection considered
- ✅ Conformance with Signal Protocol spec

---

## 🔜 Sprint 3 (v0.4.0): Double Ratchet

**Target:** ~6-8 weeks after Sprint 2

### Goals

Implement the **Double Ratchet algorithm** for forward and backward secrecy on every message.

### Scope

```typescript
class Session {
  // Encrypt outgoing message (advances symmetric ratchet)
  encrypt(plaintext: Buffer): EncryptedMessage;
  
  // Decrypt incoming message (handles out-of-order delivery)
  decrypt(packet: EncryptedMessage): Buffer;
  
  // Persist session state
  serialize(): SerializedSession;
  static deserialize(data: SerializedSession): Session;
}
```

### Technical Details

- **Symmetric-key ratchet:** Chain keys derived via HKDF on each message
- **Diffie-Hellman ratchet:** Triggered when a new ratchet key is received
- **Skipped message keys:** Buffer for out-of-order messages (with cap to prevent DoS)
- **Reference:** https://signal.org/docs/specifications/doubleratchet/

### Acceptance Criteria

- ✅ Forward secrecy: compromising current key doesn't decrypt past messages
- ✅ Backward secrecy (future secrecy): compromising current key doesn't decrypt future messages after rotation
- ✅ Out-of-order delivery works (within configurable window)
- ✅ Replay attacks detected
- ✅ Conformance with Signal Protocol spec

---

## 🔜 Sprint 4 (v0.5.0): Storage Layer

**Target:** ~4 weeks after Sprint 3

### Goals

Define the **storage interfaces** so applications can persist sessions, keys, and identities.

### Scope

```typescript
interface IdentityStore {
  getIdentityKeyPair(): Promise<IdentityKeyPair>;
  getLocalRegistrationId(): Promise<number>;
  saveIdentity(addr: ProtocolAddress, identity: PublicIdentityKey): Promise<boolean>;
  isTrustedIdentity(addr, identity, direction): Promise<boolean>;
}

interface PreKeyStore {
  loadPreKey(id: number): Promise<OneTimePreKey>;
  storePreKey(id: number, key: OneTimePreKey): Promise<void>;
  containsPreKey(id: number): Promise<boolean>;
  removePreKey(id: number): Promise<void>;
}

interface SignedPreKeyStore { /* similar */ }
interface SessionStore { /* similar */ }
```

### Deliverables

- ✅ `InMemoryStore` reference implementation (for tests)
- ✅ `SQLiteStore` reference (recommended for production)
- ✅ Documentation for implementing custom stores
- ✅ Migration helpers between stores

---

## 🔜 Sprint 5 (v0.6.0): Group Messaging

**Target:** ~4-6 weeks after Sprint 4

### Goals

Implement **Sender Keys** for efficient group messaging (Signal-style).

### Scope

```typescript
class GroupSession {
  encrypt(plaintext: Buffer): GroupMessage;
  decrypt(senderKey: SenderKey, packet: GroupMessage): Buffer;
  
  // Member management
  addMember(memberId: string, senderKey: SenderKey): void;
  removeMember(memberId: string): void;
  rotateMyKey(): SenderKey;
}
```

### Acceptance Criteria

- ✅ O(1) encryption per message (vs O(N) pairwise)
- ✅ Member rotation works
- ✅ Members removed cannot decrypt future messages
- ✅ Conformance with Signal Protocol spec

---

## 🔜 v0.7.0 — Performance & API Polish

- Benchmarking suite
- Streaming APIs (for large messages)
- Better error messages
- API ergonomics improvements
- TypeScript 6.x optimizations

---

## 🔜 v0.8.0 — Beta

- Hardening against edge cases
- Property-based testing (fast-check)
- Fuzzing of decoders
- Memory leak audits
- Production deployment checklist

---

## 🔜 v0.9.0 — Release Candidate

- **External security audit** by a reputable firm
- Fix audit findings
- Documentation site (Docusaurus)
- Comprehensive examples + tutorials
- Stable API freeze

---

## 🎯 v1.0.0 — Production-Ready

- Audit completed with no critical findings
- All sprints (1-5) complete
- 95%+ test coverage
- Documentation site live
- Multiple production deployments
- Semantic versioning commitment from this point

---

## 🌌 Beyond v1.0

### v1.x

- **PostgreSQL adapter** for storage
- **Redis adapter** for distributed sessions
- **WASM build** for browsers (if signalis-core supports it)
- **Deno / Bun** native support
- **Performance optimizations** (sub-microsecond crypto)

### v2.x (Far Future)

- **MLS support** (Messaging Layer Security, RFC 9420)
- **Post-quantum** primitives (Kyber, Dilithium) when standardized
- **Hardware token** support (YubiKey, etc.)

---

## 🚀 Ecosystem Roadmap

While `@brashkie/signalis` matures, the surrounding Hepein stack will grow:

```
@brashkie/signalis-core    ← Crypto primitives        ✅ v0.2.0 published
@brashkie/signalis         ← Signal Protocol logic    ✅ v0.2.0 (we are here)
@brashkie/waproto          ← WhatsApp wire format     🔜 After signalis v0.4
HepeinBaileys 2.0          ← Full WhatsApp client     🔜 Far future
```

---

## 💬 Feedback

This roadmap is a living document and may change based on:

- Community feedback
- Security advisories or audit findings
- Real-world use cases

To propose changes, open a [discussion](https://github.com/Brashkie/signalis/discussions) or [issue](https://github.com/Brashkie/signalis/issues).

---

🔐 + ❤️ [Hepein Oficial](https://github.com/Brashkie)
