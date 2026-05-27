# Migration Guide

## v0.2.0 → v0.3.0

**TL;DR:** 100% drop-in replacement. Just update the version.

```bash
npm install @brashkie/signalis@^0.3.0
```

No code changes needed. All v0.2.0 APIs continue to work identically.

---

## What's New (Capabilities You Now Have)

You can now publish and consume **PreKey Bundles** — the foundation for the X3DH handshake that lets you start sessions asynchronously.

### Publishing prekeys (Bob's side)

```typescript
import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
} from '@brashkie/signalis';

// Bob's long-term identity (do this once at registration)
const bob = IdentityKeyPair.generate();

// Medium-term signed prekey (rotate every 7 days)
const bobSpk = SignedPreKey.generate(bob, 1);

// One-time prekeys (generate a batch, upload public halves to server)
const bobOtpks = OneTimePreKey.generateBatch(1, 100);

// Build the bundle for the server (it picks one OTPK per request)
const bundleForAlice = PreKeyBundle.build({
  registrationId: 12345,
  deviceId: 1,
  identityKey: bob.toPublic(),
  signedPreKey: bobSpk.toPublic(),
  oneTimePreKey: bobOtpks[0].toPublic(),
});

const payload = bundleForAlice.toPayload();
await uploadToServer(payload);
```

### Fetching and verifying a peer's bundle (Alice's side)

```typescript
import { PreKeyBundle } from '@brashkie/signalis';

const payload = await fetchBobBundleFromServer();

// fromPayload AUTOMATICALLY verifies the signed prekey's signature
// against the identity key in the bundle. Tampering → throws SignatureError.
const bobBundle = PreKeyBundle.fromPayload(payload);

console.log(`Bob address: ${bobBundle.address()}`);
// Bundle ready for X3DH.initiate() in v0.4.0
```

### Rotation helpers

```typescript
const spk = SignedPreKey.generate(bob, 1);

if (spk.needsRotation()) {
  const fresh = SignedPreKey.generate(bob, spk.id + 1);
  await uploadToServer(fresh.toPayload());
}

if (spk.isExpired()) {
  throw new Error('SignedPreKey too old to use');
}
```

---

## Step-by-Step Migration

### 1. Update the package

```bash
npm install @brashkie/signalis@^0.3.0
```

### 2. Verify the version

```bash
node -e "console.log(require('@brashkie/signalis').VERSION)"
# Should print: 0.3.0
```

### 3. Run your existing tests

Your existing test suite should pass without modifications.

```bash
npm test
```

---

## What's NOT Changed

These continue to work exactly as in v0.2.0:

| API | Status |
|-----|--------|
| `IdentityKeyPair.*` (all methods) | ✅ Unchanged |
| `PublicIdentityKey.*` (all methods) | ✅ Unchanged |
| `IdentityKeyPair.sign() / verify()` (v0.2.0 XEd25519) | ✅ Unchanged |
| All branded types | ✅ Unchanged |
| All error classes | ✅ Unchanged |
| All `crypto.*` wrappers | ✅ Unchanged |
| All constants (except `VERSION`) | ✅ Unchanged |

---

## FAQ

### Q: Do I have to publish prekeys to use signalis?

**A:** Not yet. PreKeys are only needed for X3DH (Sprint 2 Part 2 — v0.4.0). v0.3.0 ships the data structures; v0.4.0 wires them into the handshake.

### Q: How many one-time prekeys should I generate?

**A:** The convention is 100 at a time (`MAX_ONE_TIME_PREKEYS`). Refill when you go below 10 (`MIN_ONE_TIME_PREKEYS`).

### Q: How often should I rotate the SignedPreKey?

**A:** Every 7 days is recommended (`SIGNED_PREKEY_ROTATION_MS`). Past 30 days (`SIGNED_PREKEY_MAX_AGE_MS`) it should not be used for new sessions.

### Q: What if PreKeyBundle.fromPayload throws SignatureError?

**A:** That means either:
- The bundle was tampered with in transit
- The server is malicious and substituted keys
- The `identityKey` field doesn't match the one that originally signed the prekey

Treat it as a critical security event. Do not proceed.

---

## v0.1.0 → v0.2.0 (Previous Migration)

If you're coming from v0.1.0, you can update directly to v0.3.0 — both upgrades are backwards compatible. See the [v0.2.0 migration notes](https://github.com/Brashkie/signalis/blob/v0.2.0/MIGRATION.md) for the XEd25519 signing additions.

---

🔐 + ❤️ Hepein Oficial
