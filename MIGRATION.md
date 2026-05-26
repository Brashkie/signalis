# Migration Guide

## v0.1.0 → v0.2.0

**TL;DR:** 100% drop-in replacement. Just update the version.

```bash
npm install @brashkie/signalis@^0.2.0
```

No code changes needed. All v0.1.0 APIs continue to work identically.

⚠️ **This update also bumps the underlying `@brashkie/signalis-core` dependency** from `^0.1.0` to `^0.2.0`. Run `npm install` after applying.

---

## What's New (Capabilities You Now Have)

You can now sign and verify data with identity keys — something that wasn't possible in v0.1.0.

### Signing with your identity

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

const alice = IdentityKeyPair.generate();
const message = Buffer.from('Hello, signed world');

// NEW: sign
const signature = alice.sign(message);

// NEW: verify (throws SignatureError on failure)
alice.verify(message, signature);

// NEW: verify (boolean, no throw)
if (alice.verifyBool(message, signature)) {
  console.log('Valid');
}
```

### Verifying signatures from peers

```typescript
import { PublicIdentityKey } from '@brashkie/signalis';

// Receive Alice's public identity over the network
const alicePub = PublicIdentityKey.fromHex(receivedHex);

// NEW: verify a signature from Alice
try {
  alicePub.verify(message, signature);
  console.log('✅ Authentic message from Alice');
} catch (e) {
  console.error('❌ Tampered or forged');
}
```

### AES-GCM with AAD (low-level)

```typescript
import { crypto } from '@brashkie/signalis';

// NEW: bind metadata (header) to ciphertext
const header = Buffer.from(JSON.stringify({ msg_id: 1, from: 'alice' }));
const ct = crypto.aesGcmEncryptWithAad(key, nonce, body, header);

// Must pass SAME header to decrypt; mismatch fails
const pt = crypto.aesGcmDecryptWithAad(key, nonce, ct, header);
```

### Ed25519 (standard, deterministic)

For when you want **separate signing keys** (not the Curve25519 identity key):

```typescript
import { crypto } from '@brashkie/signalis';

// NEW: separate Ed25519 keypair
const ed = crypto.generateEd25519KeyPair();
const sig = crypto.signEd25519(ed.privateKey, message);  // deterministic
crypto.verifyEd25519(ed.publicKey, message, sig);

// NEW: derive Ed25519 from a 32-byte seed (deterministic, reproducible)
const seed = Buffer.alloc(32, 0x42);
const fromSeed = crypto.ed25519FromSeed(seed);
```

---

## Step-by-Step Migration

### 1. Update the package

```bash
npm install @brashkie/signalis@^0.2.0
# This automatically updates @brashkie/signalis-core to ^0.2.0
```

### 2. Verify the version

```bash
node -e "console.log(require('@brashkie/signalis').VERSION)"
# Should print: 0.2.0
```

### 3. Run your existing tests

Your existing test suite should pass without modifications.

```bash
npm test
```

If anything fails, [open an issue](https://github.com/Brashkie/signalis/issues) — that would be a bug in v0.2.0.

### 4. (Optional) Adopt new features

Replace any manual HMAC-based "authentication" with proper signatures:

**Before (v0.1.0 workaround):**
```typescript
// Using HMAC over arbitrary data
const tag = crypto.hmac(sharedKey, dataToAuthenticate);
const valid = crypto.hmacVerify(sharedKey, dataToAuthenticate, receivedTag);
```

**After (v0.2.0 proper):**
```typescript
// Sign with identity key, verify with public key
const sig = alice.sign(dataToAuthenticate);
alicePub.verify(dataToAuthenticate, sig);
```

**When to use which:**

| Need | Use |
|------|-----|
| Anyone with my **public key** can verify | `identity.sign()` / `pub.verify()` (XEd25519) |
| Both sides already share a **secret key** | `crypto.hmac()` / `hmacVerify()` |

---

## What's NOT Changed

These continue to work exactly as in v0.1.0:

| API | Status |
|-----|--------|
| `IdentityKeyPair.generate()` | ✅ Unchanged |
| `IdentityKeyPair.fromKeys()` | ✅ Unchanged |
| `IdentityKeyPair.deserialize()` | ✅ Unchanged |
| `identity.serialize()` | ✅ Unchanged |
| `identity.toPublic()` | ✅ Unchanged |
| `identity.fingerprint()` / `shortFingerprint()` | ✅ Unchanged |
| `identity.equals(other)` | ✅ Unchanged |
| `identity.toJSON()` / `toString()` | ✅ Unchanged (still safe) |
| `PublicIdentityKey.fromHex()` / `fromBase64()` | ✅ Unchanged |
| `pub.toHex()` / `toBase64()` | ✅ Unchanged |
| `pub.fingerprint()` / `shortFingerprint()` | ✅ Unchanged |
| `pub.equals()` | ✅ Unchanged |
| All branded types | ✅ Unchanged |
| All error classes | ✅ Unchanged |
| All constants (except `VERSION`) | ✅ Unchanged |
| All `crypto.*` wrappers (existing ones) | ✅ Unchanged |

The only observable changes are:
- `VERSION === '0.2.0'`
- `@brashkie/signalis-core` dependency is now `^0.2.0`

---

## Performance

No performance regressions. New primitives:

| Operation | Approximate throughput |
|-----------|------------------------|
| `identity.sign()` (XEd25519) | ~25,000/sec |
| `identity.verify()` (XEd25519) | ~10,000/sec |
| `crypto.signEd25519()` | ~25,000/sec |
| `crypto.verifyEd25519()` | ~10,000/sec |
| AES-GCM with AAD | <5% overhead vs no AAD |

(From `@brashkie/signalis-core` benchmarks on M2 MacBook Pro.)

---

## Compatibility Matrix

| Node.js | Status |
|---------|--------|
| 18.x | ✅ Supported |
| 20.x | ✅ Supported |
| 22.x | ✅ Supported |
| 24.x | ✅ Supported |

| Platform | Status |
|----------|--------|
| Windows x64 (MSVC) | ✅ Prebuilt (via signalis-core) |
| macOS x64 / arm64 | ✅ Prebuilt |
| Linux x64 / arm64 (glibc + musl) | ✅ Prebuilt |

---

## FAQ

### Q: Do I have to change anything in my code?

**A:** No. v0.2.0 is 100% backwards compatible.

### Q: Why use XEd25519 instead of Ed25519?

**A:**
- **XEd25519** uses your existing Curve25519 identity key for signing. This is what the **Signal Protocol** does — one key for ECDH and signing.
- **Ed25519** requires a separate keypair but is deterministic (RFC 8032 compliant).

Use XEd25519 by default unless you need RFC 8032 compatibility or deterministic signatures.

### Q: Is XEd25519 less secure than Ed25519?

**A:** No. Both provide the same 128-bit security level. XEd25519 is a clever construction that lets you reuse a Curve25519 key for signing without compromising security. It's been used by Signal in production for years.

### Q: When will Sprint 2 (X3DH) be ready?

**A:** Sprint 2 is being actively developed. See [ROADMAP.md](ROADMAP.md) for status.

### Q: What if I find a bug?

**A:** [Open an issue](https://github.com/Brashkie/signalis/issues) on GitHub. For security issues, see [SECURITY.md](SECURITY.md).

---

## Resources

- [README.md](README.md) — Library overview
- [API.md](API.md) — Full API reference
- [EXAMPLES.md](EXAMPLES.md) — Usage examples
- [CHANGELOG.md](CHANGELOG.md) — Full release history

🔐 + ❤️ Hepein Oficial
