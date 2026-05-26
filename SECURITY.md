# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | ✅        |
| 0.1.x   | ⚠️ Critical fixes only |
| < 0.1   | ❌        |

---

## 🔐 Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

Instead, report security issues responsibly via one of these channels:

- **Email:** `security@hepein.com` (preferred)
- **GitHub Security Advisories:** [Create a private report](https://github.com/Brashkie/signalis/security/advisories/new)

### What to Include

To help us triage quickly, please provide:

1. **Affected versions** (e.g., "v0.2.0 and earlier")
2. **Component / file** where the issue lives
3. **Description** of the vulnerability
4. **Steps to reproduce** (proof-of-concept code if possible)
5. **Impact assessment** (what an attacker could do)
6. **Suggested fix** (if you have one)
7. **Your name** (for credit in advisories, or "anonymous" if preferred)

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Acknowledgement of report | Within 48 hours |
| Initial assessment | Within 7 days |
| Patch development | Within 30 days for critical issues |
| Public disclosure | After patch is released (coordinated) |

---

## 🛡️ Security Properties

`@brashkie/signalis` aims to provide:

### Cryptographic Guarantees

- **Confidentiality:** AES-256-GCM authenticated encryption
- **Integrity:** Every ciphertext is MAC-authenticated
- **Authentication:** XEd25519 signatures bind messages to identity keys
- **Forward Secrecy** (planned, Sprint 3): Past messages remain safe even if current keys are compromised
- **Backward Secrecy** (planned, Sprint 3): Future messages remain safe after a compromise

### Implementation Properties

- **Constant-time operations** for all comparisons and verifications (delegated to Rust layer)
- **Memory zeroization** of private keys when dropped (in Rust layer)
- **Type safety** via TypeScript branded types
- **Safe defaults** — `toString()`, `toJSON()` never leak private keys
- **Input validation** on all public API surfaces

### What We Do NOT Promise

- **Side-channel resistance** beyond what the underlying primitives provide
- **Hardware security** — we run on standard JavaScript runtimes
- **Quantum resistance** — Curve25519 / Ed25519 are vulnerable to a sufficiently large quantum computer (post-quantum is on the long-term roadmap)
- **Protection against compromised endpoints** — if an attacker controls your device, no library can save you

---

## 🚨 Security-Critical Usage Rules

### DO

✅ **Always store identity keys in encrypted storage** (KMS, OS keychain, encrypted DB)

✅ **Verify fingerprints out-of-band** before trusting a public key

✅ **Use unique nonces** for every AES-GCM encryption with the same key

✅ **Validate all inputs** from untrusted sources before passing to library APIs

✅ **Keep dependencies up to date** — run `npm audit` regularly

✅ **Use TLS** for all key transport over networks

### DON'T

❌ **NEVER log a serialized `IdentityKeyPair`** — it contains the private key

❌ **NEVER transmit a serialized `IdentityKeyPair`** over the network

❌ **NEVER use `console.log(identity)` without verifying** it goes through the safe `toString()`

❌ **NEVER reuse a (key, nonce) pair** in AES-GCM — catastrophic failure mode

❌ **NEVER use ECDH shared secrets directly** — always derive via HKDF first

❌ **NEVER skip signature verification** for "performance"

❌ **NEVER implement your own crypto on top** of these primitives without expert review

---

## 🔍 What's SAFE to Output

```typescript
const alice = IdentityKeyPair.generate();

// ✅ All of these are SAFE — they do NOT include the private key
console.log(alice);                  // "IdentityKeyPair(public=a1b2c3...)"
console.log(alice.toString());       // Same
console.log(JSON.stringify(alice));  // {"type":"IdentityKeyPair","publicKey":"..."}
console.log(alice.fingerprint());    // SHA-256 hex of public key
console.log(alice.toPublic().toHex()); // public key only
```

## 🔥 What's DANGEROUS

```typescript
// ⚠️ EXPLICITLY EXPOSES PRIVATE KEY
console.log(alice.serialize());        // { publicKey, privateKey } ← PRIVATE KEY!
console.log(alice.privateKey);         // raw 32-byte buffer of private key
console.log(alice.privateKey.toString('hex'));  // hex of private key

// ⚠️ NEVER do this:
fs.writeFile('/tmp/identity.json', JSON.stringify(alice.serialize()));
fetch('/api', { body: JSON.stringify(alice.serialize()) });
```

---

## 🧪 Audit Status

| Component | Status |
|-----------|--------|
| `@brashkie/signalis` | ⚠️ **Not yet audited** — pre-1.0 |
| `@brashkie/signalis-core` (crypto primitives) | ⚠️ Not yet audited, but built on audited Rust crates |
| `curve25519-dalek` (used by core) | ✅ Multiple audits |
| `ed25519-dalek` (used by core) | ✅ Multiple audits |
| `RustCrypto` (used by core) | ✅ Various audits |

An **external security audit** of `@brashkie/signalis` is planned for the v0.9.0 release candidate.

Until then, use this library at your own risk for production deployments.

---

## 📚 References

The protocol implementations follow these specifications:

- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal XEdDSA Specification](https://signal.org/docs/specifications/xeddsa/)
- [RFC 7748 — Curve25519 / Curve448](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 8032 — Ed25519](https://datatracker.ietf.org/doc/html/rfc8032)
- [RFC 5869 — HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [NIST SP 800-38D — AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

---

## 🙏 Acknowledgements

We deeply appreciate security researchers who help keep `@brashkie/signalis` safe. Contributors will be credited in security advisories (unless anonymity is requested).

---

🔐 + ❤️ [Hepein Oficial](https://github.com/Brashkie)
