# 📚 Signalis Examples

Hands-on examples covering every feature of `@brashkie/signalis` up to v0.5.0.

Each example is self-contained, heavily commented, and runs against the
public API exactly as you'd use it in a real app.

## 🚀 Quick Start

```bash
# From the repo root:
npm install
npm run build

# Run any example (TypeScript):
npx tsx examples/01-identity-keys.ts

# Run any JavaScript example:
node examples/02-prekey-bundle.js
node examples/03-x3dh-handshake.mjs
node examples/04-ratchet-encrypt.js

# More TS examples:
npx tsx examples/05-full-flow.ts
npx tsx examples/06-persistence-pattern.ts
```

## 📖 Examples

| # | File | Format | Topic | Sprint |
|---|------|--------|-------|--------|
| 1 | `01-identity-keys.ts` | TypeScript (ESM) | Identity keys, signing, verification | 1 |
| 2 | `02-prekey-bundle.js` | JS CommonJS (require) | PreKey bundle setup & verification | 2.1 |
| 3 | `03-x3dh-handshake.mjs` | JS ESM (import) | X3DH async key agreement | 2.2 |
| 4 | `04-ratchet-encrypt.js` | JS CommonJS (require) | Manual Double Ratchet encrypt/decrypt | 3.1 |
| 5 | `05-full-flow.ts` | TypeScript (ESM) | Full flow: X3DH → Ratchet → messages | 2.2 + 3.1 |
| 6 | `06-persistence-pattern.ts` | TypeScript (ESM) | Storing identity + prekeys to disk | — |

## 🎯 Recommended Reading Order

**Just want to understand the protocol?** Read in order: 1 → 2 → 3 → 4 → 5.

**Building a real app?** Read in this order:
1. **Example 1** — understand identity keys and signatures
2. **Example 6** — understand persistence patterns BEFORE you code
3. **Example 2** — implement bundle publishing
4. **Example 3** — implement X3DH on both sides
5. **Example 4** — understand what the ratchet does internally
6. **Example 5** — see how they all compose

## 🆚 Format Differences

### TypeScript ESM (`.ts`)
```typescript
import { IdentityKeyPair } from '@brashkie/signalis';
const alice = IdentityKeyPair.generate();
```
Run with: `npx tsx examples/file.ts`

### JavaScript CommonJS (`.js`)
```javascript
const { IdentityKeyPair } = require('@brashkie/signalis');
const alice = IdentityKeyPair.generate();
```
Run with: `node examples/file.js`

### JavaScript ESM (`.mjs`)
```javascript
import { IdentityKeyPair } from '@brashkie/signalis';
const alice = IdentityKeyPair.generate();
```
Run with: `node examples/file.mjs`

> `@brashkie/signalis` ships as a **dual ESM/CJS package** — both formats
> work natively, no transpilation needed for ESM `.mjs` files.

## 🆘 Troubleshooting

### `Cannot find module '@brashkie/signalis'`

Make sure you've built the package:
```bash
npm install
npm run build
```

If running from a freshly cloned repo, the examples import from the local
`dist/` folder via the `package.json` `exports` field.

### `Error: Invalid initialization vector`

You're probably mixing up `AES_NONCE_SIZE` (12, for AES-GCM) and
`AES_CBC_IV_SIZE` (16, for AES-CBC). Use the right one for the right mode.

### Example 04 / 05 looks complicated

Yes — manual ratchet state management is verbose. **The `Session` class in
v0.6.0 reduces it to:**
```typescript
const session = Session.initiateFromX3DH({...});
const packet = session.encrypt(plaintext);
```

We're shipping the primitives first (v0.5.0) so the high-level API has a
solid foundation. Hold tight.

## 🔒 Security Notes for Production

All examples use **in-memory keys with no encryption at rest**. Real
applications MUST:

1. **Encrypt private keys before storing.** Use:
   - macOS / Linux / Windows: [`keytar`](https://www.npmjs.com/package/keytar) (OS keychain)
   - Server: AWS KMS, HashiCorp Vault, GCP KMS
   - Mobile: iOS Keychain / Android KeyStore
   - Browser: NEVER plain `localStorage` — use the WebCrypto SubtleCrypto API
     with hardware-backed keys when available

2. **Never log private keys.** `console.log(identity)` is SAFE — `toString()`
   intentionally redacts the private side. But `console.log(identity.serialize())`
   would dump everything.

3. **Verify fingerprints out-of-band** before trusting public keys.
   Show users the fingerprint of new contacts via QR code, voice, or any
   channel they trust.

4. **Delete consumed OneTimePreKeys** from your store immediately upon use
   (forward secrecy). Example 06 shows the pattern.

5. **Rotate SignedPreKeys weekly** using `spk.needsRotation()`.

## 📬 Feedback

These examples are a living document. If something is unclear, file an issue:
https://github.com/Brashkie/signalis/issues

---

🔐 + ❤️ Hepein Oficial
