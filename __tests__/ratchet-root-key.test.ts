import { describe, it, expect } from 'vitest';

import {
  deriveRootKey,
  ROOT_KEY_SIZE,
  CHAIN_KEY_SIZE,
  ValidationError,
  crypto,
} from '../src';
import { asPublicKey, asPrivateKey, asRootKey } from '../src/types';

// ═══════════════════════════════════════════════════════════════════════════
// Helper
// ═══════════════════════════════════════════════════════════════════════════

function rawKp() {
  const kp = crypto.generateKeyPair();
  return { pub: asPublicKey(kp.publicKey), priv: asPrivateKey(kp.privateKey) };
}

function freshRootKey() {
  return asRootKey(crypto.randomBytes(ROOT_KEY_SIZE));
}

// ═══════════════════════════════════════════════════════════════════════════
// deriveRootKey
// ═══════════════════════════════════════════════════════════════════════════

describe('deriveRootKey (DH ratchet step)', () => {
  it('produces RootKey + ChainKey of correct sizes', () => {
    const rk = freshRootKey();
    const alice = rawKp();
    const bob = rawKp();

    const result = deriveRootKey(rk, alice.priv, bob.pub);

    expect(result.rootKey.length).toBe(ROOT_KEY_SIZE);
    expect(result.chainKey.length).toBe(CHAIN_KEY_SIZE);
  });

  it('both sides derive the SAME RK + CK (symmetric DH)', () => {
    const rk = freshRootKey();
    const alice = rawKp();
    const bob = rawKp();

    const aliceResult = deriveRootKey(rk, alice.priv, bob.pub);
    const bobResult = deriveRootKey(rk, bob.priv, alice.pub);

    expect(aliceResult.rootKey.equals(bobResult.rootKey)).toBe(true);
    expect(aliceResult.chainKey.equals(bobResult.chainKey)).toBe(true);
  });

  it('different starting RKs → different outputs', () => {
    const rk1 = freshRootKey();
    const rk2 = freshRootKey();
    const alice = rawKp();
    const bob = rawKp();

    const r1 = deriveRootKey(rk1, alice.priv, bob.pub);
    const r2 = deriveRootKey(rk2, alice.priv, bob.pub);

    expect(r1.rootKey.equals(r2.rootKey)).toBe(false);
    expect(r1.chainKey.equals(r2.chainKey)).toBe(false);
  });

  it('different DH keys → different outputs', () => {
    const rk = freshRootKey();
    const alice = rawKp();
    const bob1 = rawKp();
    const bob2 = rawKp();

    const r1 = deriveRootKey(rk, alice.priv, bob1.pub);
    const r2 = deriveRootKey(rk, alice.priv, bob2.pub);

    expect(r1.rootKey.equals(r2.rootKey)).toBe(false);
  });

  it('chained derivations produce distinct keys (forward secrecy)', () => {
    const rk0 = freshRootKey();
    const alice = rawKp();
    const bob = rawKp();
    const eve = rawKp();

    const step1 = deriveRootKey(rk0, alice.priv, bob.pub);
    const step2 = deriveRootKey(step1.rootKey, alice.priv, eve.pub);

    // Each step produces a fresh root and chain key
    expect(step1.rootKey.equals(step2.rootKey)).toBe(false);
    expect(step1.chainKey.equals(step2.chainKey)).toBe(false);
  });

  it('deterministic: same inputs → same output', () => {
    const rk = freshRootKey();
    const alice = rawKp();
    const bob = rawKp();

    const r1 = deriveRootKey(rk, alice.priv, bob.pub);
    const r2 = deriveRootKey(rk, alice.priv, bob.pub);

    expect(r1.rootKey.equals(r2.rootKey)).toBe(true);
    expect(r1.chainKey.equals(r2.chainKey)).toBe(true);
  });

  // ─── Validation errors ────────────────────────────────────────────────

  it('rejects wrong RootKey size', () => {
    const alice = rawKp();
    const bob = rawKp();
    // Bypass asRootKey() so deriveRootKey itself does the size check.
    const badRk = Buffer.alloc(10) as never;

    expect(() => deriveRootKey(badRk, alice.priv, bob.pub)).toThrow(ValidationError);
  });

  it('rejects non-Buffer RootKey', () => {
    const alice = rawKp();
    const bob = rawKp();

    expect(() =>
      deriveRootKey('not a buffer' as never, alice.priv, bob.pub),
    ).toThrow(ValidationError);
  });
});
