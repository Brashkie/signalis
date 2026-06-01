import { describe, it, expect } from 'vitest';

import { crypto } from '../src';
import {
  computeInitiatorSharedSecret,
  computeResponderSharedSecret,
} from '../src/x3dh/shared-secret';
import { asPublicKey, asPrivateKey } from '../src/types';
import { X3DH_SECRET_SIZE } from '../src/constants';

// ═══════════════════════════════════════════════════════════════════════════
// Helper: create raw keypairs for low-level testing
// ═══════════════════════════════════════════════════════════════════════════

function rawKp() {
  const kp = crypto.generateKeyPair();
  return { pub: asPublicKey(kp.publicKey), priv: asPrivateKey(kp.privateKey) };
}

// ═══════════════════════════════════════════════════════════════════════════
// computeInitiatorSharedSecret + computeResponderSharedSecret
// ═══════════════════════════════════════════════════════════════════════════

describe('X3DH shared-secret primitives', () => {
  it('initiator + responder produce identical secrets (with OPK)', () => {
    const aliceIk = rawKp();
    const aliceEk = rawKp();
    const bobIk = rawKp();
    const bobSpk = rawKp();
    const bobOpk = rawKp();

    const aliceSecret = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      bobOpk.pub,
    );

    const bobSecret = computeResponderSharedSecret(
      bobIk.priv,
      bobSpk.priv,
      bobOpk.priv,
      aliceIk.pub,
      aliceEk.pub,
    );

    expect(aliceSecret.equals(bobSecret)).toBe(true);
    expect(aliceSecret.length).toBe(X3DH_SECRET_SIZE);
  });

  it('initiator + responder produce identical secrets (without OPK)', () => {
    const aliceIk = rawKp();
    const aliceEk = rawKp();
    const bobIk = rawKp();
    const bobSpk = rawKp();

    const aliceSecret = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      null,
    );

    const bobSecret = computeResponderSharedSecret(
      bobIk.priv,
      bobSpk.priv,
      null,
      aliceIk.pub,
      aliceEk.pub,
    );

    expect(aliceSecret.equals(bobSecret)).toBe(true);
  });

  it('different ephemeral → different secret', () => {
    const aliceIk = rawKp();
    const bobIk = rawKp();
    const bobSpk = rawKp();
    const bobOpk = rawKp();

    const eph1 = rawKp();
    const eph2 = rawKp();

    const s1 = computeInitiatorSharedSecret(
      aliceIk.priv,
      eph1.priv,
      bobIk.pub,
      bobSpk.pub,
      bobOpk.pub,
    );
    const s2 = computeInitiatorSharedSecret(
      aliceIk.priv,
      eph2.priv,
      bobIk.pub,
      bobSpk.pub,
      bobOpk.pub,
    );

    expect(s1.equals(s2)).toBe(false);
  });

  it('different OPK → different secret (proves DH4 mixes in)', () => {
    const aliceIk = rawKp();
    const aliceEk = rawKp();
    const bobIk = rawKp();
    const bobSpk = rawKp();

    const opk1 = rawKp();
    const opk2 = rawKp();

    const s1 = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      opk1.pub,
    );
    const s2 = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      opk2.pub,
    );

    expect(s1.equals(s2)).toBe(false);
  });

  it('with-OPK and without-OPK produce different secrets', () => {
    const aliceIk = rawKp();
    const aliceEk = rawKp();
    const bobIk = rawKp();
    const bobSpk = rawKp();
    const bobOpk = rawKp();

    const withOpk = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      bobOpk.pub,
    );

    const withoutOpk = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      null,
    );

    expect(withOpk.equals(withoutOpk)).toBe(false);
  });

  it('returns a SharedSecret of exactly 32 bytes', () => {
    const aliceIk = rawKp();
    const aliceEk = rawKp();
    const bobIk = rawKp();
    const bobSpk = rawKp();

    const s = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      null,
    );

    expect(s.length).toBe(32);
  });

  it('deterministic: same inputs → same output', () => {
    const aliceIk = rawKp();
    const aliceEk = rawKp();
    const bobIk = rawKp();
    const bobSpk = rawKp();
    const bobOpk = rawKp();

    const s1 = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      bobOpk.pub,
    );
    const s2 = computeInitiatorSharedSecret(
      aliceIk.priv,
      aliceEk.priv,
      bobIk.pub,
      bobSpk.pub,
      bobOpk.pub,
    );

    expect(s1.equals(s2)).toBe(true);
  });
});
