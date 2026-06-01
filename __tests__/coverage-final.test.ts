/**
 * Final Coverage Sweep
 *
 * Targets the last remaining uncovered lines to reach 100% coverage:
 *   - identity-key.ts 273-276 (defensive try/catch — excluded via c8 ignore)
 *   - one-time-prekey.ts 206 (deserialize 'null' context branch)
 *   - one-time-prekey.ts 345 (PublicOneTimePreKey.equals null/undefined)
 *   - signed-prekey.ts 186-187 (fromKeys: bad id)
 *   - signed-prekey.ts 189-193 (fromKeys: bad timestamp)
 *   - signed-prekey.ts 198-199 (fromKeys: wrong sig size)
 *   - signed-prekey.ts 223-227 (fromVerifiedPayload wrapper)
 */

import { describe, it, expect } from 'vitest';

import { IdentityKeyPair } from '../src/identity';
import {
  OneTimePreKey,
  SignedPreKey,
  PublicSignedPreKey,
} from '../src/prekeys';
import {
  SerializationError,
  ValidationError,
  PreKeyError,
} from '../src/errors';
import { SIGNATURE_SIZE, MAX_PREKEY_ID } from '../src/constants';

// ═══════════════════════════════════════════════════════════════════════════
// OneTimePreKey.deserialize — 'null' context branch
// ═══════════════════════════════════════════════════════════════════════════

describe('Final coverage: OneTimePreKey.deserialize null/non-object branches', () => {
  it('rejects null explicitly (covers data === null ? "null" : typeof data branch)', () => {
    let captured: SerializationError | undefined;
    try {
      OneTimePreKey.deserialize(null);
    } catch (e) {
      captured = e as SerializationError;
    }
    expect(captured).toBeInstanceOf(SerializationError);
    expect(captured!.context).toMatchObject({ received: 'null' });
  });

  it('rejects undefined (covers received: "undefined")', () => {
    let captured: SerializationError | undefined;
    try {
      OneTimePreKey.deserialize(undefined);
    } catch (e) {
      captured = e as SerializationError;
    }
    expect(captured).toBeInstanceOf(SerializationError);
    expect(captured!.context).toMatchObject({ received: 'undefined' });
  });

  it('rejects number (covers received: "number")', () => {
    let captured: SerializationError | undefined;
    try {
      OneTimePreKey.deserialize(42);
    } catch (e) {
      captured = e as SerializationError;
    }
    expect(captured).toBeInstanceOf(SerializationError);
    expect(captured!.context).toMatchObject({ received: 'number' });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// PublicOneTimePreKey.equals — null/undefined branch (line 345)
// ═══════════════════════════════════════════════════════════════════════════

describe('Final coverage: PublicOneTimePreKey.equals null/undefined', () => {
  it('returns false for null', () => {
    const pub = OneTimePreKey.generate(1).toPublic();
    expect(pub.equals(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    const pub = OneTimePreKey.generate(1).toPublic();
    expect(pub.equals(undefined)).toBe(false);
  });

  it('returns true for matching public key', () => {
    const otpk = OneTimePreKey.generate(1);
    expect(otpk.toPublic().equals(otpk)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SignedPreKey.fromKeys — all validation branches
// ═══════════════════════════════════════════════════════════════════════════

describe('Final coverage: SignedPreKey.fromKeys validation paths', () => {
  it('rejects invalid id (lines 186-187)', () => {
    const pub = Buffer.alloc(32);
    const priv = Buffer.alloc(32);
    const sig = Buffer.alloc(SIGNATURE_SIZE);

    expect(() => SignedPreKey.fromKeys(0, pub, priv, sig, Date.now())).toThrow(
      PreKeyError,
    );

    expect(() => SignedPreKey.fromKeys(-1, pub, priv, sig, Date.now())).toThrow(
      PreKeyError,
    );

    expect(() =>
      SignedPreKey.fromKeys(MAX_PREKEY_ID + 1, pub, priv, sig, Date.now()),
    ).toThrow(PreKeyError);
  });

  it('rejects non-integer timestamp (lines 189-193)', () => {
    const pub = Buffer.alloc(32);
    const priv = Buffer.alloc(32);
    const sig = Buffer.alloc(SIGNATURE_SIZE);

    expect(() => SignedPreKey.fromKeys(1, pub, priv, sig, 1.5)).toThrow(
      ValidationError,
    );
  });

  it('rejects negative timestamp (lines 189-193)', () => {
    const pub = Buffer.alloc(32);
    const priv = Buffer.alloc(32);
    const sig = Buffer.alloc(SIGNATURE_SIZE);

    expect(() => SignedPreKey.fromKeys(1, pub, priv, sig, -1)).toThrow(
      ValidationError,
    );
  });

  it('rejects wrong signature size — too small (lines 198-199)', () => {
    const pub = Buffer.alloc(32);
    const priv = Buffer.alloc(32);
    const badSig = Buffer.alloc(10);

    expect(() =>
      SignedPreKey.fromKeys(1, pub, priv, badSig, Date.now()),
    ).toThrow(ValidationError);
  });

  it('rejects wrong signature size — too large (lines 198-199)', () => {
    const pub = Buffer.alloc(32);
    const priv = Buffer.alloc(32);
    const badSig = Buffer.alloc(128);

    expect(() =>
      SignedPreKey.fromKeys(1, pub, priv, badSig, Date.now()),
    ).toThrow(ValidationError);
  });

  it('accepts Uint8Array for keys/signature (forces conversion branch)', () => {
    const pub = new Uint8Array(32);
    const priv = new Uint8Array(32);
    const sig = new Uint8Array(SIGNATURE_SIZE);
    const spk = SignedPreKey.fromKeys(1, pub, priv, sig, Date.now());
    expect(spk.id).toBe(1);
    expect(spk.publicKey.length).toBe(32);
    expect(spk.signature.length).toBe(SIGNATURE_SIZE);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SignedPreKey.fromVerifiedPayload — wrapper around PublicSignedPreKey.fromPayload
// ═══════════════════════════════════════════════════════════════════════════

describe('Final coverage: SignedPreKey.fromVerifiedPayload wrapper', () => {
  it('delegates to PublicSignedPreKey.fromPayload and verifies (lines 222-227)', () => {
    const alice = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(alice, 7);
    const payload = spk.toPayload();

    const verified = SignedPreKey.fromVerifiedPayload(alice.toPublic(), payload);

    expect(verified).toBeInstanceOf(PublicSignedPreKey);
    expect(verified.id).toBe(7);
    expect(verified.publicKey.equals(spk.publicKey)).toBe(true);
    expect(verified.signature.equals(spk.signature)).toBe(true);
  });

  it('throws when called with a forged payload', () => {
    const alice = IdentityKeyPair.generate();
    const mallory = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(mallory, 1); // signed by Mallory
    const payload = spk.toPayload();

    // Verifying against Alice's identity should fail
    expect(() =>
      SignedPreKey.fromVerifiedPayload(alice.toPublic(), payload),
    ).toThrow();
  });
});
