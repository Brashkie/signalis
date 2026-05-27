/**
 * Coverage Boost Tests for v0.3.0
 *
 * Targets edge cases and error paths that the main test suites didn't hit,
 * bringing overall coverage from 88% → 95%+.
 *
 * Specifically:
 *   - All `*: not valid hex` paths in deserialize/fromPayload
 *   - All key-size-mismatch paths in deserialize/fromPayload
 *   - `Symbol.for('nodejs.util.inspect.custom')` for all classes
 *   - `fromBase64` wrong-size for `PublicIdentityKey`
 *   - `PublicSignedPreKey` constructor edge cases
 *   - `PreKeyBundle.fromPayload` malformed-field error paths
 *   - `PreKeyBundle.fromPayload` oneTimePreKey field-validation paths
 */

import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';

import { IdentityKeyPair, PublicIdentityKey } from '../src/identity';
import {
  OneTimePreKey,
  PublicOneTimePreKey,
  SignedPreKey,
  PublicSignedPreKey,
  PreKeyBundle,
} from '../src/prekeys';
import {
  SerializationError,
  ValidationError,
  SignatureError,
  PreKeyError,
} from '../src/errors';
import {
  SIGNATURE_SIZE,
  MAX_PREKEY_ID,
} from '../src/constants';

// ═══════════════════════════════════════════════════════════════════════════
// IdentityKeyPair / PublicIdentityKey — coverage gaps
// ═══════════════════════════════════════════════════════════════════════════

describe('Coverage: IdentityKeyPair edge cases', () => {
  it('deserialize: rejects publicKey with non-hex chars', () => {
    expect(() =>
      IdentityKeyPair.deserialize({
        publicKey: 'Z'.repeat(64),
        privateKey: 'a'.repeat(64),
      }),
    ).toThrow(SerializationError);
  });

  it('deserialize: rejects privateKey with non-hex chars', () => {
    expect(() =>
      IdentityKeyPair.deserialize({
        publicKey: 'a'.repeat(64),
        privateKey: 'Z'.repeat(64),
      }),
    ).toThrow(SerializationError);
  });

  it('deserialize: rejects wrong public key size', () => {
    expect(() =>
      IdentityKeyPair.deserialize({
        publicKey: 'aa',
        privateKey: 'a'.repeat(64),
      }),
    ).toThrow(SerializationError);
  });

  it('deserialize: rejects wrong private key size', () => {
    expect(() =>
      IdentityKeyPair.deserialize({
        publicKey: 'a'.repeat(64),
        privateKey: 'aa',
      }),
    ).toThrow(SerializationError);
  });

  it('deserialize: rejects missing publicKey field type', () => {
    expect(() =>
      IdentityKeyPair.deserialize({
        publicKey: 123 as unknown as string,
        privateKey: 'a'.repeat(64),
      }),
    ).toThrow(SerializationError);
  });

  it('deserialize: rejects missing privateKey field type', () => {
    expect(() =>
      IdentityKeyPair.deserialize({
        publicKey: 'a'.repeat(64),
        privateKey: 123 as unknown as string,
      }),
    ).toThrow(SerializationError);
  });

  it('deserialize: rejects null input', () => {
    expect(() => IdentityKeyPair.deserialize(null)).toThrow(SerializationError);
  });

  it('deserialize: rejects non-object input', () => {
    expect(() => IdentityKeyPair.deserialize('string')).toThrow(SerializationError);
  });

  it('IdentityKeyPair inspect via util.inspect() returns safe representation', () => {
    const id = IdentityKeyPair.generate();
    const inspected = inspect(id);
    expect(inspected).toMatch(/IdentityKeyPair\(public=/);
    expect(inspected).not.toContain(id.privateKey.toString('hex'));
  });
});

describe('Coverage: PublicIdentityKey edge cases', () => {
  it('fromBase64: rejects non-string input', () => {
    expect(() =>
      PublicIdentityKey.fromBase64(123 as unknown as string),
    ).toThrow(ValidationError);
  });

  it('fromBase64: rejects wrong-size base64 string', () => {
    // 4 bytes of base64 = 3 bytes after decode — not 32
    expect(() => PublicIdentityKey.fromBase64('AAAA')).toThrow(ValidationError);
  });

  it('fromBase64: accepts a valid base64 32-byte input', () => {
    const id = IdentityKeyPair.generate();
    const b64 = id.toPublic().toBase64();
    const restored = PublicIdentityKey.fromBase64(b64);
    expect(restored.equals(id.toPublic())).toBe(true);
  });

  it('PublicIdentityKey inspect via util.inspect() returns safe representation', () => {
    const pub = IdentityKeyPair.generate().toPublic();
    const inspected = inspect(pub);
    expect(inspected).toMatch(/PublicIdentityKey\(/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// OneTimePreKey — coverage gaps
// ═══════════════════════════════════════════════════════════════════════════

describe('Coverage: OneTimePreKey edge cases', () => {
  it('deserialize: rejects privateKey with non-hex chars', () => {
    expect(() =>
      OneTimePreKey.deserialize({
        id: 1,
        publicKey: 'a'.repeat(64),
        privateKey: 'Z'.repeat(64),
      }),
    ).toThrow(SerializationError);
  });

  it('deserialize: rejects wrong private key size', () => {
    expect(() =>
      OneTimePreKey.deserialize({
        id: 1,
        publicKey: 'a'.repeat(64),
        privateKey: 'aa',
      }),
    ).toThrow(SerializationError);
  });

  it('OneTimePreKey inspect via util.inspect() is safe', () => {
    const otpk = OneTimePreKey.generate(1);
    const inspected = inspect(otpk);
    expect(inspected).toMatch(/OneTimePreKey\(id=1/);
    expect(inspected).not.toContain(otpk.privateKey.toString('hex'));
  });

  it('PublicOneTimePreKey inspect via util.inspect() is safe', () => {
    const pub = OneTimePreKey.generate(1).toPublic();
    const inspected = inspect(pub);
    expect(inspected).toMatch(/PublicOneTimePreKey\(id=1/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SignedPreKey — coverage gaps (biggest improvement target)
// ═══════════════════════════════════════════════════════════════════════════

describe('Coverage: SignedPreKey deserialize edge cases', () => {
  it('rejects null input', () => {
    expect(() => SignedPreKey.deserialize(null)).toThrow(SerializationError);
  });

  it('rejects non-object input', () => {
    expect(() => SignedPreKey.deserialize('string')).toThrow(SerializationError);
  });

  it('rejects non-number id', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: '1' as unknown as number,
        publicKey: 'a'.repeat(64),
        privateKey: 'a'.repeat(64),
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('rejects non-string publicKey', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: 1,
        publicKey: 123 as unknown as string,
        privateKey: 'a'.repeat(64),
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('rejects non-string privateKey', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: 1,
        publicKey: 'a'.repeat(64),
        privateKey: 123 as unknown as string,
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('rejects non-string signature', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: 1,
        publicKey: 'a'.repeat(64),
        privateKey: 'a'.repeat(64),
        signature: 123 as unknown as string,
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('rejects non-number timestamp', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: 1,
        publicKey: 'a'.repeat(64),
        privateKey: 'a'.repeat(64),
        signature: 'a'.repeat(128),
        timestamp: '0' as unknown as number,
      }),
    ).toThrow(SerializationError);
  });

  it('rejects publicKey with non-hex chars', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: 1,
        publicKey: 'Z'.repeat(64),
        privateKey: 'a'.repeat(64),
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('rejects privateKey with non-hex chars', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: 1,
        publicKey: 'a'.repeat(64),
        privateKey: 'Z'.repeat(64),
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('rejects wrong publicKey size', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: 1,
        publicKey: 'aa',
        privateKey: 'a'.repeat(64),
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('rejects wrong privateKey size', () => {
    expect(() =>
      SignedPreKey.deserialize({
        id: 1,
        publicKey: 'a'.repeat(64),
        privateKey: 'aa',
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('SignedPreKey inspect via util.inspect() is safe', () => {
    const alice = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(alice, 1);
    const inspected = inspect(spk);
    expect(inspected).toMatch(/SignedPreKey\(id=1/);
    expect(inspected).not.toContain(spk.privateKey.toString('hex'));
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// PublicSignedPreKey — coverage gaps
// ═══════════════════════════════════════════════════════════════════════════

describe('Coverage: PublicSignedPreKey edge cases', () => {
  it('constructor accepts Uint8Array for publicKey/signature', () => {
    const pub = new Uint8Array(32);
    const sig = new Uint8Array(SIGNATURE_SIZE);
    const psp = new PublicSignedPreKey(1, pub, sig, Date.now());
    expect(psp.id).toBe(1);
  });

  it('fromPayload rejects non-number id', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      PublicSignedPreKey.fromPayload(alice.toPublic(), {
        id: '1' as unknown as number,
        publicKey: 'a'.repeat(64),
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('fromPayload rejects non-string publicKey', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      PublicSignedPreKey.fromPayload(alice.toPublic(), {
        id: 1,
        publicKey: 123 as unknown as string,
        signature: 'a'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('fromPayload rejects non-string signature', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      PublicSignedPreKey.fromPayload(alice.toPublic(), {
        id: 1,
        publicKey: 'a'.repeat(64),
        signature: 123 as unknown as string,
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('fromPayload rejects non-number timestamp', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      PublicSignedPreKey.fromPayload(alice.toPublic(), {
        id: 1,
        publicKey: 'a'.repeat(64),
        signature: 'a'.repeat(128),
        timestamp: '0' as unknown as number,
      }),
    ).toThrow(SerializationError);
  });

  it('fromPayload rejects signature with non-hex chars', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      PublicSignedPreKey.fromPayload(alice.toPublic(), {
        id: 1,
        publicKey: 'a'.repeat(64),
        signature: 'Z'.repeat(128),
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('fromPayload rejects wrong signature size', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      PublicSignedPreKey.fromPayload(alice.toPublic(), {
        id: 1,
        publicKey: 'a'.repeat(64),
        signature: 'aa',
        timestamp: 0,
      }),
    ).toThrow(SerializationError);
  });

  it('PublicSignedPreKey inspect via util.inspect() is safe', () => {
    const alice = IdentityKeyPair.generate();
    const psp = SignedPreKey.generate(alice, 1).toPublic();
    const inspected = inspect(psp);
    expect(inspected).toMatch(/PublicSignedPreKey\(id=1/);
  });

  it('PublicSignedPreKey toString includes id and fingerprint', () => {
    const alice = IdentityKeyPair.generate();
    const psp = SignedPreKey.generate(alice, 42).toPublic();
    expect(psp.toString()).toMatch(/id=42/);
    expect(psp.toString()).toMatch(/public=/);
  });

  it('PublicSignedPreKey toJSON output excludes secrets', () => {
    const alice = IdentityKeyPair.generate();
    const psp = SignedPreKey.generate(alice, 1).toPublic();
    const json = psp.toJSON();
    expect(json.type).toBe('PublicSignedPreKey');
    expect(json).not.toHaveProperty('privateKey');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// PreKeyBundle — coverage gaps
// ═══════════════════════════════════════════════════════════════════════════

describe('Coverage: PreKeyBundle edge cases', () => {
  function aliceMaterial() {
    const alice = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(alice, 1);
    const otpk = OneTimePreKey.generate(100);
    return { alice, spk, otpk };
  }

  it('fromPayload: rejects non-number deviceId', () => {
    const { alice, spk } = aliceMaterial();
    const bundle = PreKeyBundle.build({
      registrationId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    });
    const payload = bundle.toPayload();
    const bad = { ...payload, deviceId: '1' as unknown as number };
    expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
  });

  it('fromPayload: rejects non-string identityKey', () => {
    const { alice, spk } = aliceMaterial();
    const payload = PreKeyBundle.build({
      registrationId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    }).toPayload();
    const bad = { ...payload, identityKey: 123 as unknown as string };
    expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
  });

  it('fromPayload: rejects null signedPreKey', () => {
    const { alice, spk } = aliceMaterial();
    const payload = PreKeyBundle.build({
      registrationId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    }).toPayload();
    const bad = { ...payload, signedPreKey: null as never };
    expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
  });

  it('fromPayload: rejects oneTimePreKey.id non-number', () => {
    const { alice, spk } = aliceMaterial();
    const payload = PreKeyBundle.build({
      registrationId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    }).toPayload();
    const bad = {
      ...payload,
      oneTimePreKey: { id: '1' as unknown as number, publicKey: 'a'.repeat(64) },
    };
    expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
  });

  it('fromPayload: rejects oneTimePreKey.publicKey non-string', () => {
    const { alice, spk } = aliceMaterial();
    const payload = PreKeyBundle.build({
      registrationId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    }).toPayload();
    const bad = {
      ...payload,
      oneTimePreKey: { id: 1, publicKey: 123 as unknown as string },
    };
    expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
  });

  it('fromPayload: invalid identityKey hex bubbles up as SerializationError', () => {
    const { alice, spk } = aliceMaterial();
    const payload = PreKeyBundle.build({
      registrationId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    }).toPayload();
    // identityKey size wrong (decodes to non-32 bytes)
    const bad = { ...payload, identityKey: 'aa' };
    expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
  });

  it('fromPayload: signedPreKey size mismatch surfaces as SerializationError', () => {
    const { alice, spk } = aliceMaterial();
    const payload = PreKeyBundle.build({
      registrationId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    }).toPayload();
    // Bad SPK publicKey size — but goes through PublicSignedPreKey.fromPayload
    // which throws SerializationError on size mismatch
    const bad = {
      ...payload,
      signedPreKey: { ...payload.signedPreKey, publicKey: 'aa' },
    };
    expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
  });

  it('fromPayload: SignatureError propagates verbatim (not wrapped)', () => {
    const { alice, spk } = aliceMaterial();
    const mallory = IdentityKeyPair.generate();
    const malloryHex = mallory.toPublic().toHex();

    // Build a bundle with Mallory's identityKey + Alice's spk (signature mismatch)
    const payload = PreKeyBundle.build({
      registrationId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    }).toPayload();
    const forged = { ...payload, identityKey: malloryHex };

    // The error MUST be SignatureError (not SerializationError)
    expect(() => PreKeyBundle.fromPayload(forged)).toThrow(SignatureError);
  });

  it('PreKeyBundle inspect via util.inspect() returns safe representation', () => {
    const { alice, spk } = aliceMaterial();
    const bundle = PreKeyBundle.build({
      registrationId: 12345,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
    });
    const inspected = inspect(bundle);
    expect(inspected).toMatch(/PreKeyBundle\(addr=12345\.1/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Misc: hit remaining error helpers
// ═══════════════════════════════════════════════════════════════════════════

describe('Coverage: PreKeyError.invalidId helper', () => {
  it('produces a PreKeyError with the right shape', () => {
    const err = PreKeyError.invalidId('not-a-number', 1, MAX_PREKEY_ID);
    expect(err).toBeInstanceOf(PreKeyError);
    expect(err.message).toMatch(/Invalid prekey id/);
    expect(err.context).toMatchObject({ min: 1, max: MAX_PREKEY_ID });
  });
});

describe('Coverage: PublicOneTimePreKey constructor edge case', () => {
  it('accepts Uint8Array', () => {
    const pub = new Uint8Array(32);
    const otpk = new PublicOneTimePreKey(1, pub);
    expect(otpk.id).toBe(1);
  });
});
