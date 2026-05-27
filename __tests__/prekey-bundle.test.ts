import { describe, it, expect } from 'vitest';
import {
  PreKeyBundle,
  isPreKeyBundle,
  OneTimePreKey,
  SignedPreKey,
  PublicSignedPreKey,
  PublicOneTimePreKey,
} from '../src/prekeys';
import { IdentityKeyPair, PublicIdentityKey } from '../src/identity';
import {
  ValidationError,
  SerializationError,
  SignatureError,
} from '../src/errors';
import { DEFAULT_DEVICE_ID, MAX_DEVICE_ID } from '../src/constants';

describe('PreKeyBundle', () => {
  // Helper: build a complete valid bundle for Alice
  function aliceBundle(opts: { withOneTime?: boolean } = {}): {
    alice: IdentityKeyPair;
    aliceSpk: SignedPreKey;
    aliceOtpk: OneTimePreKey;
    bundle: PreKeyBundle;
  } {
    const alice = IdentityKeyPair.generate();
    const aliceSpk = SignedPreKey.generate(alice, 1);
    const aliceOtpk = OneTimePreKey.generate(100);
    const bundle = PreKeyBundle.build({
      registrationId: 12345,
      deviceId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: aliceSpk.toPublic(),
      oneTimePreKey: opts.withOneTime !== false ? aliceOtpk.toPublic() : null,
    });
    return { alice, aliceSpk, aliceOtpk, bundle };
  }

  // ═══════════════════════════════════════════════════════════════════
  // build()
  // ═══════════════════════════════════════════════════════════════════

  describe('build()', () => {
    it('creates a complete bundle with OTPK', () => {
      const { bundle } = aliceBundle();
      expect(bundle.registrationId).toBe(12345);
      expect(bundle.deviceId).toBe(1);
      expect(bundle.hasOneTimePreKey()).toBe(true);
    });

    it('creates a bundle without OTPK', () => {
      const { bundle } = aliceBundle({ withOneTime: false });
      expect(bundle.hasOneTimePreKey()).toBe(false);
      expect(bundle.oneTimePreKey).toBeNull();
    });

    it('uses default deviceId when not specified', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const bundle = PreKeyBundle.build({
        registrationId: 1,
        identityKey: alice.toPublic(),
        signedPreKey: spk.toPublic(),
      });
      expect(bundle.deviceId).toBe(DEFAULT_DEVICE_ID);
    });

    it('rejects invalid registrationId', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(() =>
        PreKeyBundle.build({
          registrationId: 0,
          identityKey: alice.toPublic(),
          signedPreKey: spk.toPublic(),
        }),
      ).toThrow(ValidationError);

      expect(() =>
        PreKeyBundle.build({
          registrationId: 1_000_000,
          identityKey: alice.toPublic(),
          signedPreKey: spk.toPublic(),
        }),
      ).toThrow(ValidationError);
    });

    it('rejects invalid deviceId', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(() =>
        PreKeyBundle.build({
          registrationId: 1,
          deviceId: 0,
          identityKey: alice.toPublic(),
          signedPreKey: spk.toPublic(),
        }),
      ).toThrow(ValidationError);

      expect(() =>
        PreKeyBundle.build({
          registrationId: 1,
          deviceId: MAX_DEVICE_ID + 1,
          identityKey: alice.toPublic(),
          signedPreKey: spk.toPublic(),
        }),
      ).toThrow(ValidationError);
    });

    it('rejects non-PublicIdentityKey for identity', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(() =>
        PreKeyBundle.build({
          registrationId: 1,
          identityKey: {} as PublicIdentityKey,
          signedPreKey: spk.toPublic(),
        }),
      ).toThrow(ValidationError);
    });

    it('rejects non-PublicSignedPreKey for signedPreKey', () => {
      const alice = IdentityKeyPair.generate();
      expect(() =>
        PreKeyBundle.build({
          registrationId: 1,
          identityKey: alice.toPublic(),
          signedPreKey: {} as PublicSignedPreKey,
        }),
      ).toThrow(ValidationError);
    });

    it('rejects non-PublicOneTimePreKey for oneTimePreKey', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(() =>
        PreKeyBundle.build({
          registrationId: 1,
          identityKey: alice.toPublic(),
          signedPreKey: spk.toPublic(),
          oneTimePreKey: {} as PublicOneTimePreKey,
        }),
      ).toThrow(ValidationError);
    });

    it('bundle is frozen', () => {
      const { bundle } = aliceBundle();
      expect(Object.isFrozen(bundle)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // fromPayload() — SECURITY CRITICAL
  // ═══════════════════════════════════════════════════════════════════

  describe('fromPayload() — security critical', () => {
    it('parses and verifies a valid bundle', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();

      const reconstructed = PreKeyBundle.fromPayload(payload);
      expect(reconstructed.registrationId).toBe(bundle.registrationId);
      expect(reconstructed.deviceId).toBe(bundle.deviceId);
      expect(reconstructed.signedPreKey.id).toBe(bundle.signedPreKey.id);
      expect(reconstructed.hasOneTimePreKey()).toBe(true);
    });

    it('parses bundle without OTPK', () => {
      const { bundle } = aliceBundle({ withOneTime: false });
      const payload = bundle.toPayload();

      const reconstructed = PreKeyBundle.fromPayload(payload);
      expect(reconstructed.hasOneTimePreKey()).toBe(false);
    });

    it('REJECTS bundle with forged signed prekey (Mallory)', () => {
      const alice = IdentityKeyPair.generate();
      const mallory = IdentityKeyPair.generate();
      // Mallory signs with HIS identity, but the bundle claims Alice's identity
      const fakeSpk = SignedPreKey.generate(mallory, 1);

      const forgedPayload = {
        registrationId: 1,
        deviceId: 1,
        identityKey: alice.toPublic().toHex(),
        signedPreKey: fakeSpk.toPayload(),
      };

      expect(() => PreKeyBundle.fromPayload(forgedPayload)).toThrow(
        SignatureError,
      );
    });

    it('REJECTS bundle with tampered signed prekey publicKey', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();

      // Tamper with the SPK public key
      const tamperedPub = Buffer.from(payload.signedPreKey.publicKey, 'hex');
      tamperedPub[0] ^= 0xff;
      const tampered = {
        ...payload,
        signedPreKey: {
          ...payload.signedPreKey,
          publicKey: tamperedPub.toString('hex'),
        },
      };

      expect(() => PreKeyBundle.fromPayload(tampered)).toThrow(SignatureError);
    });

    it('rejects null payload', () => {
      expect(() => PreKeyBundle.fromPayload(null)).toThrow(SerializationError);
    });

    it('rejects non-object payload', () => {
      expect(() => PreKeyBundle.fromPayload('not an object')).toThrow(
        SerializationError,
      );
    });

    it('rejects missing registrationId', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();
      const bad = { ...payload, registrationId: undefined } as never;
      expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
    });

    it('rejects out-of-range registrationId', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();
      const bad = { ...payload, registrationId: 99999999 };
      expect(() => PreKeyBundle.fromPayload(bad)).toThrow(ValidationError);
    });

    it('rejects out-of-range deviceId', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();
      const bad = { ...payload, deviceId: 0 };
      expect(() => PreKeyBundle.fromPayload(bad)).toThrow(ValidationError);
    });

    it('rejects bad identityKey hex', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();
      const bad = { ...payload, identityKey: 'ZZZ' };
      expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
    });

    it('rejects malformed signedPreKey', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();
      const bad = { ...payload, signedPreKey: 'not an object' as never };
      expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
    });

    it('rejects malformed oneTimePreKey', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();
      const bad = {
        ...payload,
        oneTimePreKey: 'not an object' as never,
      };
      expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
    });

    it('rejects oneTimePreKey with bad hex', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();
      const bad = {
        ...payload,
        oneTimePreKey: { id: 1, publicKey: 'ZZZ' },
      };
      expect(() => PreKeyBundle.fromPayload(bad)).toThrow(SerializationError);
    });

    it('accepts oneTimePreKey: null/undefined as missing', () => {
      const { bundle } = aliceBundle({ withOneTime: false });
      const payload = bundle.toPayload();
      const noOtp = PreKeyBundle.fromPayload(payload);
      expect(noOtp.hasOneTimePreKey()).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // toPayload round-trip
  // ═══════════════════════════════════════════════════════════════════

  describe('toPayload() round-trip', () => {
    it('roundtrips a bundle with OTPK', () => {
      const { bundle } = aliceBundle();
      const payload = bundle.toPayload();
      const back = PreKeyBundle.fromPayload(payload);

      expect(back.registrationId).toBe(bundle.registrationId);
      expect(back.deviceId).toBe(bundle.deviceId);
      expect(back.identityKey.equals(bundle.identityKey)).toBe(true);
      expect(back.signedPreKey.id).toBe(bundle.signedPreKey.id);
      expect(back.oneTimePreKey?.id).toBe(bundle.oneTimePreKey?.id);
    });

    it('roundtrips a bundle without OTPK', () => {
      const { bundle } = aliceBundle({ withOneTime: false });
      const payload = bundle.toPayload();
      const back = PreKeyBundle.fromPayload(payload);

      expect(back.hasOneTimePreKey()).toBe(false);
      expect(payload.oneTimePreKey).toBeUndefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // verify()
  // ═══════════════════════════════════════════════════════════════════

  describe('verify()', () => {
    it('returns true for a valid bundle', () => {
      const { bundle } = aliceBundle();
      expect(bundle.verify()).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // address()
  // ═══════════════════════════════════════════════════════════════════

  describe('address()', () => {
    it('formats as registrationId.deviceId', () => {
      const { bundle } = aliceBundle();
      expect(bundle.address()).toBe('12345.1');
    });

    it('reflects custom deviceId', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const bundle = PreKeyBundle.build({
        registrationId: 100,
        deviceId: 5,
        identityKey: alice.toPublic(),
        signedPreKey: spk.toPublic(),
      });
      expect(bundle.address()).toBe('100.5');
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Safe output
  // ═══════════════════════════════════════════════════════════════════

  describe('safe output', () => {
    it('toString includes addr and spk id', () => {
      const { bundle } = aliceBundle();
      const s = bundle.toString();
      expect(s).toContain('addr=12345.1');
      expect(s).toContain('spk=1');
    });

    it('toJSON includes summary fields', () => {
      const { bundle } = aliceBundle();
      const json = bundle.toJSON();
      expect(json.type).toBe('PreKeyBundle');
      expect(json.registrationId).toBe(12345);
      expect(json.signedPreKeyId).toBe(1);
      expect(json.oneTimePreKeyId).toBe(100);
    });

    it('toJSON without OTPK has null oneTimePreKeyId', () => {
      const { bundle } = aliceBundle({ withOneTime: false });
      expect(bundle.toJSON().oneTimePreKeyId).toBeNull();
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Type guard
  // ═══════════════════════════════════════════════════════════════════

  describe('isPreKeyBundle', () => {
    it('returns true for PreKeyBundle', () => {
      const { bundle } = aliceBundle();
      expect(isPreKeyBundle(bundle)).toBe(true);
    });

    it('returns false for plain object', () => {
      expect(isPreKeyBundle({})).toBe(false);
      expect(isPreKeyBundle(null)).toBe(false);
      expect(isPreKeyBundle(undefined)).toBe(false);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// E2E: Full server-mediated handshake setup
// ═══════════════════════════════════════════════════════════════════════════

describe('E2E: Server-mediated PreKey Bundle handshake setup', () => {
  it('Alice publishes → Bob fetches → Bob verifies bundle', () => {
    // ─── Alice's side (registration) ─────────────────────────────────
    const alice = IdentityKeyPair.generate();
    const aliceSpk = SignedPreKey.generate(alice, 1);
    const aliceOtpks = OneTimePreKey.generateBatch(1, 100);

    // Server stores Alice's stuff. When Bob requests, the server
    // assembles a bundle picking the first available one-time prekey.
    const pickedOtpk = aliceOtpks[0]!;
    const serverPayload = PreKeyBundle.build({
      registrationId: 12345,
      deviceId: 1,
      identityKey: alice.toPublic(),
      signedPreKey: aliceSpk.toPublic(),
      oneTimePreKey: pickedOtpk.toPublic(),
    }).toPayload();

    // ─── Bob's side (initiating session with Alice) ──────────────────
    // Bob receives the JSON payload over the network and reconstructs
    const bundle = PreKeyBundle.fromPayload(serverPayload);

    // Verification happened automatically inside fromPayload
    expect(bundle.identityKey.equals(alice.toPublic())).toBe(true);
    expect(bundle.signedPreKey.publicKey.equals(aliceSpk.publicKey)).toBe(true);
    expect(bundle.oneTimePreKey?.id).toBe(1);

    // Bundle is ready to be consumed by X3DH.initiate(bundle) — Sprint 2 Part 2
  });

  it('Bundle without OTPK still works (lower forward secrecy)', () => {
    const alice = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(alice, 1);

    const payload = PreKeyBundle.build({
      registrationId: 12345,
      identityKey: alice.toPublic(),
      signedPreKey: spk.toPublic(),
      oneTimePreKey: null,
    }).toPayload();

    const bundle = PreKeyBundle.fromPayload(payload);
    expect(bundle.hasOneTimePreKey()).toBe(false);
  });
});
