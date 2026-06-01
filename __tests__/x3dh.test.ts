import { describe, it, expect } from 'vitest';

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
  InitialMessage,
  isInitialMessage,
  ProtocolError,
  ValidationError,
  PreKeyError,
  SignatureError,
  SerializationError,
  X3DH_SECRET_SIZE,
} from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// Helper: set up Alice and Bob ready for a handshake
// ═══════════════════════════════════════════════════════════════════════════

function setup(opts: { withOneTimeKey?: boolean } = {}) {
  const alice = IdentityKeyPair.generate();
  const bob = IdentityKeyPair.generate();

  const bobSpk = SignedPreKey.generate(bob, 1);
  const bobOpk = OneTimePreKey.generate(100);

  const bobBundle = PreKeyBundle.build({
    registrationId: 6789,
    deviceId: 1,
    identityKey: bob.toPublic(),
    signedPreKey: bobSpk.toPublic(),
    oneTimePreKey: opts.withOneTimeKey !== false ? bobOpk.toPublic() : null,
  });

  return { alice, bob, bobSpk, bobOpk, bobBundle };
}

// ═══════════════════════════════════════════════════════════════════════════
// Core E2E: Alice and Bob derive the same secret
// ═══════════════════════════════════════════════════════════════════════════

describe('X3DH End-to-End: Alice ↔ Bob derive same shared secret', () => {
  it('with one-time prekey: secrets match', () => {
    const { alice, bob, bobSpk, bobOpk, bobBundle } = setup();

    // ─── Alice's side ─────────────────────────────────────────────────
    const aliceResult = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 12345,
      myDeviceId: 1,
    });

    expect(aliceResult.sharedSecret.length).toBe(X3DH_SECRET_SIZE);
    expect(aliceResult.initialMessage.signedPreKeyId).toBe(1);
    expect(aliceResult.initialMessage.oneTimePreKeyId).toBe(100);

    // ─── Bob's side ───────────────────────────────────────────────────
    const bobResult = X3DH.receive(
      bob,
      bobSpk,
      bobOpk,
      aliceResult.initialMessage,
    );

    // ★ Core invariant: same secret
    expect(bobResult.sharedSecret.equals(aliceResult.sharedSecret)).toBe(true);
    expect(bobResult.oneTimePreKeyId).toBe(100);
  });

  it('without one-time prekey: secrets match (DH4 omitted)', () => {
    const { alice, bob, bobSpk, bobBundle } = setup({ withOneTimeKey: false });

    const aliceResult = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 12345,
    });
    expect(aliceResult.initialMessage.oneTimePreKeyId).toBeUndefined();

    const bobResult = X3DH.receive(bob, bobSpk, null, aliceResult.initialMessage);

    expect(bobResult.sharedSecret.equals(aliceResult.sharedSecret)).toBe(true);
    expect(bobResult.oneTimePreKeyId).toBeNull();
  });

  it('two independent runs produce different secrets (fresh ephemeral)', () => {
    const { alice, bob, bobSpk, bobOpk, bobBundle } = setup();

    const r1 = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });
    const r2 = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    // Different ephemerals → different secrets
    expect(r1.sharedSecret.equals(r2.sharedSecret)).toBe(false);
    expect(r1.ephemeralPublicKey.equals(r2.ephemeralPublicKey)).toBe(false);

    // But each round-trips correctly with its own initial message
    const b1 = X3DH.receive(bob, bobSpk, bobOpk, r1.initialMessage);
    const b2 = X3DH.receive(bob, bobSpk, bobOpk, r2.initialMessage);

    expect(b1.sharedSecret.equals(r1.sharedSecret)).toBe(true);
    expect(b2.sharedSecret.equals(r2.sharedSecret)).toBe(true);
  });

  it('shared secret is exactly 32 bytes', () => {
    const { alice, bobBundle } = setup();
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });
    expect(r.sharedSecret.length).toBe(32);
  });

  it('shared secret has reasonable entropy (not all zeros, not predictable)', () => {
    const { alice, bobBundle } = setup();
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    // It must not be all zeros (sanity)
    expect(r.sharedSecret.every((b) => b === 0)).toBe(false);
    // It must not equal a known buffer (HKDF output is essentially random)
    const allFFs = Buffer.alloc(32, 0xff);
    expect(r.sharedSecret.equals(allFFs)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Wire format round-trip
// ═══════════════════════════════════════════════════════════════════════════

describe('X3DH initial message wire format round-trip', () => {
  it('initial message can be serialized to JSON and reconstructed', () => {
    const { alice, bob, bobSpk, bobOpk, bobBundle } = setup();

    // Alice initiates and sends over the wire
    const aliceResult = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 12345,
    });
    const jsonString = JSON.stringify(aliceResult.initialMessage);

    // Bob receives and parses
    const parsedPayload = JSON.parse(jsonString);
    const bobResult = X3DH.receive(bob, bobSpk, bobOpk, parsedPayload);

    expect(bobResult.sharedSecret.equals(aliceResult.sharedSecret)).toBe(true);
  });

  it('InitialMessage.fromPayload returns a usable instance', () => {
    const { alice, bobBundle } = setup();
    const result = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    const msg = InitialMessage.fromPayload(result.initialMessage);
    expect(isInitialMessage(msg)).toBe(true);
    expect(msg.signedPreKeyId).toBe(1);
    expect(msg.usesOneTimePreKey()).toBe(true);
    expect(msg.address()).toBe('1.1');
  });

  it('InitialMessage instance can be passed directly to X3DH.receive()', () => {
    const { alice, bob, bobSpk, bobOpk, bobBundle } = setup();
    const result = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    // Reconstruct as InitialMessage object, not raw payload
    const msgInstance = InitialMessage.fromPayload(result.initialMessage);
    const bobResult = X3DH.receive(bob, bobSpk, bobOpk, msgInstance);

    expect(bobResult.sharedSecret.equals(result.sharedSecret)).toBe(true);
  });

  it('InitialMessage payload omits oneTimePreKeyId when not used', () => {
    const { alice, bobBundle } = setup({ withOneTimeKey: false });
    const result = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    expect(result.initialMessage.oneTimePreKeyId).toBeUndefined();
    expect(JSON.stringify(result.initialMessage)).not.toContain('oneTimePreKeyId');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Security: Attacker scenarios
// ═══════════════════════════════════════════════════════════════════════════

describe('X3DH security: Mallory-style attacks', () => {
  it('Mallory cannot derive Alice and Bobs secret without IK_B private', () => {
    const { alice, bobBundle } = setup();
    const aliceResult = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 1,
    });

    // Mallory has his own keys but doesn't know Bob's private prekeys
    const mallory = IdentityKeyPair.generate();
    const mallorySpk = SignedPreKey.generate(mallory, 1);
    const malloryOpk = OneTimePreKey.generate(100);

    // Mallory tries to "receive" Alice's initial message using HIS keys
    const malloryResult = X3DH.receive(
      mallory,
      mallorySpk,
      malloryOpk,
      aliceResult.initialMessage,
    );

    // Mallory derives SOMETHING (the protocol doesn't fail catastrophically),
    // but it's not the secret Alice has
    expect(malloryResult.sharedSecret.equals(aliceResult.sharedSecret)).toBe(false);
  });

  it('Tampered ephemeralKey produces different secret on Bob side', () => {
    const { alice, bob, bobSpk, bobOpk, bobBundle } = setup();
    const aliceResult = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 1,
    });

    // Mallory tampers ephemeralKey
    const tamperedEphHex = Buffer.from(
      aliceResult.initialMessage.ephemeralKey,
      'hex',
    );
    tamperedEphHex[0] ^= 0xff;

    const tamperedPayload = {
      ...aliceResult.initialMessage,
      ephemeralKey: tamperedEphHex.toString('hex'),
    };

    const bobResult = X3DH.receive(bob, bobSpk, bobOpk, tamperedPayload);
    // The protocol doesn't detect this here — that's the Double Ratchet's job.
    // But the derived secret MUST NOT match Alice's.
    expect(bobResult.sharedSecret.equals(aliceResult.sharedSecret)).toBe(false);
  });

  it('Tampered initialMessage payload hex is rejected (size mismatch)', () => {
    const { alice, bob, bobSpk, bobOpk, bobBundle } = setup();
    const aliceResult = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 1,
    });

    // Half the ephemeral key
    const truncated = {
      ...aliceResult.initialMessage,
      ephemeralKey: aliceResult.initialMessage.ephemeralKey.slice(0, 30),
    };

    expect(() =>
      X3DH.receive(bob, bobSpk, bobOpk, truncated),
    ).toThrow(SerializationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Validation: input checking
// ═══════════════════════════════════════════════════════════════════════════

describe('X3DH.initiate input validation', () => {
  it('rejects non-IdentityKeyPair for myIdentity', () => {
    const { bobBundle } = setup();
    expect(() =>
      X3DH.initiate({} as IdentityKeyPair, bobBundle, { myRegistrationId: 1 }),
    ).toThrow(ValidationError);
  });

  it('rejects non-PreKeyBundle for theirBundle', () => {
    const { alice } = setup();
    expect(() =>
      X3DH.initiate(alice, {} as PreKeyBundle, { myRegistrationId: 1 }),
    ).toThrow(ValidationError);
  });

  it('rejects missing myRegistrationId in options', () => {
    const { alice, bobBundle } = setup();
    expect(() =>
      X3DH.initiate(alice, bobBundle, {} as never),
    ).toThrow(ValidationError);
  });

  it('rejects null options', () => {
    const { alice, bobBundle } = setup();
    expect(() =>
      X3DH.initiate(alice, bobBundle, null as never),
    ).toThrow(ValidationError);
  });

  it('rejects expired signed prekey (default behavior)', () => {
    const alice = IdentityKeyPair.generate();
    const bob = IdentityKeyPair.generate();

    // Create a SPK that's already expired
    const expiredAge = 31 * 24 * 60 * 60 * 1000; // 31 days
    const oldSpk = SignedPreKey.generate(bob, 1, Date.now() - expiredAge);

    const expiredBundle = PreKeyBundle.build({
      registrationId: 1,
      identityKey: bob.toPublic(),
      signedPreKey: oldSpk.toPublic(),
    });

    expect(() =>
      X3DH.initiate(alice, expiredBundle, { myRegistrationId: 1 }),
    ).toThrow(ProtocolError);
  });

  it('accepts expired SPK when rejectExpiredSignedPreKey=false', () => {
    const alice = IdentityKeyPair.generate();
    const bob = IdentityKeyPair.generate();

    const oldSpk = SignedPreKey.generate(
      bob,
      1,
      Date.now() - 31 * 24 * 60 * 60 * 1000,
    );
    const expiredBundle = PreKeyBundle.build({
      registrationId: 1,
      identityKey: bob.toPublic(),
      signedPreKey: oldSpk.toPublic(),
    });

    const result = X3DH.initiate(alice, expiredBundle, {
      myRegistrationId: 1,
      rejectExpiredSignedPreKey: false,
    });
    expect(result.sharedSecret.length).toBe(32);
  });

  it('respects custom signedPreKeyMaxAgeMs', () => {
    const alice = IdentityKeyPair.generate();
    const bob = IdentityKeyPair.generate();

    // 2 days old
    const spk = SignedPreKey.generate(
      bob,
      1,
      Date.now() - 2 * 24 * 60 * 60 * 1000,
    );
    const bundle = PreKeyBundle.build({
      registrationId: 1,
      identityKey: bob.toPublic(),
      signedPreKey: spk.toPublic(),
    });

    // With 1-day max → reject
    expect(() =>
      X3DH.initiate(alice, bundle, {
        myRegistrationId: 1,
        signedPreKeyMaxAgeMs: 24 * 60 * 60 * 1000,
      }),
    ).toThrow(ProtocolError);

    // With 3-day max → accept
    const result = X3DH.initiate(alice, bundle, {
      myRegistrationId: 1,
      signedPreKeyMaxAgeMs: 3 * 24 * 60 * 60 * 1000,
    });
    expect(result.sharedSecret.length).toBe(32);
  });

  it('uses myDeviceId default = 1', () => {
    const { alice, bobBundle } = setup();
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });
    expect(r.initialMessage.deviceId).toBe(1);
  });

  it('respects custom myDeviceId', () => {
    const { alice, bobBundle } = setup();
    const r = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 1,
      myDeviceId: 5,
    });
    expect(r.initialMessage.deviceId).toBe(5);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Validation: receiver
// ═══════════════════════════════════════════════════════════════════════════

describe('X3DH.receive input validation', () => {
  it('rejects non-IdentityKeyPair', () => {
    const { bobSpk, bobOpk } = setup();
    const fakeMsg = {
      identityKey: 'a'.repeat(64),
      ephemeralKey: 'a'.repeat(64),
      signedPreKeyId: 1,
      oneTimePreKeyId: 100,
      registrationId: 1,
      deviceId: 1,
    };
    expect(() =>
      X3DH.receive({} as IdentityKeyPair, bobSpk, bobOpk, fakeMsg),
    ).toThrow(ValidationError);
  });

  it('rejects non-SignedPreKey', () => {
    const { alice, bob, bobOpk, bobBundle } = setup();
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });
    expect(() =>
      X3DH.receive(bob, {} as SignedPreKey, bobOpk, r.initialMessage),
    ).toThrow(ValidationError);
  });

  it('rejects non-OneTimePreKey for myOneTimePreKey (when defined)', () => {
    const { alice, bob, bobSpk, bobBundle } = setup();
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });
    expect(() =>
      X3DH.receive(bob, bobSpk, {} as OneTimePreKey, r.initialMessage),
    ).toThrow(ValidationError);
  });

  it('rejects SignedPreKey ID mismatch', () => {
    const { alice, bob, bobOpk, bobBundle } = setup();
    const wrongSpk = SignedPreKey.generate(bob, 999); // different id
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    expect(() =>
      X3DH.receive(bob, wrongSpk, bobOpk, r.initialMessage),
    ).toThrow(PreKeyError);
  });

  it('rejects when Alice used OPK but Bob provides null', () => {
    const { alice, bob, bobSpk, bobBundle } = setup();
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });
    // Alice used OPK=100 but Bob says he has no OPK
    expect(() =>
      X3DH.receive(bob, bobSpk, null, r.initialMessage),
    ).toThrow(PreKeyError);
  });

  it('rejects OPK ID mismatch', () => {
    const { alice, bob, bobSpk, bobBundle } = setup();
    const wrongOpk = OneTimePreKey.generate(200); // different id
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    expect(() =>
      X3DH.receive(bob, bobSpk, wrongOpk, r.initialMessage),
    ).toThrow(PreKeyError);
  });

  it('tolerates Bob providing OPK when Alice did not use one', () => {
    const { alice, bob, bobSpk, bobOpk, bobBundle } = setup({
      withOneTimeKey: false,
    });
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    // Bob provides an OPK (extra) but Alice didn't use one — should ignore it
    const result = X3DH.receive(bob, bobSpk, bobOpk, r.initialMessage);
    expect(result.sharedSecret.equals(r.sharedSecret)).toBe(true);
    expect(result.oneTimePreKeyId).toBeNull();
  });

  it('accepts raw payload OR InitialMessage instance', () => {
    const { alice, bob, bobSpk, bobOpk, bobBundle } = setup();
    const r = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1 });

    const fromPayload = X3DH.receive(bob, bobSpk, bobOpk, r.initialMessage);
    const fromInstance = X3DH.receive(
      bob,
      bobSpk,
      bobOpk,
      InitialMessage.fromPayload(r.initialMessage),
    );

    expect(fromPayload.sharedSecret.equals(fromInstance.sharedSecret)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// InitialMessage class — direct tests
// ═══════════════════════════════════════════════════════════════════════════

describe('InitialMessage', () => {
  it('constructor builds a valid instance', () => {
    const alice = IdentityKeyPair.generate();
    const msg = new InitialMessage({
      identityKey: alice.toPublic(),
      ephemeralKey: Buffer.alloc(32),
      signedPreKeyId: 1,
      oneTimePreKeyId: 100,
      registrationId: 12345,
      deviceId: 1,
    });
    expect(msg.signedPreKeyId).toBe(1);
    expect(msg.oneTimePreKeyId).toBe(100);
    expect(msg.address()).toBe('12345.1');
  });

  it('rejects non-PublicIdentityKey', () => {
    expect(() =>
      new InitialMessage({
        identityKey: {} as never,
        ephemeralKey: Buffer.alloc(32),
        signedPreKeyId: 1,
        registrationId: 1,
        deviceId: 1,
      }),
    ).toThrow(ValidationError);
  });

  it('rejects wrong ephemeralKey size', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      new InitialMessage({
        identityKey: alice.toPublic(),
        ephemeralKey: Buffer.alloc(10),
        signedPreKeyId: 1,
        registrationId: 1,
        deviceId: 1,
      }),
    ).toThrow(ValidationError);
  });

  it('rejects invalid signedPreKeyId', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      new InitialMessage({
        identityKey: alice.toPublic(),
        ephemeralKey: Buffer.alloc(32),
        signedPreKeyId: 0,
        registrationId: 1,
        deviceId: 1,
      }),
    ).toThrow(ValidationError);
  });

  it('rejects invalid oneTimePreKeyId', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      new InitialMessage({
        identityKey: alice.toPublic(),
        ephemeralKey: Buffer.alloc(32),
        signedPreKeyId: 1,
        oneTimePreKeyId: -1,
        registrationId: 1,
        deviceId: 1,
      }),
    ).toThrow(ValidationError);
  });

  it('rejects out-of-range registrationId', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      new InitialMessage({
        identityKey: alice.toPublic(),
        ephemeralKey: Buffer.alloc(32),
        signedPreKeyId: 1,
        registrationId: 0,
        deviceId: 1,
      }),
    ).toThrow(ValidationError);
  });

  it('rejects out-of-range deviceId', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      new InitialMessage({
        identityKey: alice.toPublic(),
        ephemeralKey: Buffer.alloc(32),
        signedPreKeyId: 1,
        registrationId: 1,
        deviceId: 0,
      }),
    ).toThrow(ValidationError);
  });

  it('accepts Uint8Array for ephemeralKey', () => {
    const alice = IdentityKeyPair.generate();
    const msg = new InitialMessage({
      identityKey: alice.toPublic(),
      ephemeralKey: new Uint8Array(32),
      signedPreKeyId: 1,
      registrationId: 1,
      deviceId: 1,
    });
    expect(msg.ephemeralKey.length).toBe(32);
  });

  it('instance is frozen', () => {
    const alice = IdentityKeyPair.generate();
    const msg = new InitialMessage({
      identityKey: alice.toPublic(),
      ephemeralKey: Buffer.alloc(32),
      signedPreKeyId: 1,
      registrationId: 1,
      deviceId: 1,
    });
    expect(Object.isFrozen(msg)).toBe(true);
  });

  it('toString and toJSON are safe', () => {
    const alice = IdentityKeyPair.generate();
    const msg = new InitialMessage({
      identityKey: alice.toPublic(),
      ephemeralKey: Buffer.alloc(32),
      signedPreKeyId: 5,
      oneTimePreKeyId: 42,
      registrationId: 100,
      deviceId: 1,
    });
    expect(msg.toString()).toMatch(/InitialMessage\(from=100\.1, spk=5, otpk=42\)/);
    expect(msg.toJSON().from).toBe('100.1');
  });

  it('toString without OPK', () => {
    const alice = IdentityKeyPair.generate();
    const msg = new InitialMessage({
      identityKey: alice.toPublic(),
      ephemeralKey: Buffer.alloc(32),
      signedPreKeyId: 1,
      registrationId: 1,
      deviceId: 1,
    });
    expect(msg.toString()).not.toContain('otpk');
  });

  // ═══════════════════════════════════════════════════════════════════
  // fromPayload errors
  // ═══════════════════════════════════════════════════════════════════

  describe('fromPayload errors', () => {
    it('rejects null', () => {
      expect(() => InitialMessage.fromPayload(null)).toThrow(SerializationError);
    });

    it('rejects non-object', () => {
      expect(() => InitialMessage.fromPayload('string')).toThrow(SerializationError);
    });

    it('rejects missing identityKey', () => {
      expect(() => InitialMessage.fromPayload({})).toThrow(SerializationError);
    });

    it('rejects non-string identityKey', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 123,
          ephemeralKey: 'a'.repeat(64),
          signedPreKeyId: 1,
          registrationId: 1,
          deviceId: 1,
        }),
      ).toThrow(SerializationError);
    });

    it('rejects non-string ephemeralKey', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 'a'.repeat(64),
          ephemeralKey: 123,
          signedPreKeyId: 1,
          registrationId: 1,
          deviceId: 1,
        }),
      ).toThrow(SerializationError);
    });

    it('rejects non-number signedPreKeyId', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 'a'.repeat(64),
          ephemeralKey: 'a'.repeat(64),
          signedPreKeyId: '1',
          registrationId: 1,
          deviceId: 1,
        }),
      ).toThrow(SerializationError);
    });

    it('rejects non-number registrationId', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 'a'.repeat(64),
          ephemeralKey: 'a'.repeat(64),
          signedPreKeyId: 1,
          registrationId: '1',
          deviceId: 1,
        }),
      ).toThrow(SerializationError);
    });

    it('rejects non-number deviceId', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 'a'.repeat(64),
          ephemeralKey: 'a'.repeat(64),
          signedPreKeyId: 1,
          registrationId: 1,
          deviceId: '1',
        }),
      ).toThrow(SerializationError);
    });

    it('rejects non-(number|null|undefined) oneTimePreKeyId', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 'a'.repeat(64),
          ephemeralKey: 'a'.repeat(64),
          signedPreKeyId: 1,
          oneTimePreKeyId: 'foo',
          registrationId: 1,
          deviceId: 1,
        }),
      ).toThrow(SerializationError);
    });

    it('rejects bad identityKey hex', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 'ZZZ',
          ephemeralKey: 'a'.repeat(64),
          signedPreKeyId: 1,
          registrationId: 1,
          deviceId: 1,
        }),
      ).toThrow(SerializationError);
    });

    it('rejects bad ephemeralKey hex', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 'a'.repeat(64),
          ephemeralKey: 'ZZZ',
          signedPreKeyId: 1,
          registrationId: 1,
          deviceId: 1,
        }),
      ).toThrow(SerializationError);
    });

    it('rejects wrong identityKey size', () => {
      expect(() =>
        InitialMessage.fromPayload({
          identityKey: 'aa',
          ephemeralKey: 'a'.repeat(64),
          signedPreKeyId: 1,
          registrationId: 1,
          deviceId: 1,
        }),
      ).toThrow(SerializationError);
    });

    it('accepts null oneTimePreKeyId', () => {
      const alice = IdentityKeyPair.generate();
      const msg = InitialMessage.fromPayload({
        identityKey: alice.toPublic().toHex(),
        ephemeralKey: 'a'.repeat(64),
        signedPreKeyId: 1,
        oneTimePreKeyId: null,
        registrationId: 1,
        deviceId: 1,
      });
      expect(msg.oneTimePreKeyId).toBeNull();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Type guard
// ═══════════════════════════════════════════════════════════════════════════

describe('isInitialMessage', () => {
  it('returns true for InitialMessage', () => {
    const alice = IdentityKeyPair.generate();
    const msg = new InitialMessage({
      identityKey: alice.toPublic(),
      ephemeralKey: Buffer.alloc(32),
      signedPreKeyId: 1,
      registrationId: 1,
      deviceId: 1,
    });
    expect(isInitialMessage(msg)).toBe(true);
  });

  it('returns false for plain object', () => {
    expect(isInitialMessage({})).toBe(false);
    expect(isInitialMessage(null)).toBe(false);
    expect(isInitialMessage(undefined)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Sanity: SignatureError is exported from main entry
// (was added in v0.2.0, used by PreKeyBundle.fromPayload internally)
// ═══════════════════════════════════════════════════════════════════════════

describe('Module exports sanity', () => {
  it('SignatureError can be imported and instantiated', () => {
    const e = new SignatureError('test', { foo: 'bar' });
    expect(e).toBeInstanceOf(SignatureError);
    expect(e.message).toBe('test');
    expect(e.context).toMatchObject({ foo: 'bar' });
  });
});
