import { describe, it, expect } from 'vitest';
import {
  SignedPreKey,
  PublicSignedPreKey,
  isSignedPreKey,
  isPublicSignedPreKey,
} from '../src/prekeys';
import { IdentityKeyPair, PublicIdentityKey } from '../src/identity';
import {
  PreKeyError,
  ValidationError,
  SerializationError,
  SignatureError,
} from '../src/errors';
import {
  MAX_PREKEY_ID,
  MIN_PREKEY_ID,
  SIGNATURE_SIZE,
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  SIGNED_PREKEY_ROTATION_MS,
  SIGNED_PREKEY_MAX_AGE_MS,
} from '../src/constants';

describe('SignedPreKey', () => {
  // ═══════════════════════════════════════════════════════════════════
  // Generation
  // ═══════════════════════════════════════════════════════════════════

  describe('generate()', () => {
    it('produces a 32-byte public key and 64-byte signature', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);

      expect(spk.publicKey.length).toBe(PUBLIC_KEY_SIZE);
      expect(spk.privateKey.length).toBe(PRIVATE_KEY_SIZE);
      expect(spk.signature.length).toBe(SIGNATURE_SIZE);
    });

    it('signature verifies against identity public key', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);

      // ★ Core invariant: the signature must verify against alice's PUBLIC key
      expect(spk.verify(alice.toPublic())).toBe(true);
    });

    it('signature does NOT verify against a different identity', () => {
      const alice = IdentityKeyPair.generate();
      const bob = IdentityKeyPair.generate();
      const aliceSpk = SignedPreKey.generate(alice, 1);

      expect(aliceSpk.verify(bob.toPublic())).toBe(false);
    });

    it('different generations produce different keys/sigs', () => {
      const alice = IdentityKeyPair.generate();
      const a = SignedPreKey.generate(alice, 1);
      const b = SignedPreKey.generate(alice, 1);

      expect(a.publicKey.equals(b.publicKey)).toBe(false);
      expect(a.signature.equals(b.signature)).toBe(false);
    });

    it('accepts MIN_PREKEY_ID and MAX_PREKEY_ID', () => {
      const alice = IdentityKeyPair.generate();
      expect(SignedPreKey.generate(alice, MIN_PREKEY_ID).id).toBe(MIN_PREKEY_ID);
      expect(SignedPreKey.generate(alice, MAX_PREKEY_ID).id).toBe(MAX_PREKEY_ID);
    });

    it('rejects id 0', () => {
      const alice = IdentityKeyPair.generate();
      expect(() => SignedPreKey.generate(alice, 0)).toThrow(PreKeyError);
    });

    it('rejects negative id', () => {
      const alice = IdentityKeyPair.generate();
      expect(() => SignedPreKey.generate(alice, -1)).toThrow(PreKeyError);
    });

    it('rejects id > MAX_PREKEY_ID', () => {
      const alice = IdentityKeyPair.generate();
      expect(() => SignedPreKey.generate(alice, MAX_PREKEY_ID + 1)).toThrow(
        PreKeyError,
      );
    });

    it('rejects non-IdentityKeyPair', () => {
      expect(() =>
        SignedPreKey.generate({} as IdentityKeyPair, 1),
      ).toThrow(ValidationError);
    });

    it('accepts custom timestamp', () => {
      const alice = IdentityKeyPair.generate();
      const ts = 1700000000000;
      const spk = SignedPreKey.generate(alice, 1, ts);
      expect(spk.timestamp).toBe(ts);
    });

    it('rejects negative timestamp', () => {
      const alice = IdentityKeyPair.generate();
      expect(() => SignedPreKey.generate(alice, 1, -1)).toThrow(ValidationError);
    });

    it('rejects non-integer timestamp', () => {
      const alice = IdentityKeyPair.generate();
      expect(() => SignedPreKey.generate(alice, 1, 1.5)).toThrow(ValidationError);
    });

    it('default timestamp is roughly Date.now()', () => {
      const alice = IdentityKeyPair.generate();
      const before = Date.now();
      const spk = SignedPreKey.generate(alice, 1);
      const after = Date.now();
      expect(spk.timestamp).toBeGreaterThanOrEqual(before);
      expect(spk.timestamp).toBeLessThanOrEqual(after);
    });

    it('instance is frozen', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(Object.isFrozen(spk)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Verify - security critical
  // ═══════════════════════════════════════════════════════════════════

  describe('verify()', () => {
    it('returns true for valid signature', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(spk.verify(alice.toPublic())).toBe(true);
    });

    it('returns false for wrong identity', () => {
      const alice = IdentityKeyPair.generate();
      const eve = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(spk.verify(eve.toPublic())).toBe(false);
    });

    it('returns false for non-PublicIdentityKey input', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(spk.verify({} as PublicIdentityKey)).toBe(false);
    });

    it('Mallory cannot forge a SignedPreKey for Alice', () => {
      const alice = IdentityKeyPair.generate();
      const mallory = IdentityKeyPair.generate();

      // Mallory tries to create a SignedPreKey pretending to be Alice
      const fake = SignedPreKey.generate(mallory, 1);

      // Bob, who only knows Alice's public identity, rejects it
      expect(fake.verify(alice.toPublic())).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Rotation lifecycle
  // ═══════════════════════════════════════════════════════════════════

  describe('rotation lifecycle', () => {
    it('fresh prekey does not need rotation', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(spk.needsRotation()).toBe(false);
    });

    it('prekey older than threshold needs rotation', () => {
      const alice = IdentityKeyPair.generate();
      const oldTimestamp = Date.now() - SIGNED_PREKEY_ROTATION_MS - 1000;
      const spk = SignedPreKey.generate(alice, 1, oldTimestamp);
      expect(spk.needsRotation()).toBe(true);
    });

    it('fresh prekey is not expired', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(spk.isExpired()).toBe(false);
    });

    it('prekey older than max age is expired', () => {
      const alice = IdentityKeyPair.generate();
      const oldTimestamp = Date.now() - SIGNED_PREKEY_MAX_AGE_MS - 1000;
      const spk = SignedPreKey.generate(alice, 1, oldTimestamp);
      expect(spk.isExpired()).toBe(true);
    });

    it('ageMs returns non-negative value', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1, Date.now() + 1_000_000); // future
      expect(spk.ageMs()).toBe(0);
    });

    it('custom rotation threshold', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1, Date.now() - 1000);
      expect(spk.needsRotation(500)).toBe(true);
      expect(spk.needsRotation(2000)).toBe(false);
    });

    it('custom expiration threshold', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1, Date.now() - 1000);
      expect(spk.isExpired(500)).toBe(true);
      expect(spk.isExpired(2000)).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Serialization
  // ═══════════════════════════════════════════════════════════════════

  describe('serialize / deserialize round-trip', () => {
    it('round-trips correctly', () => {
      const alice = IdentityKeyPair.generate();
      const original = SignedPreKey.generate(alice, 7);
      const restored = SignedPreKey.deserialize(original.serialize());

      expect(restored.id).toBe(original.id);
      expect(restored.publicKey.equals(original.publicKey)).toBe(true);
      expect(restored.privateKey.equals(original.privateKey)).toBe(true);
      expect(restored.signature.equals(original.signature)).toBe(true);
      expect(restored.timestamp).toBe(original.timestamp);

      // ★ And the restored key still verifies
      expect(restored.verify(alice.toPublic())).toBe(true);
    });

    it('deserialize rejects null', () => {
      expect(() => SignedPreKey.deserialize(null)).toThrow(SerializationError);
    });

    it('deserialize rejects missing fields', () => {
      expect(() => SignedPreKey.deserialize({})).toThrow(SerializationError);
    });

    it('deserialize rejects bad signature size', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const data = spk.serialize();
      const bad = { ...data, signature: 'aa' };
      expect(() => SignedPreKey.deserialize(bad)).toThrow(SerializationError);
    });

    it('deserialize rejects bad hex', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const data = spk.serialize();
      const bad = { ...data, publicKey: 'ZZZ' };
      expect(() => SignedPreKey.deserialize(bad)).toThrow(SerializationError);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // toPayload / toPublic
  // ═══════════════════════════════════════════════════════════════════

  describe('toPayload()', () => {
    it('returns wire-format object', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const payload = spk.toPayload();

      expect(payload.id).toBe(1);
      expect(payload.publicKey).toBe(spk.publicKey.toString('hex'));
      expect(payload.signature).toBe(spk.signature.toString('hex'));
      expect(payload.timestamp).toBe(spk.timestamp);
    });

    it('payload does not include private key', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const payload = spk.toPayload();
      expect(payload).not.toHaveProperty('privateKey');
    });
  });

  describe('toPublic()', () => {
    it('returns a PublicSignedPreKey', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const pub = spk.toPublic();

      expect(pub).toBeInstanceOf(PublicSignedPreKey);
      expect(pub.id).toBe(spk.id);
      expect(pub.publicKey.equals(spk.publicKey)).toBe(true);
      expect(pub.signature.equals(spk.signature)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Safe Output
  // ═══════════════════════════════════════════════════════════════════

  describe('safe output (no private key leak)', () => {
    it('toString does not expose private key', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      expect(spk.toString()).not.toContain(spk.privateKey.toString('hex'));
    });

    it('toJSON does not include private key', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const json = spk.toJSON();
      expect(json).not.toHaveProperty('privateKey');
      expect(JSON.stringify(json)).not.toContain(spk.privateKey.toString('hex'));
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// PublicSignedPreKey
// ═══════════════════════════════════════════════════════════════════════════

describe('PublicSignedPreKey', () => {
  describe('constructor', () => {
    it('builds from components', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const pub = new PublicSignedPreKey(
        spk.id,
        spk.publicKey,
        spk.signature,
        spk.timestamp,
      );
      expect(pub.id).toBe(spk.id);
    });

    it('rejects bad signature size', () => {
      expect(() =>
        new PublicSignedPreKey(1, Buffer.alloc(32), Buffer.alloc(10), Date.now()),
      ).toThrow(ValidationError);
    });

    it('rejects invalid id', () => {
      expect(() =>
        new PublicSignedPreKey(0, Buffer.alloc(32), Buffer.alloc(64), Date.now()),
      ).toThrow(PreKeyError);
    });

    it('rejects negative timestamp', () => {
      expect(() =>
        new PublicSignedPreKey(1, Buffer.alloc(32), Buffer.alloc(64), -1),
      ).toThrow(ValidationError);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // fromPayload - SECURITY CRITICAL
  // ═══════════════════════════════════════════════════════════════════

  describe('fromPayload() — security critical', () => {
    it('accepts valid signed payload', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const payload = spk.toPayload();

      const verified = PublicSignedPreKey.fromPayload(alice.toPublic(), payload);
      expect(verified.id).toBe(1);
      expect(verified.publicKey.equals(spk.publicKey)).toBe(true);
    });

    it('REJECTS payload signed by Mallory pretending to be Alice', () => {
      const alice = IdentityKeyPair.generate();
      const mallory = IdentityKeyPair.generate();

      // Mallory generates a SignedPreKey with HIS key
      const mallorySpk = SignedPreKey.generate(mallory, 1);
      const fakePayload = mallorySpk.toPayload();

      // Bob expects it to be from Alice — fromPayload throws
      expect(() =>
        PublicSignedPreKey.fromPayload(alice.toPublic(), fakePayload),
      ).toThrow(SignatureError);
    });

    it('REJECTS payload with tampered publicKey', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const payload = spk.toPayload();

      // Tamper with the public key but keep the signature
      const tamperedPubBuf = Buffer.from(payload.publicKey, 'hex');
      tamperedPubBuf[0] ^= 0xff;
      const tampered = { ...payload, publicKey: tamperedPubBuf.toString('hex') };

      expect(() =>
        PublicSignedPreKey.fromPayload(alice.toPublic(), tampered),
      ).toThrow(SignatureError);
    });

    it('REJECTS payload with tampered signature', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const payload = spk.toPayload();

      const tamperedSigBuf = Buffer.from(payload.signature, 'hex');
      tamperedSigBuf[0] ^= 0xff;
      const tampered = { ...payload, signature: tamperedSigBuf.toString('hex') };

      expect(() =>
        PublicSignedPreKey.fromPayload(alice.toPublic(), tampered),
      ).toThrow(SignatureError);
    });

    it('rejects non-object payload', () => {
      const alice = IdentityKeyPair.generate();
      expect(() =>
        PublicSignedPreKey.fromPayload(alice.toPublic(), null as never),
      ).toThrow(SerializationError);
    });

    it('rejects payload missing fields', () => {
      const alice = IdentityKeyPair.generate();
      expect(() =>
        PublicSignedPreKey.fromPayload(alice.toPublic(), {} as never),
      ).toThrow(SerializationError);
    });

    it('rejects non-PublicIdentityKey for identityPub', () => {
      expect(() =>
        PublicSignedPreKey.fromPayload(
          {} as PublicIdentityKey,
          {} as never,
        ),
      ).toThrow(ValidationError);
    });

    it('rejects payload with bad hex', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const payload = spk.toPayload();
      const bad = { ...payload, publicKey: 'ZZZ' };
      expect(() =>
        PublicSignedPreKey.fromPayload(alice.toPublic(), bad),
      ).toThrow(SerializationError);
    });

    it('rejects payload with wrong key size', () => {
      const alice = IdentityKeyPair.generate();
      const spk = SignedPreKey.generate(alice, 1);
      const payload = spk.toPayload();
      const bad = { ...payload, publicKey: 'aa' };
      expect(() =>
        PublicSignedPreKey.fromPayload(alice.toPublic(), bad),
      ).toThrow(SerializationError);
    });
  });

  it('isExpired honors maxAge', () => {
    const alice = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(alice, 1, Date.now() - 1000);
    const pub = spk.toPublic();
    expect(pub.isExpired(500)).toBe(true);
    expect(pub.isExpired(2000)).toBe(false);
  });

  it('toJSON does not expose private key', () => {
    const alice = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(alice, 1);
    const pub = spk.toPublic();
    expect(pub.toJSON()).not.toHaveProperty('privateKey');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// E2E Scenario: Alice's server → Bob receives
// ═══════════════════════════════════════════════════════════════════════════

describe('E2E: Server-mediated SignedPreKey exchange', () => {
  it('Alice signs → server stores payload → Bob verifies', () => {
    // ─── Alice's side ─────────────────────────────────────────────────
    const alice = IdentityKeyPair.generate();
    const aliceSpk = SignedPreKey.generate(alice, 42);

    // Alice uploads (publicly):
    //   - her identity public key
    //   - the signed prekey payload
    const upload = {
      identityKey: alice.toPublic().toHex(),
      signedPreKey: aliceSpk.toPayload(),
    };

    // ─── Bob's side (later, possibly while Alice is offline) ──────────
    // Bob reconstructs Alice's identity from the uploaded hex
    const aliceIdentity = PublicIdentityKey.fromHex(upload.identityKey);

    // Bob verifies the signed prekey using Alice's identity
    const verified = PublicSignedPreKey.fromPayload(
      aliceIdentity,
      upload.signedPreKey,
    );

    // Bob now trusts this prekey: it has been signed by Alice's identity
    expect(verified.id).toBe(42);
    expect(verified.publicKey.equals(aliceSpk.publicKey)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards
// ═══════════════════════════════════════════════════════════════════════════

describe('Type Guards', () => {
  it('isSignedPreKey', () => {
    const alice = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(alice, 1);
    expect(isSignedPreKey(spk)).toBe(true);
    expect(isSignedPreKey(spk.toPublic())).toBe(false);
    expect(isSignedPreKey(null)).toBe(false);
  });

  it('isPublicSignedPreKey', () => {
    const alice = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(alice, 1);
    expect(isPublicSignedPreKey(spk.toPublic())).toBe(true);
    expect(isPublicSignedPreKey(spk)).toBe(false);
    expect(isPublicSignedPreKey(null)).toBe(false);
  });
});
