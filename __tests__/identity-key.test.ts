import { describe, it, expect } from 'vitest';
import {
  IdentityKeyPair,
  PublicIdentityKey,
  isIdentityKeyPair,
  isPublicIdentityKey,
} from '../src/identity';
import { ValidationError, SerializationError, SignatureError } from '../src/errors';
import { PUBLIC_KEY_SIZE, PRIVATE_KEY_SIZE, SIGNATURE_SIZE } from '../src/constants';

describe('IdentityKeyPair', () => {
  describe('generate()', () => {
    it('generates a valid key pair', () => {
      const identity = IdentityKeyPair.generate();
      expect(identity.publicKey).toBeInstanceOf(Buffer);
      expect(identity.privateKey).toBeInstanceOf(Buffer);
      expect(identity.publicKey.length).toBe(PUBLIC_KEY_SIZE);
      expect(identity.privateKey.length).toBe(PRIVATE_KEY_SIZE);
    });

    it('generates unique keys on each call', () => {
      const a = IdentityKeyPair.generate();
      const b = IdentityKeyPair.generate();
      expect(a.publicKey.equals(b.publicKey)).toBe(false);
      expect(a.privateKey.equals(b.privateKey)).toBe(false);
    });

    it('instance is frozen (immutable)', () => {
      const identity = IdentityKeyPair.generate();
      expect(Object.isFrozen(identity)).toBe(true);
    });

    it('keys are non-zero', () => {
      const identity = IdentityKeyPair.generate();
      const allZeros = Buffer.alloc(32);
      expect(identity.publicKey.equals(allZeros)).toBe(false);
      expect(identity.privateKey.equals(allZeros)).toBe(false);
    });
  });

  describe('fromKeys()', () => {
    it('creates from existing Buffers', () => {
      const original = IdentityKeyPair.generate();
      const recreated = IdentityKeyPair.fromKeys(
        original.publicKey,
        original.privateKey,
      );
      expect(recreated.publicKey.equals(original.publicKey)).toBe(true);
      expect(recreated.privateKey.equals(original.privateKey)).toBe(true);
    });

    it('creates from Uint8Array', () => {
      const original = IdentityKeyPair.generate();
      const pub = new Uint8Array(original.publicKey);
      const priv = new Uint8Array(original.privateKey);

      const recreated = IdentityKeyPair.fromKeys(pub, priv);
      expect(recreated.publicKey.equals(original.publicKey)).toBe(true);
    });

    it('throws on wrong public key size', () => {
      expect(() =>
        IdentityKeyPair.fromKeys(Buffer.alloc(31), Buffer.alloc(32)),
      ).toThrow(ValidationError);
    });

    it('throws on wrong private key size', () => {
      expect(() =>
        IdentityKeyPair.fromKeys(Buffer.alloc(32), Buffer.alloc(31)),
      ).toThrow(ValidationError);
    });

    it('throws on non-buffer input', () => {
      expect(() =>
        IdentityKeyPair.fromKeys(
          'not a buffer' as unknown as Buffer,
          Buffer.alloc(32),
        ),
      ).toThrow(ValidationError);
    });

    it('error includes context', () => {
      try {
        IdentityKeyPair.fromKeys(Buffer.alloc(10), Buffer.alloc(32));
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ValidationError);
        if (e instanceof ValidationError) {
          expect(e.context).toHaveProperty('expected', 32);
          expect(e.context).toHaveProperty('actual', 10);
        }
      }
    });
  });

  describe('serialize() / deserialize()', () => {
    it('round-trip preserves keys exactly', () => {
      const original = IdentityKeyPair.generate();
      const serialized = original.serialize();
      const deserialized = IdentityKeyPair.deserialize(serialized);

      expect(deserialized.publicKey.equals(original.publicKey)).toBe(true);
      expect(deserialized.privateKey.equals(original.privateKey)).toBe(true);
    });

    it('serialize returns valid hex strings', () => {
      const identity = IdentityKeyPair.generate();
      const serialized = identity.serialize();
      expect(typeof serialized.publicKey).toBe('string');
      expect(typeof serialized.privateKey).toBe('string');
      expect(serialized.publicKey).toMatch(/^[0-9a-f]{64}$/);
      expect(serialized.privateKey).toMatch(/^[0-9a-f]{64}$/);
    });

    it('deserialize throws on null', () => {
      expect(() => IdentityKeyPair.deserialize(null)).toThrow(SerializationError);
    });

    it('deserialize throws on undefined', () => {
      expect(() => IdentityKeyPair.deserialize(undefined)).toThrow(
        SerializationError,
      );
    });

    it('deserialize throws on non-object', () => {
      expect(() => IdentityKeyPair.deserialize('string')).toThrow(SerializationError);
      expect(() => IdentityKeyPair.deserialize(123)).toThrow(SerializationError);
      expect(() => IdentityKeyPair.deserialize([])).toThrow(SerializationError);
    });

    it('deserialize throws when publicKey missing', () => {
      expect(() =>
        IdentityKeyPair.deserialize({ privateKey: '00'.repeat(32) }),
      ).toThrow(SerializationError);
    });

    it('deserialize throws when privateKey missing', () => {
      expect(() =>
        IdentityKeyPair.deserialize({ publicKey: '00'.repeat(32) }),
      ).toThrow(SerializationError);
    });

    it('deserialize throws on invalid hex characters', () => {
      expect(() =>
        IdentityKeyPair.deserialize({
          publicKey: 'XYZ' + '0'.repeat(61),
          privateKey: '00'.repeat(32),
        }),
      ).toThrow(SerializationError);
    });

    it('deserialize throws on wrong public key size', () => {
      expect(() =>
        IdentityKeyPair.deserialize({
          publicKey: '00'.repeat(31),
          privateKey: '00'.repeat(32),
        }),
      ).toThrow(SerializationError);
    });

    it('deserialize throws on wrong private key size', () => {
      expect(() =>
        IdentityKeyPair.deserialize({
          publicKey: '00'.repeat(32),
          privateKey: '00'.repeat(31),
        }),
      ).toThrow(SerializationError);
    });
  });

  describe('toPublic()', () => {
    it('returns PublicIdentityKey with same public key', () => {
      const identity = IdentityKeyPair.generate();
      const pub = identity.toPublic();
      expect(pub).toBeInstanceOf(PublicIdentityKey);
      expect(pub.publicKey.equals(identity.publicKey)).toBe(true);
    });
  });

  describe('equals()', () => {
    it('returns true for same identity', () => {
      const a = IdentityKeyPair.generate();
      const b = IdentityKeyPair.fromKeys(a.publicKey, a.privateKey);
      expect(a.equals(b)).toBe(true);
    });

    it('returns false for different identities', () => {
      const a = IdentityKeyPair.generate();
      const b = IdentityKeyPair.generate();
      expect(a.equals(b)).toBe(false);
    });

    it('compares against PublicIdentityKey', () => {
      const identity = IdentityKeyPair.generate();
      const pub = identity.toPublic();
      expect(identity.equals(pub)).toBe(true);
    });

    it('returns false for null/undefined', () => {
      const identity = IdentityKeyPair.generate();
      expect(identity.equals(null)).toBe(false);
      expect(identity.equals(undefined)).toBe(false);
    });
  });

  describe('fingerprint()', () => {
    it('returns SHA-256 hex (64 chars)', () => {
      const identity = IdentityKeyPair.generate();
      const fp = identity.fingerprint();
      expect(fp).toMatch(/^[0-9a-f]{64}$/);
    });

    it('is deterministic for same key', () => {
      const identity = IdentityKeyPair.generate();
      expect(identity.fingerprint()).toBe(identity.fingerprint());
    });

    it('differs for different keys', () => {
      const a = IdentityKeyPair.generate();
      const b = IdentityKeyPair.generate();
      expect(a.fingerprint()).not.toBe(b.fingerprint());
    });
  });

  describe('shortFingerprint()', () => {
    it('returns 16 hex chars', () => {
      const identity = IdentityKeyPair.generate();
      expect(identity.shortFingerprint()).toMatch(/^[0-9a-f]{16}$/);
    });
  });

  describe('toString()', () => {
    it('does NOT expose private key', () => {
      const identity = IdentityKeyPair.generate();
      const str = identity.toString();
      expect(str).not.toContain(identity.privateKey.toString('hex'));
      expect(str).toContain('IdentityKeyPair');
    });
  });

  describe('toJSON()', () => {
    it('does NOT expose private key in JSON', () => {
      const identity = IdentityKeyPair.generate();
      const json = JSON.stringify(identity);
      expect(json).not.toContain(identity.privateKey.toString('hex'));
      const parsed = JSON.parse(json);
      expect(parsed).toHaveProperty('type', 'IdentityKeyPair');
      expect(parsed).toHaveProperty('publicKey');
      expect(parsed).not.toHaveProperty('privateKey');
    });
  });
});

describe('PublicIdentityKey', () => {
  describe('constructor', () => {
    it('creates from PublicKey', () => {
      const identity = IdentityKeyPair.generate();
      const pub = new PublicIdentityKey(identity.publicKey);
      expect(pub.publicKey.equals(identity.publicKey)).toBe(true);
    });

    it('creates from raw Buffer', () => {
      const buf = Buffer.alloc(32);
      const pub = new PublicIdentityKey(buf);
      expect(pub.publicKey.length).toBe(32);
    });

    it('creates from Uint8Array', () => {
      const buf = new Uint8Array(32);
      const pub = new PublicIdentityKey(buf);
      expect(pub.publicKey.length).toBe(32);
    });

    it('throws on wrong size', () => {
      expect(() => new PublicIdentityKey(Buffer.alloc(31))).toThrow(ValidationError);
    });

    it('is frozen', () => {
      const identity = IdentityKeyPair.generate();
      const pub = new PublicIdentityKey(identity.publicKey);
      expect(Object.isFrozen(pub)).toBe(true);
    });
  });

  describe('fromHex()', () => {
    it('creates from valid hex', () => {
      const identity = IdentityKeyPair.generate();
      const hex = identity.publicKey.toString('hex');
      const pub = PublicIdentityKey.fromHex(hex);
      expect(pub.publicKey.equals(identity.publicKey)).toBe(true);
    });

    it('throws on non-string', () => {
      expect(() =>
        PublicIdentityKey.fromHex(123 as unknown as string),
      ).toThrow(ValidationError);
    });

    it('throws on invalid hex chars', () => {
      expect(() => PublicIdentityKey.fromHex('XYZ' + 'a'.repeat(61))).toThrow(
        ValidationError,
      );
    });

    it('throws on wrong size', () => {
      expect(() => PublicIdentityKey.fromHex('00'.repeat(31))).toThrow(ValidationError);
    });
  });

  describe('fromBase64()', () => {
    it('creates from valid base64', () => {
      const identity = IdentityKeyPair.generate();
      const b64 = identity.publicKey.toString('base64');
      const pub = PublicIdentityKey.fromBase64(b64);
      expect(pub.publicKey.equals(identity.publicKey)).toBe(true);
    });

    it('throws on non-string', () => {
      expect(() =>
        PublicIdentityKey.fromBase64(123 as unknown as string),
      ).toThrow(ValidationError);
    });
  });

  describe('toHex() / toBase64()', () => {
    it('toHex round-trip', () => {
      const identity = IdentityKeyPair.generate();
      const hex = identity.publicKey.toString('hex');
      const pub = PublicIdentityKey.fromHex(hex);
      expect(pub.toHex()).toBe(hex);
    });

    it('toBase64 round-trip', () => {
      const identity = IdentityKeyPair.generate();
      const b64 = identity.publicKey.toString('base64');
      const pub = PublicIdentityKey.fromBase64(b64);
      expect(pub.toBase64()).toBe(b64);
    });
  });

  describe('equals()', () => {
    it('compares two PublicIdentityKeys', () => {
      const identity = IdentityKeyPair.generate();
      const a = new PublicIdentityKey(identity.publicKey);
      const b = new PublicIdentityKey(identity.publicKey);
      expect(a.equals(b)).toBe(true);
    });

    it('compares against IdentityKeyPair', () => {
      const identity = IdentityKeyPair.generate();
      const pub = new PublicIdentityKey(identity.publicKey);
      expect(pub.equals(identity)).toBe(true);
    });

    it('returns false for null/undefined', () => {
      const identity = IdentityKeyPair.generate();
      const pub = identity.toPublic();
      expect(pub.equals(null)).toBe(false);
      expect(pub.equals(undefined)).toBe(false);
    });
  });

  describe('fingerprints', () => {
    it('matches IdentityKeyPair fingerprint', () => {
      const identity = IdentityKeyPair.generate();
      const pub = identity.toPublic();
      expect(pub.fingerprint()).toBe(identity.fingerprint());
    });

    it('shortFingerprint is 16 chars', () => {
      const identity = IdentityKeyPair.generate();
      const pub = identity.toPublic();
      expect(pub.shortFingerprint()).toMatch(/^[0-9a-f]{16}$/);
    });
  });

  describe('serialization', () => {
    it('toJSON includes only public key', () => {
      const identity = IdentityKeyPair.generate();
      const pub = identity.toPublic();
      const json = JSON.stringify(pub);
      const parsed = JSON.parse(json);
      expect(parsed).toHaveProperty('type', 'PublicIdentityKey');
      expect(parsed).toHaveProperty('publicKey');
      expect(parsed).not.toHaveProperty('privateKey');
    });

    it('toString format', () => {
      const identity = IdentityKeyPair.generate();
      const pub = identity.toPublic();
      expect(pub.toString()).toContain('PublicIdentityKey');
    });
  });
});

describe('Type Guards', () => {
  it('isIdentityKeyPair', () => {
    const identity = IdentityKeyPair.generate();
    expect(isIdentityKeyPair(identity)).toBe(true);
    expect(isIdentityKeyPair(identity.toPublic())).toBe(false);
    expect(isIdentityKeyPair(null)).toBe(false);
    expect(isIdentityKeyPair({})).toBe(false);
  });

  it('isPublicIdentityKey', () => {
    const identity = IdentityKeyPair.generate();
    expect(isPublicIdentityKey(identity.toPublic())).toBe(true);
    expect(isPublicIdentityKey(identity)).toBe(false);
    expect(isPublicIdentityKey(null)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Signing & Verification (XEd25519) — NEW v0.2.0
// ═══════════════════════════════════════════════════════════════════════════

describe('IdentityKeyPair.sign() — XEd25519', () => {
  it('produces a 64-byte signature', () => {
    const alice = IdentityKeyPair.generate();
    const sig = alice.sign(Buffer.from('hello'));
    expect(sig.length).toBe(SIGNATURE_SIZE);
  });

  it('round-trip: alice signs, bob verifies with public key', () => {
    const alice = IdentityKeyPair.generate();
    const msg = Buffer.from('I am alice');
    const sig = alice.sign(msg);

    // Bob has Alice's PublicIdentityKey
    const alicePub = alice.toPublic();

    // verify() throws if invalid; we expect it to succeed
    alicePub.verify(msg, sig);
  });

  it('verify() on the keypair itself works (delegates to public)', () => {
    const alice = IdentityKeyPair.generate();
    const sig = alice.sign(Buffer.from('msg'));
    alice.verify(Buffer.from('msg'), sig);
  });

  it('signatures are non-deterministic by default', () => {
    const alice = IdentityKeyPair.generate();
    const msg = Buffer.from('test');
    const sig1 = alice.sign(msg);
    const sig2 = alice.sign(msg);
    expect(sig1.equals(sig2)).toBe(false);

    // But both verify
    alice.verify(msg, sig1);
    alice.verify(msg, sig2);
  });

  it('signWithRandom is deterministic with same random', () => {
    const alice = IdentityKeyPair.generate();
    const msg = Buffer.from('test');
    const random = Buffer.alloc(64, 0x42);

    const sig1 = alice.signWithRandom(msg, random);
    const sig2 = alice.signWithRandom(msg, random);
    expect(sig1.equals(sig2)).toBe(true);

    // And the signature verifies
    alice.verify(msg, sig1);
  });

  it('signWithRandom rejects wrong random size', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      alice.signWithRandom(Buffer.from('msg'), Buffer.alloc(63)),
    ).toThrow(ValidationError);
    expect(() =>
      alice.signWithRandom(Buffer.from('msg'), Buffer.alloc(65)),
    ).toThrow(ValidationError);
  });

  it('signWithRandom rejects non-Buffer inputs', () => {
    const alice = IdentityKeyPair.generate();
    expect(() =>
      alice.signWithRandom('not a buffer' as unknown as Buffer, Buffer.alloc(64)),
    ).toThrow(ValidationError);
    expect(() =>
      alice.signWithRandom(Buffer.from('msg'), 'not a buffer' as unknown as Buffer),
    ).toThrow(ValidationError);
  });

  it('sign rejects non-Buffer messages', () => {
    const alice = IdentityKeyPair.generate();
    expect(() => alice.sign('not a buffer' as unknown as Buffer)).toThrow(
      ValidationError,
    );
  });

  it('verifyBool returns true for valid signature', () => {
    const alice = IdentityKeyPair.generate();
    const msg = Buffer.from('test');
    const sig = alice.sign(msg);
    expect(alice.verifyBool(msg, sig)).toBe(true);
  });

  it('verifyBool returns false for invalid signature', () => {
    const alice = IdentityKeyPair.generate();
    const fakeSig = Buffer.alloc(64);
    expect(alice.verifyBool(Buffer.from('msg'), fakeSig)).toBe(false);
  });

  it('throws SignatureError on tampered message', () => {
    const alice = IdentityKeyPair.generate();
    const sig = alice.sign(Buffer.from('original'));
    expect(() => alice.verify(Buffer.from('tampered'), sig)).toThrow(
      SignatureError,
    );
  });

  it('Mallory cannot forge Alice signatures', () => {
    const alice = IdentityKeyPair.generate();
    const mallory = IdentityKeyPair.generate();
    const msg = Buffer.from('I am alice');

    // Mallory tries to sign with HER key, pretending to be Alice
    const fakeSig = mallory.sign(msg);

    // Bob, who only has Alice's PUBLIC key, rejects it
    const alicePub = alice.toPublic();
    expect(() => alicePub.verify(msg, fakeSig)).toThrow(SignatureError);
    expect(alicePub.verifyBool(msg, fakeSig)).toBe(false);
  });

  it('signature verification is independent across messages', () => {
    const alice = IdentityKeyPair.generate();
    const sig1 = alice.sign(Buffer.from('msg1'));
    const sig2 = alice.sign(Buffer.from('msg2'));

    // sig1 should NOT verify msg2 and vice versa
    expect(alice.verifyBool(Buffer.from('msg2'), sig1)).toBe(false);
    expect(alice.verifyBool(Buffer.from('msg1'), sig2)).toBe(false);

    // But they verify their own message
    alice.verify(Buffer.from('msg1'), sig1);
    alice.verify(Buffer.from('msg2'), sig2);
  });

  it('signing also works on the deserialized keypair', () => {
    const alice = IdentityKeyPair.generate();
    const serialized = alice.serialize();
    const restored = IdentityKeyPair.deserialize(serialized);

    const msg = Buffer.from('cross-deserialization test');
    const sig = restored.sign(msg);

    // Original key verifies signature from restored key
    alice.verify(msg, sig);
    // And vice versa
    const sigFromOriginal = alice.sign(msg);
    restored.verify(msg, sigFromOriginal);
  });
});

describe('PublicIdentityKey.verify()', () => {
  it('verifies a valid signature', () => {
    const alice = IdentityKeyPair.generate();
    const msg = Buffer.from('hello');
    const sig = alice.sign(msg);

    const alicePub = alice.toPublic();
    alicePub.verify(msg, sig);
  });

  it('throws SignatureError on invalid signature', () => {
    const alice = IdentityKeyPair.generate();
    const alicePub = alice.toPublic();
    const fakeSig = Buffer.alloc(64);

    expect(() => alicePub.verify(Buffer.from('msg'), fakeSig)).toThrow(
      SignatureError,
    );
  });

  it('rejects non-Buffer message', () => {
    const alicePub = IdentityKeyPair.generate().toPublic();
    expect(() =>
      alicePub.verify('not a buffer' as unknown as Buffer, Buffer.alloc(64)),
    ).toThrow(ValidationError);
  });

  it('rejects non-Buffer signature', () => {
    const alicePub = IdentityKeyPair.generate().toPublic();
    expect(() =>
      alicePub.verify(Buffer.from('msg'), 'not a buffer' as unknown as Buffer),
    ).toThrow(ValidationError);
  });

  it('verifyBool returns false (not throws) on bad inputs', () => {
    const alicePub = IdentityKeyPair.generate().toPublic();
    expect(
      alicePub.verifyBool('not a buffer' as unknown as Buffer, Buffer.alloc(64)),
    ).toBe(false);
    expect(
      alicePub.verifyBool(Buffer.from('msg'), 'not a buffer' as unknown as Buffer),
    ).toBe(false);
    // Wrong size signature
    expect(alicePub.verifyBool(Buffer.from('msg'), Buffer.alloc(63))).toBe(
      false,
    );
  });

  it('verifyBool returns true for valid signature', () => {
    const alice = IdentityKeyPair.generate();
    const msg = Buffer.from('verify-me');
    const sig = alice.sign(msg);
    expect(alice.toPublic().verifyBool(msg, sig)).toBe(true);
  });

  it('cross-instance: PublicIdentityKey from fromHex verifies signature', () => {
    const alice = IdentityKeyPair.generate();
    const sig = alice.sign(Buffer.from('hello'));

    // Simulate Bob receiving Alice's public key as hex
    const hex = alice.toPublic().toHex();
    const alicePubReconstructed = PublicIdentityKey.fromHex(hex);

    alicePubReconstructed.verify(Buffer.from('hello'), sig);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// End-to-End Scenarios
// ═══════════════════════════════════════════════════════════════════════════

describe('E2E: Signal Protocol-style identity authentication', () => {
  it('Alice signs an assertion, Bob verifies with received public key', () => {
    // ── Alice (sender) ────────────────────────────────────────────────
    const alice = IdentityKeyPair.generate();
    const assertion = Buffer.from('I am alice, and I am online');
    const sig = alice.sign(assertion);

    // Alice sends to Bob:
    //   - Her public identity key (hex)
    //   - The assertion bytes
    //   - The signature
    const alicePublicHex = alice.toPublic().toHex();

    // ── Bob (receiver) ────────────────────────────────────────────────
    const alicePubReconstructed = PublicIdentityKey.fromHex(alicePublicHex);

    // Bob verifies that Alice signed this assertion
    expect(alicePubReconstructed.verifyBool(assertion, sig)).toBe(true);

    // Bob would reject anything else
    expect(
      alicePubReconstructed.verifyBool(Buffer.from('I am bob'), sig),
    ).toBe(false);
  });

  it('Identity key can sign multiple distinct ephemeral keys', () => {
    const alice = IdentityKeyPair.generate();

    // Each ephemeral has a unique 32-byte fake-pubkey
    const eph1 = Buffer.alloc(32, 0x11);
    const eph2 = Buffer.alloc(32, 0x22);
    const eph3 = Buffer.alloc(32, 0x33);

    const sig1 = alice.sign(eph1);
    const sig2 = alice.sign(eph2);
    const sig3 = alice.sign(eph3);

    const pub = alice.toPublic();
    expect(pub.verifyBool(eph1, sig1)).toBe(true);
    expect(pub.verifyBool(eph2, sig2)).toBe(true);
    expect(pub.verifyBool(eph3, sig3)).toBe(true);

    // Cross-checks fail
    expect(pub.verifyBool(eph1, sig2)).toBe(false);
    expect(pub.verifyBool(eph2, sig3)).toBe(false);
  });
});
