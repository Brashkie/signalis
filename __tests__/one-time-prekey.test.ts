import { describe, it, expect } from 'vitest';
import {
  OneTimePreKey,
  PublicOneTimePreKey,
  isOneTimePreKey,
  isPublicOneTimePreKey,
} from '../src/prekeys';
import { PreKeyError, ValidationError, SerializationError } from '../src/errors';
import {
  MAX_PREKEY_ID,
  MIN_PREKEY_ID,
  MAX_ONE_TIME_PREKEYS,
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
} from '../src/constants';

describe('OneTimePreKey', () => {
  // ═══════════════════════════════════════════════════════════════════
  // Generation
  // ═══════════════════════════════════════════════════════════════════

  describe('generate()', () => {
    it('creates a key with the given id', () => {
      const otpk = OneTimePreKey.generate(1);
      expect(otpk.id).toBe(1);
    });

    it('public and private keys are 32 bytes', () => {
      const otpk = OneTimePreKey.generate(1);
      expect(otpk.publicKey.length).toBe(PUBLIC_KEY_SIZE);
      expect(otpk.privateKey.length).toBe(PRIVATE_KEY_SIZE);
    });

    it('different calls produce different keys', () => {
      const a = OneTimePreKey.generate(1);
      const b = OneTimePreKey.generate(1);
      expect(a.publicKey.equals(b.publicKey)).toBe(false);
      expect(a.privateKey.equals(b.privateKey)).toBe(false);
    });

    it('accepts MIN_PREKEY_ID', () => {
      const otpk = OneTimePreKey.generate(MIN_PREKEY_ID);
      expect(otpk.id).toBe(MIN_PREKEY_ID);
    });

    it('accepts MAX_PREKEY_ID', () => {
      const otpk = OneTimePreKey.generate(MAX_PREKEY_ID);
      expect(otpk.id).toBe(MAX_PREKEY_ID);
    });

    it('rejects id 0', () => {
      expect(() => OneTimePreKey.generate(0)).toThrow(PreKeyError);
    });

    it('rejects negative id', () => {
      expect(() => OneTimePreKey.generate(-1)).toThrow(PreKeyError);
    });

    it('rejects id > MAX_PREKEY_ID', () => {
      expect(() => OneTimePreKey.generate(MAX_PREKEY_ID + 1)).toThrow(PreKeyError);
    });

    it('rejects non-integer id', () => {
      expect(() => OneTimePreKey.generate(1.5)).toThrow(PreKeyError);
    });

    it('rejects non-number id', () => {
      expect(() =>
        OneTimePreKey.generate('1' as unknown as number),
      ).toThrow(PreKeyError);
    });

    it('instance is frozen', () => {
      const otpk = OneTimePreKey.generate(1);
      expect(Object.isFrozen(otpk)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Batch
  // ═══════════════════════════════════════════════════════════════════

  describe('generateBatch()', () => {
    it('generates the requested count', () => {
      const batch = OneTimePreKey.generateBatch(1, 10);
      expect(batch).toHaveLength(10);
    });

    it('assigns contiguous IDs', () => {
      const batch = OneTimePreKey.generateBatch(100, 5);
      expect(batch.map((k) => k.id)).toEqual([100, 101, 102, 103, 104]);
    });

    it('each key is unique', () => {
      const batch = OneTimePreKey.generateBatch(1, 20);
      const pubKeys = new Set(batch.map((k) => k.publicKey.toString('hex')));
      expect(pubKeys.size).toBe(20);
    });

    it('handles batch of 1', () => {
      const batch = OneTimePreKey.generateBatch(1, 1);
      expect(batch).toHaveLength(1);
    });

    it('handles MAX_ONE_TIME_PREKEYS', () => {
      const batch = OneTimePreKey.generateBatch(1, MAX_ONE_TIME_PREKEYS);
      expect(batch).toHaveLength(MAX_ONE_TIME_PREKEYS);
    });

    it('rejects count = 0', () => {
      expect(() => OneTimePreKey.generateBatch(1, 0)).toThrow(ValidationError);
    });

    it('rejects negative count', () => {
      expect(() => OneTimePreKey.generateBatch(1, -1)).toThrow(ValidationError);
    });

    it('rejects count > MAX_ONE_TIME_PREKEYS', () => {
      expect(() =>
        OneTimePreKey.generateBatch(1, MAX_ONE_TIME_PREKEYS + 1),
      ).toThrow(ValidationError);
    });

    it('rejects non-integer count', () => {
      expect(() => OneTimePreKey.generateBatch(1, 1.5)).toThrow(ValidationError);
    });

    it('rejects batch exceeding MAX_PREKEY_ID', () => {
      expect(() =>
        OneTimePreKey.generateBatch(MAX_PREKEY_ID, 2),
      ).toThrow(PreKeyError);
    });

    it('rejects invalid startId', () => {
      expect(() => OneTimePreKey.generateBatch(0, 1)).toThrow(PreKeyError);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // fromKeys
  // ═══════════════════════════════════════════════════════════════════

  describe('fromKeys()', () => {
    it('reconstructs from existing keys', () => {
      const original = OneTimePreKey.generate(7);
      const reconstructed = OneTimePreKey.fromKeys(
        original.id,
        original.publicKey,
        original.privateKey,
      );
      expect(reconstructed.equals(original)).toBe(true);
    });

    it('accepts Uint8Array', () => {
      const pub = new Uint8Array(32);
      const priv = new Uint8Array(32);
      const otpk = OneTimePreKey.fromKeys(1, pub, priv);
      expect(otpk.id).toBe(1);
    });

    it('rejects wrong public key size', () => {
      expect(() =>
        OneTimePreKey.fromKeys(1, Buffer.alloc(10), Buffer.alloc(32)),
      ).toThrow(ValidationError);
    });

    it('rejects wrong private key size', () => {
      expect(() =>
        OneTimePreKey.fromKeys(1, Buffer.alloc(32), Buffer.alloc(10)),
      ).toThrow(ValidationError);
    });

    it('rejects invalid id', () => {
      expect(() =>
        OneTimePreKey.fromKeys(0, Buffer.alloc(32), Buffer.alloc(32)),
      ).toThrow(PreKeyError);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Serialization
  // ═══════════════════════════════════════════════════════════════════

  describe('serialize / deserialize round-trip', () => {
    it('round-trips correctly', () => {
      const original = OneTimePreKey.generate(42);
      const data = original.serialize();
      const restored = OneTimePreKey.deserialize(data);

      expect(restored.id).toBe(original.id);
      expect(restored.publicKey.equals(original.publicKey)).toBe(true);
      expect(restored.privateKey.equals(original.privateKey)).toBe(true);
    });

    it('serialize includes id, publicKey, privateKey as hex', () => {
      const otpk = OneTimePreKey.generate(1);
      const data = otpk.serialize();

      expect(data.id).toBe(1);
      expect(typeof data.publicKey).toBe('string');
      expect(typeof data.privateKey).toBe('string');
      expect(data.publicKey).toMatch(/^[0-9a-fA-F]{64}$/);
      expect(data.privateKey).toMatch(/^[0-9a-fA-F]{64}$/);
    });

    it('deserialize rejects null', () => {
      expect(() => OneTimePreKey.deserialize(null)).toThrow(SerializationError);
    });

    it('deserialize rejects missing fields', () => {
      expect(() => OneTimePreKey.deserialize({})).toThrow(SerializationError);
      expect(() => OneTimePreKey.deserialize({ id: 1 })).toThrow(SerializationError);
      expect(() =>
        OneTimePreKey.deserialize({ id: 1, publicKey: 'a'.repeat(64) }),
      ).toThrow(SerializationError);
    });

    it('deserialize rejects bad hex', () => {
      expect(() =>
        OneTimePreKey.deserialize({
          id: 1,
          publicKey: 'ZZZ',
          privateKey: 'a'.repeat(64),
        }),
      ).toThrow(SerializationError);
    });

    it('deserialize rejects wrong key size', () => {
      expect(() =>
        OneTimePreKey.deserialize({
          id: 1,
          publicKey: 'aa',
          privateKey: 'a'.repeat(64),
        }),
      ).toThrow(SerializationError);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // toPublic
  // ═══════════════════════════════════════════════════════════════════

  describe('toPublic()', () => {
    it('returns a PublicOneTimePreKey with same id and public key', () => {
      const otpk = OneTimePreKey.generate(99);
      const pub = otpk.toPublic();

      expect(pub).toBeInstanceOf(PublicOneTimePreKey);
      expect(pub.id).toBe(99);
      expect(pub.publicKey.equals(otpk.publicKey)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Comparison
  // ═══════════════════════════════════════════════════════════════════

  describe('equals()', () => {
    it('matches identical key', () => {
      const a = OneTimePreKey.generate(1);
      const b = OneTimePreKey.fromKeys(a.id, a.publicKey, a.privateKey);
      expect(a.equals(b)).toBe(true);
    });

    it('does not match different id', () => {
      const a = OneTimePreKey.generate(1);
      const b = OneTimePreKey.fromKeys(2, a.publicKey, a.privateKey);
      expect(a.equals(b)).toBe(false);
    });

    it('does not match different key', () => {
      const a = OneTimePreKey.generate(1);
      const b = OneTimePreKey.generate(1);
      expect(a.equals(b)).toBe(false);
    });

    it('does not match null/undefined', () => {
      const a = OneTimePreKey.generate(1);
      expect(a.equals(null)).toBe(false);
      expect(a.equals(undefined)).toBe(false);
    });

    it('cross-compare with PublicOneTimePreKey', () => {
      const otpk = OneTimePreKey.generate(1);
      expect(otpk.equals(otpk.toPublic())).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Safe Output
  // ═══════════════════════════════════════════════════════════════════

  describe('safe output (no private key leak)', () => {
    it('toString does not expose private key', () => {
      const otpk = OneTimePreKey.generate(1);
      const s = otpk.toString();
      expect(s).not.toContain(otpk.privateKey.toString('hex'));
    });

    it('toJSON does not include private key', () => {
      const otpk = OneTimePreKey.generate(1);
      const json = otpk.toJSON();
      expect(json).not.toHaveProperty('privateKey');
      expect(JSON.stringify(json)).not.toContain(otpk.privateKey.toString('hex'));
    });

    it('inspect does not expose private key', () => {
      const otpk = OneTimePreKey.generate(1);
      const inspected = otpk[Symbol.for('nodejs.util.inspect.custom')]();
      expect(inspected).not.toContain(otpk.privateKey.toString('hex'));
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// PublicOneTimePreKey
// ═══════════════════════════════════════════════════════════════════════════

describe('PublicOneTimePreKey', () => {
  it('constructs from Buffer', () => {
    const pub = new PublicOneTimePreKey(1, Buffer.alloc(32));
    expect(pub.id).toBe(1);
  });

  it('rejects invalid id', () => {
    expect(() => new PublicOneTimePreKey(0, Buffer.alloc(32))).toThrow(PreKeyError);
  });

  describe('fromHex()', () => {
    it('parses valid hex', () => {
      const hex = 'a'.repeat(64);
      const pub = PublicOneTimePreKey.fromHex(1, hex);
      expect(pub.publicKey.toString('hex')).toBe(hex);
    });

    it('rejects bad hex', () => {
      expect(() => PublicOneTimePreKey.fromHex(1, 'ZZZ')).toThrow(ValidationError);
    });

    it('rejects wrong size', () => {
      expect(() => PublicOneTimePreKey.fromHex(1, 'aa')).toThrow(ValidationError);
    });

    it('rejects non-string', () => {
      expect(() =>
        PublicOneTimePreKey.fromHex(1, 123 as unknown as string),
      ).toThrow(ValidationError);
    });
  });

  it('toHex returns hex string', () => {
    const otpk = OneTimePreKey.generate(1);
    const pub = otpk.toPublic();
    expect(pub.toHex()).toBe(otpk.publicKey.toString('hex'));
  });

  it('equals matches public twin', () => {
    const otpk = OneTimePreKey.generate(1);
    expect(otpk.toPublic().equals(otpk)).toBe(true);
  });

  it('toString and toJSON are safe', () => {
    const pub = OneTimePreKey.generate(1).toPublic();
    expect(pub.toString()).toMatch(/PublicOneTimePreKey\(id=1, public=/);
    expect(pub.toJSON().type).toBe('PublicOneTimePreKey');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards
// ═══════════════════════════════════════════════════════════════════════════

describe('Type Guards', () => {
  it('isOneTimePreKey', () => {
    expect(isOneTimePreKey(OneTimePreKey.generate(1))).toBe(true);
    expect(isOneTimePreKey(OneTimePreKey.generate(1).toPublic())).toBe(false);
    expect(isOneTimePreKey(null)).toBe(false);
    expect(isOneTimePreKey({})).toBe(false);
  });

  it('isPublicOneTimePreKey', () => {
    expect(isPublicOneTimePreKey(OneTimePreKey.generate(1).toPublic())).toBe(true);
    expect(isPublicOneTimePreKey(OneTimePreKey.generate(1))).toBe(false);
    expect(isPublicOneTimePreKey(null)).toBe(false);
  });
});
