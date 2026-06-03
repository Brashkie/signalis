import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';

import {
  MessageHeader,
  isMessageHeader,
  SkippedMessageKeys,
  MAX_SKIPPED_MESSAGE_KEYS,
  ValidationError,
  SerializationError,
  ProtocolError,
  crypto,
} from '../src';
import { asPublicKey, asMessageKey } from '../src/types';

// ═══════════════════════════════════════════════════════════════════════════
// MessageHeader
// ═══════════════════════════════════════════════════════════════════════════

describe('MessageHeader', () => {
  const validPub = asPublicKey(Buffer.alloc(32, 0xaa));

  describe('constructor', () => {
    it('builds with valid fields', () => {
      const h = new MessageHeader({ dhPublicKey: validPub, n: 5, pn: 3 });
      expect(h.n).toBe(5);
      expect(h.pn).toBe(3);
      expect(h.dhPublicKey.length).toBe(32);
    });

    it('accepts Uint8Array for dhPublicKey', () => {
      const h = new MessageHeader({
        dhPublicKey: new Uint8Array(32),
        n: 0,
        pn: 0,
      });
      expect(h.dhPublicKey.length).toBe(32);
    });

    it('rejects wrong dhPublicKey size', () => {
      expect(() =>
        new MessageHeader({ dhPublicKey: Buffer.alloc(10), n: 0, pn: 0 }),
      ).toThrow(ValidationError);
    });

    it('rejects negative n', () => {
      expect(() =>
        new MessageHeader({ dhPublicKey: validPub, n: -1, pn: 0 }),
      ).toThrow(ValidationError);
    });

    it('rejects non-integer n', () => {
      expect(() =>
        new MessageHeader({ dhPublicKey: validPub, n: 1.5, pn: 0 }),
      ).toThrow(ValidationError);
    });

    it('rejects n > uint32 max', () => {
      expect(() =>
        new MessageHeader({ dhPublicKey: validPub, n: 0xffffffff + 1, pn: 0 }),
      ).toThrow(ValidationError);
    });

    it('rejects negative pn', () => {
      expect(() =>
        new MessageHeader({ dhPublicKey: validPub, n: 0, pn: -1 }),
      ).toThrow(ValidationError);
    });

    it('rejects non-integer pn', () => {
      expect(() =>
        new MessageHeader({ dhPublicKey: validPub, n: 0, pn: 1.5 }),
      ).toThrow(ValidationError);
    });

    it('rejects pn > uint32 max', () => {
      expect(() =>
        new MessageHeader({ dhPublicKey: validPub, n: 0, pn: 0xffffffff + 1 }),
      ).toThrow(ValidationError);
    });

    it('instance is frozen', () => {
      const h = new MessageHeader({ dhPublicKey: validPub, n: 0, pn: 0 });
      expect(Object.isFrozen(h)).toBe(true);
    });
  });

  // ─── Binary wire format ──────────────────────────────────────────────

  describe('toBytes / fromBytes', () => {
    it('round-trips through binary format', () => {
      const original = new MessageHeader({ dhPublicKey: validPub, n: 42, pn: 17 });
      const bytes = original.toBytes();
      expect(bytes.length).toBe(32 + 4 + 4); // 40

      const restored = MessageHeader.fromBytes(bytes);
      expect(restored.dhPublicKey.equals(original.dhPublicKey)).toBe(true);
      expect(restored.n).toBe(42);
      expect(restored.pn).toBe(17);
    });

    it('encodes n and pn as uint32 BE', () => {
      const h = new MessageHeader({ dhPublicKey: validPub, n: 0x01020304, pn: 0 });
      const bytes = h.toBytes();

      // Bytes 32-35 should be [01, 02, 03, 04] (BE)
      expect(bytes[32]).toBe(0x01);
      expect(bytes[33]).toBe(0x02);
      expect(bytes[34]).toBe(0x03);
      expect(bytes[35]).toBe(0x04);
    });

    it('fromBytes rejects wrong length', () => {
      expect(() => MessageHeader.fromBytes(Buffer.alloc(20))).toThrow(SerializationError);
      expect(() => MessageHeader.fromBytes(Buffer.alloc(50))).toThrow(SerializationError);
    });

    it('fromBytes rejects non-Buffer', () => {
      expect(() => MessageHeader.fromBytes('string' as never)).toThrow(SerializationError);
    });
  });

  // ─── JSON wire format ────────────────────────────────────────────────

  describe('toPayload / fromPayload', () => {
    it('round-trips through JSON format', () => {
      const original = new MessageHeader({ dhPublicKey: validPub, n: 99, pn: 50 });
      const payload = original.toPayload();
      const restored = MessageHeader.fromPayload(payload);

      expect(restored.n).toBe(99);
      expect(restored.pn).toBe(50);
      expect(restored.dhPublicKey.equals(original.dhPublicKey)).toBe(true);
    });

    it('fromPayload rejects null', () => {
      expect(() => MessageHeader.fromPayload(null)).toThrow(SerializationError);
    });

    it('fromPayload rejects non-object', () => {
      expect(() => MessageHeader.fromPayload('string')).toThrow(SerializationError);
    });

    it('fromPayload rejects non-string dhPublicKey', () => {
      expect(() =>
        MessageHeader.fromPayload({ dhPublicKey: 123, n: 0, pn: 0 }),
      ).toThrow(SerializationError);
    });

    it('fromPayload rejects non-number n', () => {
      expect(() =>
        MessageHeader.fromPayload({ dhPublicKey: 'a'.repeat(64), n: '0', pn: 0 }),
      ).toThrow(SerializationError);
    });

    it('fromPayload rejects non-number pn', () => {
      expect(() =>
        MessageHeader.fromPayload({ dhPublicKey: 'a'.repeat(64), n: 0, pn: '0' }),
      ).toThrow(SerializationError);
    });

    it('fromPayload rejects bad hex', () => {
      expect(() =>
        MessageHeader.fromPayload({ dhPublicKey: 'ZZZ', n: 0, pn: 0 }),
      ).toThrow(SerializationError);
    });

    it('fromPayload rejects wrong dhPublicKey size', () => {
      expect(() =>
        MessageHeader.fromPayload({ dhPublicKey: 'aa', n: 0, pn: 0 }),
      ).toThrow(SerializationError);
    });
  });

  // ─── Safe output ─────────────────────────────────────────────────────

  describe('safe output', () => {
    it('toString includes n and pn', () => {
      const h = new MessageHeader({ dhPublicKey: validPub, n: 5, pn: 3 });
      expect(h.toString()).toMatch(/MessageHeader\(dh=.*\.\.\., n=5, pn=3\)/);
    });

    it('toJSON includes summary', () => {
      const h = new MessageHeader({ dhPublicKey: validPub, n: 1, pn: 2 });
      const json = h.toJSON();
      expect(json.type).toBe('MessageHeader');
      expect(json.n).toBe(1);
      expect(json.pn).toBe(2);
    });

    it('util.inspect returns safe representation', () => {
      const h = new MessageHeader({ dhPublicKey: validPub, n: 0, pn: 0 });
      const i = inspect(h);
      expect(i).toMatch(/MessageHeader\(/);
    });
  });

  // ─── Type guard ──────────────────────────────────────────────────────

  it('isMessageHeader works', () => {
    const h = new MessageHeader({ dhPublicKey: validPub, n: 0, pn: 0 });
    expect(isMessageHeader(h)).toBe(true);
    expect(isMessageHeader({})).toBe(false);
    expect(isMessageHeader(null)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SkippedMessageKeys
// ═══════════════════════════════════════════════════════════════════════════

describe('SkippedMessageKeys', () => {
  const dh1 = asPublicKey(Buffer.alloc(32, 0x01));
  const dh2 = asPublicKey(Buffer.alloc(32, 0x02));
  const mk1 = asMessageKey(crypto.randomBytes(32));
  const mk2 = asMessageKey(crypto.randomBytes(32));

  describe('basic ops', () => {
    it('starts empty', () => {
      const cache = new SkippedMessageKeys();
      expect(cache.size).toBe(0);
    });

    it('uses default maxKeys = MAX_SKIPPED_MESSAGE_KEYS', () => {
      const cache = new SkippedMessageKeys();
      expect(cache.maxKeys).toBe(MAX_SKIPPED_MESSAGE_KEYS);
    });

    it('respects custom maxKeys', () => {
      const cache = new SkippedMessageKeys(100);
      expect(cache.maxKeys).toBe(100);
    });

    it('rejects invalid maxKeys', () => {
      expect(() => new SkippedMessageKeys(0)).toThrow(ValidationError);
      expect(() => new SkippedMessageKeys(-1)).toThrow(ValidationError);
      expect(() => new SkippedMessageKeys(1.5)).toThrow(ValidationError);
    });

    it('set + has + take work', () => {
      const cache = new SkippedMessageKeys();
      cache.set(dh1, 5, mk1);

      expect(cache.has(dh1, 5)).toBe(true);
      expect(cache.has(dh1, 6)).toBe(false);
      expect(cache.size).toBe(1);

      const got = cache.take(dh1, 5);
      expect(got?.equals(mk1)).toBe(true);
      expect(cache.size).toBe(0);
      expect(cache.has(dh1, 5)).toBe(false);
    });

    it('take returns null for missing key', () => {
      const cache = new SkippedMessageKeys();
      expect(cache.take(dh1, 999)).toBe(null);
    });

    it('different (dhPub, counter) tuples are separate entries', () => {
      const cache = new SkippedMessageKeys();
      cache.set(dh1, 5, mk1);
      cache.set(dh2, 5, mk2);  // same counter, different DH
      cache.set(dh1, 6, mk2);  // same DH, different counter

      expect(cache.size).toBe(3);
      expect(cache.take(dh1, 5)?.equals(mk1)).toBe(true);
      expect(cache.take(dh2, 5)?.equals(mk2)).toBe(true);
      expect(cache.take(dh1, 6)?.equals(mk2)).toBe(true);
    });

    it('updating existing key does not double-count size', () => {
      const cache = new SkippedMessageKeys();
      cache.set(dh1, 5, mk1);
      cache.set(dh1, 5, mk2); // same key, new value

      expect(cache.size).toBe(1);
      expect(cache.take(dh1, 5)?.equals(mk2)).toBe(true);
    });

    it('clear() empties the cache', () => {
      const cache = new SkippedMessageKeys();
      cache.set(dh1, 1, mk1);
      cache.set(dh1, 2, mk2);
      cache.clear();
      expect(cache.size).toBe(0);
    });
  });

  // ─── Validation ──────────────────────────────────────────────────────

  describe('set() validation', () => {
    const cache = new SkippedMessageKeys();

    it('rejects negative counter', () => {
      expect(() => cache.set(dh1, -1, mk1)).toThrow(ValidationError);
    });

    it('rejects non-integer counter', () => {
      expect(() => cache.set(dh1, 1.5, mk1)).toThrow(ValidationError);
    });

    it('rejects non-Buffer messageKey', () => {
      expect(() => cache.set(dh1, 0, 'string' as never)).toThrow(ValidationError);
    });
  });

  // ─── FIFO eviction ───────────────────────────────────────────────────

  describe('FIFO eviction at capacity', () => {
    it('evicts oldest when adding beyond maxKeys', () => {
      const cache = new SkippedMessageKeys(3);

      cache.set(dh1, 0, mk1);
      cache.set(dh1, 1, mk1);
      cache.set(dh1, 2, mk1);
      expect(cache.size).toBe(3);

      // Add a 4th — counter=0 (oldest) should be evicted
      cache.set(dh1, 3, mk1);
      expect(cache.size).toBe(3);
      expect(cache.has(dh1, 0)).toBe(false);
      expect(cache.has(dh1, 1)).toBe(true);
      expect(cache.has(dh1, 2)).toBe(true);
      expect(cache.has(dh1, 3)).toBe(true);
    });

    it('does not evict when updating existing key', () => {
      const cache = new SkippedMessageKeys(2);
      cache.set(dh1, 0, mk1);
      cache.set(dh1, 1, mk1);
      cache.set(dh1, 0, mk2); // update existing
      expect(cache.size).toBe(2);
      expect(cache.has(dh1, 0)).toBe(true);
      expect(cache.has(dh1, 1)).toBe(true);
    });
  });

  // ─── Anti-DoS ────────────────────────────────────────────────────────

  describe('assertCanAdd (anti-DoS)', () => {
    it('passes for counts <= maxKeys', () => {
      const cache = new SkippedMessageKeys(100);
      expect(() => cache.assertCanAdd(0)).not.toThrow();
      expect(() => cache.assertCanAdd(50)).not.toThrow();
      expect(() => cache.assertCanAdd(100)).not.toThrow();
    });

    it('throws ProtocolError for counts > maxKeys', () => {
      const cache = new SkippedMessageKeys(100);
      expect(() => cache.assertCanAdd(101)).toThrow(ProtocolError);
      expect(() => cache.assertCanAdd(1_000_000)).toThrow(ProtocolError);
    });

    it('throws ValidationError on invalid count', () => {
      const cache = new SkippedMessageKeys();
      expect(() => cache.assertCanAdd(-1)).toThrow(ValidationError);
      expect(() => cache.assertCanAdd(1.5)).toThrow(ValidationError);
    });
  });

  // ─── entries() ───────────────────────────────────────────────────────

  describe('entries()', () => {
    it('returns insertion-ordered list', () => {
      const cache = new SkippedMessageKeys();
      cache.set(dh1, 0, mk1);
      cache.set(dh2, 5, mk2);

      const entries = cache.entries();
      expect(entries).toHaveLength(2);
      expect(entries[0]!.counter).toBe(0);
      expect(entries[1]!.counter).toBe(5);
      expect(entries[0]!.messageKey.equals(mk1)).toBe(true);
    });

    it('returns empty array when empty', () => {
      const cache = new SkippedMessageKeys();
      expect(cache.entries()).toEqual([]);
    });
  });

  // ─── Safe output ─────────────────────────────────────────────────────

  describe('safe output', () => {
    it('toString includes size and max', () => {
      const cache = new SkippedMessageKeys(500);
      cache.set(dh1, 0, mk1);
      expect(cache.toString()).toBe('SkippedMessageKeys(size=1, max=500)');
    });

    it('toJSON includes summary', () => {
      const cache = new SkippedMessageKeys();
      expect(cache.toJSON().type).toBe('SkippedMessageKeys');
    });

    it('util.inspect returns safe rep', () => {
      const cache = new SkippedMessageKeys();
      expect(inspect(cache)).toMatch(/SkippedMessageKeys\(/);
    });
  });
});
