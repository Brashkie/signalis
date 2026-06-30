/**
 * ProtocolAddress tests
 */

import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';

import {
  ProtocolAddress,
  isProtocolAddress,
  MAX_USER_ID_LENGTH,
  MAX_DEVICE_ID,
  ValidationError,
} from '../src';

describe('ProtocolAddress — construction', () => {
  it('creates a valid address', () => {
    const a = new ProtocolAddress('alice@example.com', 1);
    expect(a.userId).toBe('alice@example.com');
    expect(a.deviceId).toBe(1);
  });

  it('accepts deviceId 0 (main device)', () => {
    expect(() => new ProtocolAddress('alice', 0)).not.toThrow();
  });

  it('accepts MAX_DEVICE_ID', () => {
    expect(() => new ProtocolAddress('alice', MAX_DEVICE_ID)).not.toThrow();
  });

  it('rejects non-string userId', () => {
    expect(() => new ProtocolAddress(42 as never, 1)).toThrow(ValidationError);
  });

  it('rejects empty userId', () => {
    expect(() => new ProtocolAddress('', 1)).toThrow(ValidationError);
  });

  it('rejects userId longer than max', () => {
    const long = 'a'.repeat(MAX_USER_ID_LENGTH + 1);
    expect(() => new ProtocolAddress(long, 1)).toThrow(ValidationError);
  });

  it('rejects userId with forward slash', () => {
    expect(() => new ProtocolAddress('alice/bob', 1)).toThrow(ValidationError);
  });

  it('rejects userId with backslash', () => {
    expect(() => new ProtocolAddress('alice\\bob', 1)).toThrow(ValidationError);
  });

  it('rejects userId with control characters', () => {
    expect(() => new ProtocolAddress('alice\x00', 1)).toThrow(ValidationError);
    expect(() => new ProtocolAddress('alice\x1f', 1)).toThrow(ValidationError);
  });

  it('rejects userId with shell-meta', () => {
    expect(() => new ProtocolAddress('alice*', 1)).toThrow(ValidationError);
    expect(() => new ProtocolAddress('a"b', 1)).toThrow(ValidationError);
    expect(() => new ProtocolAddress('a|b', 1)).toThrow(ValidationError);
    expect(() => new ProtocolAddress('a:b', 1)).toThrow(ValidationError);
  });

  it('rejects non-integer deviceId', () => {
    expect(() => new ProtocolAddress('alice', 1.5)).toThrow(ValidationError);
  });

  it('rejects negative deviceId', () => {
    expect(() => new ProtocolAddress('alice', -1)).toThrow(ValidationError);
  });

  it('rejects deviceId > MAX', () => {
    expect(() => new ProtocolAddress('alice', MAX_DEVICE_ID + 1)).toThrow(ValidationError);
  });

  it('is immutable (frozen)', () => {
    const a = new ProtocolAddress('alice', 1);
    expect(Object.isFrozen(a)).toBe(true);
  });
});

describe('ProtocolAddress — toString / equality', () => {
  it('toString uses canonical format', () => {
    const a = new ProtocolAddress('alice@example.com', 1);
    expect(a.toString()).toBe('alice@example.com.1');
  });

  it('toString works with deviceId 0', () => {
    expect(new ProtocolAddress('alice', 0).toString()).toBe('alice.0');
  });

  it('equals returns true for same fields', () => {
    const a = new ProtocolAddress('alice', 1);
    const b = new ProtocolAddress('alice', 1);
    expect(a.equals(b)).toBe(true);
  });

  it('equals returns false for different userId', () => {
    const a = new ProtocolAddress('alice', 1);
    const b = new ProtocolAddress('bob', 1);
    expect(a.equals(b)).toBe(false);
  });

  it('equals returns false for different deviceId', () => {
    const a = new ProtocolAddress('alice', 1);
    const b = new ProtocolAddress('alice', 2);
    expect(a.equals(b)).toBe(false);
  });

  it('equals returns false for non-ProtocolAddress', () => {
    const a = new ProtocolAddress('alice', 1);
    expect(a.equals(null as never)).toBe(false);
    expect(a.equals({} as never)).toBe(false);
    expect(a.equals('alice.1' as never)).toBe(false);
  });
});

describe('ProtocolAddress — parse', () => {
  it('parses canonical form', () => {
    const a = ProtocolAddress.parse('alice@example.com.1');
    expect(a.userId).toBe('alice@example.com');
    expect(a.deviceId).toBe(1);
  });

  it('parses with deviceId 0', () => {
    const a = ProtocolAddress.parse('alice.0');
    expect(a.deviceId).toBe(0);
  });

  it('round-trips toString → parse', () => {
    const original = new ProtocolAddress('alice@signal.org', 42);
    const parsed = ProtocolAddress.parse(original.toString());
    expect(parsed.equals(original)).toBe(true);
  });

  it('uses LAST dot as separator (userId with dots OK)', () => {
    const a = ProtocolAddress.parse('alice.smith.42');
    expect(a.userId).toBe('alice.smith');
    expect(a.deviceId).toBe(42);
  });

  it('rejects malformed: no dot', () => {
    expect(() => ProtocolAddress.parse('alice')).toThrow(ValidationError);
  });

  it('rejects malformed: starts with dot', () => {
    expect(() => ProtocolAddress.parse('.1')).toThrow(ValidationError);
  });

  it('rejects malformed: ends with dot', () => {
    expect(() => ProtocolAddress.parse('alice.')).toThrow(ValidationError);
  });

  it('rejects malformed: non-numeric deviceId', () => {
    expect(() => ProtocolAddress.parse('alice.abc')).toThrow(ValidationError);
  });

  it('rejects non-string input', () => {
    expect(() => ProtocolAddress.parse(42 as never)).toThrow(ValidationError);
  });
});

describe('ProtocolAddress — serialization / inspect', () => {
  it('toJSON returns POJO', () => {
    const a = new ProtocolAddress('alice', 1);
    expect(a.toJSON()).toEqual({ userId: 'alice', deviceId: 1 });
  });

  it('inspect returns readable form', () => {
    const a = new ProtocolAddress('alice', 1);
    expect(inspect(a)).toContain('ProtocolAddress(alice.1)');
  });
});

describe('isProtocolAddress', () => {
  it('returns true for ProtocolAddress', () => {
    expect(isProtocolAddress(new ProtocolAddress('a', 0))).toBe(true);
  });

  it('returns false for non-ProtocolAddress', () => {
    expect(isProtocolAddress({})).toBe(false);
    expect(isProtocolAddress(null)).toBe(false);
    expect(isProtocolAddress('alice.1')).toBe(false);
  });
});
