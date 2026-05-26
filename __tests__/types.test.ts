import { describe, it, expect } from 'vitest';
import {
  asPublicKey,
  asPrivateKey,
  asSignature,
  asSharedSecret,
  asChainKey,
  asMessageKey,
  asRootKey,
  isPublicKey,
  isPrivateKey,
  isSignature,
} from '../src/types';
import { ValidationError } from '../src/errors';

describe('Branded Type Constructors', () => {
  describe('asPublicKey', () => {
    it('accepts 32-byte Buffer', () => {
      const buf = Buffer.alloc(32);
      expect(() => asPublicKey(buf)).not.toThrow();
    });

    it('throws on wrong size', () => {
      expect(() => asPublicKey(Buffer.alloc(31))).toThrow(ValidationError);
      expect(() => asPublicKey(Buffer.alloc(33))).toThrow(ValidationError);
      expect(() => asPublicKey(Buffer.alloc(0))).toThrow(ValidationError);
    });

    it('throws on non-Buffer', () => {
      expect(() => asPublicKey('string')).toThrow(ValidationError);
      expect(() => asPublicKey(123)).toThrow(ValidationError);
      expect(() => asPublicKey(null)).toThrow(ValidationError);
      expect(() => asPublicKey(undefined)).toThrow(ValidationError);
      expect(() => asPublicKey({})).toThrow(ValidationError);
    });
  });

  describe('asPrivateKey', () => {
    it('accepts 32-byte Buffer', () => {
      const buf = Buffer.alloc(32);
      expect(() => asPrivateKey(buf)).not.toThrow();
    });

    it('throws on wrong size', () => {
      expect(() => asPrivateKey(Buffer.alloc(31))).toThrow(ValidationError);
    });

    it('throws on non-Buffer', () => {
      expect(() => asPrivateKey('string')).toThrow(ValidationError);
    });
  });

  describe('asSignature', () => {
    it('accepts 64-byte Buffer', () => {
      const buf = Buffer.alloc(64);
      expect(() => asSignature(buf)).not.toThrow();
    });

    it('throws on wrong size', () => {
      expect(() => asSignature(Buffer.alloc(32))).toThrow(ValidationError);
      expect(() => asSignature(Buffer.alloc(63))).toThrow(ValidationError);
    });
  });

  describe('asSharedSecret', () => {
    it('accepts 32-byte Buffer', () => {
      expect(() => asSharedSecret(Buffer.alloc(32))).not.toThrow();
    });

    it('throws on wrong size', () => {
      expect(() => asSharedSecret(Buffer.alloc(31))).toThrow(ValidationError);
    });
  });

  describe('asChainKey', () => {
    it('accepts 32-byte Buffer', () => {
      expect(() => asChainKey(Buffer.alloc(32))).not.toThrow();
    });

    it('throws on wrong size', () => {
      expect(() => asChainKey(Buffer.alloc(31))).toThrow(ValidationError);
    });
  });

  describe('asMessageKey', () => {
    it('accepts 32-byte Buffer', () => {
      expect(() => asMessageKey(Buffer.alloc(32))).not.toThrow();
    });
  });

  describe('asRootKey', () => {
    it('accepts 32-byte Buffer', () => {
      expect(() => asRootKey(Buffer.alloc(32))).not.toThrow();
    });
  });
});

describe('Type Guards', () => {
  describe('isPublicKey', () => {
    it('returns true for 32-byte Buffer', () => {
      expect(isPublicKey(Buffer.alloc(32))).toBe(true);
    });

    it('returns false for wrong size', () => {
      expect(isPublicKey(Buffer.alloc(31))).toBe(false);
      expect(isPublicKey(Buffer.alloc(64))).toBe(false);
    });

    it('returns false for non-Buffer', () => {
      expect(isPublicKey('string')).toBe(false);
      expect(isPublicKey(null)).toBe(false);
      expect(isPublicKey(undefined)).toBe(false);
      expect(isPublicKey(123)).toBe(false);
    });
  });

  describe('isPrivateKey', () => {
    it('returns true for 32-byte Buffer', () => {
      expect(isPrivateKey(Buffer.alloc(32))).toBe(true);
    });

    it('returns false for wrong size', () => {
      expect(isPrivateKey(Buffer.alloc(31))).toBe(false);
    });
  });

  describe('isSignature', () => {
    it('returns true for 64-byte Buffer', () => {
      expect(isSignature(Buffer.alloc(64))).toBe(true);
    });

    it('returns false for wrong size', () => {
      expect(isSignature(Buffer.alloc(32))).toBe(false);
    });

    it('returns false for non-Buffer', () => {
      expect(isSignature(null)).toBe(false);
    });
  });
});
