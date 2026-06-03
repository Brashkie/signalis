import { describe, it, expect } from 'vitest';
import {
  VERSION,
  PROTOCOL_VERSION,
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  SIGNATURE_SIZE,
  HASH_SIZE,
  MAC_SIZE,
  MAX_PREKEY_ID,
  MIN_PREKEY_ID,
  MAX_REGISTRATION_ID,
  DEFAULT_DEVICE_ID,
  INFO_STRINGS,
  getX3DHInfo,
  getRatchetInfo,
  getChainInfo,
  getMessageInfo,
  getSignedPreKeyContext,
  isValidPreKeyId,
  isValidRegistrationId,
  isValidDeviceId,
} from '../src/constants';

describe('Constants', () => {
  describe('Versioning', () => {
    it('VERSION is "0.5.0"', () => {
      expect(VERSION).toBe('0.5.0');
    });

    it('PROTOCOL_VERSION is 3', () => {
      expect(PROTOCOL_VERSION).toBe(3);
    });
  });

  describe('Key Sizes', () => {
    it('PUBLIC_KEY_SIZE is 32', () => {
      expect(PUBLIC_KEY_SIZE).toBe(32);
    });

    it('PRIVATE_KEY_SIZE is 32', () => {
      expect(PRIVATE_KEY_SIZE).toBe(32);
    });

    it('SIGNATURE_SIZE is 64', () => {
      expect(SIGNATURE_SIZE).toBe(64);
    });

    it('HASH_SIZE is 32', () => {
      expect(HASH_SIZE).toBe(32);
    });

    it('MAC_SIZE is 32', () => {
      expect(MAC_SIZE).toBe(32);
    });
  });

  describe('PreKey Range', () => {
    it('MIN_PREKEY_ID is 1', () => {
      expect(MIN_PREKEY_ID).toBe(1);
    });

    it('MAX_PREKEY_ID is 16777215 (2^24-1)', () => {
      expect(MAX_PREKEY_ID).toBe(0xffffff);
    });
  });

  describe('Info Strings (Buffer getters)', () => {
    it('getX3DHInfo returns fresh Buffer', () => {
      const a = getX3DHInfo();
      const b = getX3DHInfo();
      expect(a).toBeInstanceOf(Buffer);
      expect(a.equals(b)).toBe(true);
      expect(a).not.toBe(b); // Different instances (fresh copy)
    });

    it('getRatchetInfo returns fresh Buffer', () => {
      const buf = getRatchetInfo();
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.toString('utf-8')).toContain('Ratchet');
    });

    it('getChainInfo returns fresh Buffer', () => {
      const buf = getChainInfo();
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.toString('utf-8')).toContain('Chain');
    });

    it('getMessageInfo returns fresh Buffer', () => {
      const buf = getMessageInfo();
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.toString('utf-8')).toContain('Message');
    });

    it('getSignedPreKeyContext returns fresh Buffer', () => {
      const buf = getSignedPreKeyContext();
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.toString('utf-8')).toContain('SPK');
    });

    it('mutating returned buffer does not affect next call', () => {
      const a = getX3DHInfo();
      a.fill(0);
      const b = getX3DHInfo();
      expect(b.toString('utf-8')).toContain('X3DH');
    });
  });

  describe('INFO_STRINGS', () => {
    it('contains all info strings', () => {
      expect(INFO_STRINGS.X3DH).toBeDefined();
      expect(INFO_STRINGS.RATCHET).toBeDefined();
      expect(INFO_STRINGS.CHAIN).toBeDefined();
      expect(INFO_STRINGS.MESSAGE).toBeDefined();
      expect(INFO_STRINGS.SIGNED_PREKEY).toBeDefined();
    });

    it('is frozen', () => {
      expect(Object.isFrozen(INFO_STRINGS)).toBe(true);
    });
  });

  describe('isValidPreKeyId', () => {
    it('returns true for valid IDs', () => {
      expect(isValidPreKeyId(1)).toBe(true);
      expect(isValidPreKeyId(100)).toBe(true);
      expect(isValidPreKeyId(MAX_PREKEY_ID)).toBe(true);
    });

    it('returns false for invalid IDs', () => {
      expect(isValidPreKeyId(0)).toBe(false);
      expect(isValidPreKeyId(-1)).toBe(false);
      expect(isValidPreKeyId(MAX_PREKEY_ID + 1)).toBe(false);
      expect(isValidPreKeyId(1.5)).toBe(false);
      expect(isValidPreKeyId('1')).toBe(false);
      expect(isValidPreKeyId(null)).toBe(false);
      expect(isValidPreKeyId(undefined)).toBe(false);
      expect(isValidPreKeyId(NaN)).toBe(false);
    });
  });

  describe('isValidRegistrationId', () => {
    it('returns true for valid IDs', () => {
      expect(isValidRegistrationId(1)).toBe(true);
      expect(isValidRegistrationId(MAX_REGISTRATION_ID)).toBe(true);
    });

    it('returns false for invalid IDs', () => {
      expect(isValidRegistrationId(0)).toBe(false);
      expect(isValidRegistrationId(MAX_REGISTRATION_ID + 1)).toBe(false);
      expect(isValidRegistrationId(1.5)).toBe(false);
      expect(isValidRegistrationId('5')).toBe(false);
    });
  });

  describe('isValidDeviceId', () => {
    it('returns true for valid IDs', () => {
      expect(isValidDeviceId(DEFAULT_DEVICE_ID)).toBe(true);
      expect(isValidDeviceId(1)).toBe(true);
      expect(isValidDeviceId(1000)).toBe(true);
    });

    it('returns false for invalid IDs', () => {
      expect(isValidDeviceId(0)).toBe(false);
      expect(isValidDeviceId(-1)).toBe(false);
      expect(isValidDeviceId(1.5)).toBe(false);
      expect(isValidDeviceId('1')).toBe(false);
    });
  });
});
