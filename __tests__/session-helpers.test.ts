/**
 * Direct tests for session-helpers internal functions.
 *
 * Most code paths are exercised through the public Session API, but a few
 * defensive branches (like "skip backwards") are only reachable by calling
 * the helpers directly. Those tests live here.
 */

import { describe, it, expect } from 'vitest';

import {
  SkippedMessageKeys,
  ProtocolError,
  asChainKey,
  asPublicKey,
  asPrivateKey,
  asRootKey,
  crypto,
  CHAIN_KEY_SIZE,
  ROOT_KEY_SIZE,
} from '../src';

// These three helpers are NOT exported from the package — they're internal
// to the session module. We import them directly from the source path.
import {
  dhRatchetStep,
  skipMessageKeys,
  tryRecoverSkippedKey,
} from '../src/session/session-helpers';

// ═══════════════════════════════════════════════════════════════════════════
// dhRatchetStep
// ═══════════════════════════════════════════════════════════════════════════

describe('dhRatchetStep (internal)', () => {
  it('produces a new RK + CK from a DH exchange', () => {
    const rk = asRootKey(crypto.randomBytes(ROOT_KEY_SIZE));
    const me = crypto.generateKeyPair();
    const them = crypto.generateKeyPair();

    const result = dhRatchetStep({
      currentRootKey: rk,
      myDhPrivate: asPrivateKey(me.privateKey),
      theirDhPublic: asPublicKey(them.publicKey),
    });

    expect(result.rootKey.length).toBe(ROOT_KEY_SIZE);
    expect(result.chainKey.length).toBe(CHAIN_KEY_SIZE);
    expect(result.rootKey.equals(rk)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// skipMessageKeys
// ═══════════════════════════════════════════════════════════════════════════

describe('skipMessageKeys (internal)', () => {
  const dhPub = asPublicKey(Buffer.alloc(32, 0xaa));

  it('skips 0 keys when start === until (no-op)', () => {
    const ck = asChainKey(crypto.randomBytes(CHAIN_KEY_SIZE));
    const cache = new SkippedMessageKeys();

    const result = skipMessageKeys({
      chainKey: ck,
      startCounter: 5,
      untilCounter: 5,
      theirDhPublic: dhPub,
      skippedCache: cache,
    });

    expect(result.skippedCount).toBe(0);
    expect(result.chainKeyAtTarget.equals(ck)).toBe(true);
    expect(cache.size).toBe(0);
  });

  it('skips N keys and caches them', () => {
    const ck = asChainKey(crypto.randomBytes(CHAIN_KEY_SIZE));
    const cache = new SkippedMessageKeys();

    const result = skipMessageKeys({
      chainKey: ck,
      startCounter: 0,
      untilCounter: 3,
      theirDhPublic: dhPub,
      skippedCache: cache,
    });

    expect(result.skippedCount).toBe(3);
    expect(cache.size).toBe(3);
    expect(cache.has(dhPub, 0)).toBe(true);
    expect(cache.has(dhPub, 1)).toBe(true);
    expect(cache.has(dhPub, 2)).toBe(true);
  });

  // ─── The branch we're targeting for 100% coverage ─────────────────
  it('throws ProtocolError when untilCounter < startCounter (skip backwards)', () => {
    const ck = asChainKey(crypto.randomBytes(CHAIN_KEY_SIZE));
    const cache = new SkippedMessageKeys();

    expect(() =>
      skipMessageKeys({
        chainKey: ck,
        startCounter: 10,
        untilCounter: 5,
        theirDhPublic: dhPub,
        skippedCache: cache,
      }),
    ).toThrow(ProtocolError);
  });

  it('error message and context are informative', () => {
    const ck = asChainKey(crypto.randomBytes(CHAIN_KEY_SIZE));
    const cache = new SkippedMessageKeys();

    try {
      skipMessageKeys({
        chainKey: ck,
        startCounter: 100,
        untilCounter: 50,
        theirDhPublic: dhPub,
        skippedCache: cache,
      });
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ProtocolError);
      const err = e as ProtocolError;
      expect(err.message).toMatch(/Cannot skip backwards/);
      expect(err.message).toContain('100');
      expect(err.message).toContain('50');
      expect(err.context).toMatchObject({
        startCounter: 100,
        untilCounter: 50,
      });
    }
  });

  it('propagates anti-DoS ProtocolError when count > cap', () => {
    const ck = asChainKey(crypto.randomBytes(CHAIN_KEY_SIZE));
    const cache = new SkippedMessageKeys(/* maxKeys */ 5);

    // Asking to skip 10 keys when cap is 5 → fails inside assertCanAdd
    expect(() =>
      skipMessageKeys({
        chainKey: ck,
        startCounter: 0,
        untilCounter: 10,
        theirDhPublic: dhPub,
        skippedCache: cache,
      }),
    ).toThrow(ProtocolError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// tryRecoverSkippedKey
// ═══════════════════════════════════════════════════════════════════════════

describe('tryRecoverSkippedKey (internal)', () => {
  const dhPub = asPublicKey(Buffer.alloc(32, 0xbb));

  it('returns null when cache miss', () => {
    const cache = new SkippedMessageKeys();
    const result = tryRecoverSkippedKey({
      cache,
      theirDhPublic: dhPub,
      counter: 0,
    });
    expect(result).toBeNull();
  });

  it('returns and consumes the message key on hit', () => {
    const cache = new SkippedMessageKeys();

    // Seed: skip 3 keys
    const ck = asChainKey(crypto.randomBytes(CHAIN_KEY_SIZE));
    skipMessageKeys({
      chainKey: ck,
      startCounter: 0,
      untilCounter: 3,
      theirDhPublic: dhPub,
      skippedCache: cache,
    });
    expect(cache.size).toBe(3);

    // Recover one
    const mk = tryRecoverSkippedKey({
      cache,
      theirDhPublic: dhPub,
      counter: 1,
    });

    expect(mk).not.toBeNull();
    expect(mk!.length).toBe(32);

    // The key is consumed (removed from cache)
    expect(cache.size).toBe(2);
    expect(cache.has(dhPub, 1)).toBe(false);
  });
});
