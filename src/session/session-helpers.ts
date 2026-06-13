/**
 * Session Helpers
 *
 * Internal helpers used by the Session class:
 *   - DH ratchet step (when peer sends a new DH key)
 *   - Skipped key derivation for out-of-order delivery
 *
 * @module session/session-helpers
 */

import {
  deriveRootKey,
  advanceChainKey,
} from '../ratchet';
import { SkippedMessageKeys } from '../ratchet';
import type { RootKey, ChainKey, MessageKey, PublicKey, PrivateKey } from '../types';
import { ProtocolError } from '../errors';

// ═══════════════════════════════════════════════════════════════════════════
// dhRatchetStep
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Perform a DH ratchet step using the peer's new DH public key.
 *
 * Returns the new root key + new chain key. Caller decides whether this
 * is a "receiving" or "sending" ratchet step — both flows use the same
 * underlying derivation.
 */
export function dhRatchetStep(args: {
  currentRootKey: RootKey;
  myDhPrivate: PrivateKey;
  theirDhPublic: PublicKey;
}): { rootKey: RootKey; chainKey: ChainKey } {
  const result = deriveRootKey(
    args.currentRootKey,
    args.myDhPrivate,
    args.theirDhPublic,
  );
  return {
    rootKey: result.rootKey,
    chainKey: result.chainKey,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// skipMessageKeys — derive and cache keys for messages we haven't seen yet
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Advance the receiving chain N steps, caching the derived MessageKeys
 * for later out-of-order retrieval.
 *
 * Called when we receive a message with `header.n` ahead of our expected
 * counter. We derive the intermediate keys, cache them, and the caller
 * proceeds with the current message.
 *
 * @param chainKey  Current receiving chain key
 * @param startCounter  Our current receiving counter
 * @param untilCounter  The header.n we just received (we cache up to this - 1)
 * @param theirDhPublic  The peer's current DH public — used as cache key
 * @param skippedCache  Where to stash the derived keys
 *
 * @returns The chain key AT position `untilCounter` (ready to derive its message key)
 *
 * @throws {ProtocolError} If untilCounter - startCounter exceeds the anti-DoS cap
 */
export function skipMessageKeys(args: {
  chainKey: ChainKey;
  startCounter: number;
  untilCounter: number;
  theirDhPublic: PublicKey;
  skippedCache: SkippedMessageKeys;
}): { chainKeyAtTarget: ChainKey; skippedCount: number } {
  const distance = args.untilCounter - args.startCounter;

  if (distance < 0) {
    throw new ProtocolError(
      `Cannot skip backwards: startCounter=${args.startCounter} > untilCounter=${args.untilCounter}`,
      { startCounter: args.startCounter, untilCounter: args.untilCounter },
    );
  }

  // Anti-DoS check: would caching `distance` more keys exceed the cap?
  args.skippedCache.assertCanAdd(distance);

  let ck = args.chainKey;
  for (let n = args.startCounter; n < args.untilCounter; n++) {
    const step = advanceChainKey(ck, n);
    args.skippedCache.set(args.theirDhPublic, n, step.messageKey);
    ck = step.nextChainKey;
  }

  return {
    chainKeyAtTarget: ck,
    skippedCount: distance,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// tryRecoverSkippedKey — check if an out-of-order message has a cached key
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Look up a skipped message key in the cache and remove it if found.
 *
 * Returns null if no cached key matches. Caller can then proceed with
 * normal chain derivation (or detect a replay if the counter is in the
 * past with no cached key).
 */
export function tryRecoverSkippedKey(args: {
  cache: SkippedMessageKeys;
  theirDhPublic: PublicKey;
  counter: number;
}): MessageKey | null {
  return args.cache.take(args.theirDhPublic, args.counter);
}
