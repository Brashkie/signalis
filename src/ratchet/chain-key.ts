/**
 * Chain Key Advancement (Symmetric-Key Ratchet)
 *
 * Implements the symmetric-key ratchet of the Double Ratchet algorithm.
 *
 * For each message sent or received, we advance the chain:
 *   1. Derive a MessageKey from the current ChainKey
 *   2. Derive the NEXT ChainKey from the current ChainKey
 *   3. Throw away the current ChainKey (forward secrecy)
 *
 * Spec:
 *   MK_seed   = HMAC-SHA256(CK, 0x01)
 *   CK_next   = HMAC-SHA256(CK, 0x02)
 *
 * Note: The MK_seed is then run through HKDF in `message-key.ts` to derive
 * the actual (AES key, HMAC key, IV) triple. This module just does the
 * raw chain advancement.
 *
 * @module ratchet/chain-key
 */

import { hmac } from '../crypto';
import type { ChainKey } from '../types';
import { asChainKey, asMessageKey } from '../types';
import {
  CHAIN_KEY_SIZE,
  KDF_CK_NEXT_INPUT,
  KDF_CK_MESSAGE_INPUT,
} from '../constants';
import { ValidationError } from '../errors';
import type { ChainKeyAdvancement } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// advanceChainKey
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Advance the chain key by one step.
 *
 * Returns BOTH the message key for the current step AND the next chain key.
 * After calling this, the OLD chain key should be zeroed/forgotten.
 *
 * @param chainKey  The current chain key
 * @param counter   The message number (n) THIS step represents (0, 1, 2, ...)
 *                  Used only for tracking; doesn't affect derivation.
 *
 * @returns
 *   - `nextChainKey`: the chain key for the NEXT message
 *   - `messageKey`: the message key for THIS message (32 bytes seed)
 *   - `counter`: the message number this key encrypts
 *
 * @throws {ValidationError} On wrong sizes / invalid counter
 *
 * @example
 * ```ts
 * let ck = initialChainKey;
 * for (let n = 0; n < 3; n++) {
 *   const { nextChainKey, messageKey } = advanceChainKey(ck, n);
 *   // ... use messageKey to encrypt message n ...
 *   ck = nextChainKey;
 * }
 * ```
 */
export function advanceChainKey(
  chainKey: ChainKey,
  counter: number,
): ChainKeyAdvancement {
  // ─── Validate ─────────────────────────────────────────────────────────
  if (!Buffer.isBuffer(chainKey) || chainKey.length !== CHAIN_KEY_SIZE) {
    throw new ValidationError(
      `advanceChainKey: chainKey must be ${CHAIN_KEY_SIZE} bytes`,
      { actual: chainKey?.length, expected: CHAIN_KEY_SIZE },
    );
  }
  if (!Number.isInteger(counter) || counter < 0) {
    throw new ValidationError(
      `advanceChainKey: counter must be a non-negative integer (got ${counter})`,
      { counter },
    );
  }

  // ─── Derive MessageKey seed: HMAC(CK, 0x01) ───────────────────────────
  const mkInput = Buffer.from([KDF_CK_MESSAGE_INPUT]);
  const mkSeed = hmac(chainKey, mkInput);

  // ─── Derive next ChainKey: HMAC(CK, 0x02) ─────────────────────────────
  const ckInput = Buffer.from([KDF_CK_NEXT_INPUT]);
  const nextCk = hmac(chainKey, ckInput);

  return {
    nextChainKey: asChainKey(nextCk),
    messageKey: asMessageKey(mkSeed),
    counter,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// advanceChainKeyN (skip forward N steps)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Advance the chain key N times, collecting every message key in between.
 *
 * Used when we receive a message with `header.n` ahead of our expected
 * counter — we need to derive all the skipped keys so we can decrypt
 * out-of-order future messages.
 *
 * Caller is responsible for enforcing MAX_SKIPPED_MESSAGE_KEYS at a higher
 * level (in the SkippedKeys cache).
 *
 * @param startingChainKey  Chain key at counter `startingCounter`
 * @param startingCounter   Counter value at start
 * @param targetCounter     Counter to advance TO (exclusive — collects keys 0..target-1)
 *
 * @returns Array of `ChainKeyAdvancement` covering counters startingCounter..targetCounter-1
 *          plus the final `nextChainKey` (the one for counter `targetCounter`)
 *
 * @throws {ValidationError} On invalid range
 */
export function advanceChainKeyN(
  startingChainKey: ChainKey,
  startingCounter: number,
  targetCounter: number,
): {
  skippedKeys: ChainKeyAdvancement[];
  nextChainKey: ChainKey;
} {
  if (!Number.isInteger(startingCounter) || startingCounter < 0) {
    throw new ValidationError(
      `advanceChainKeyN: startingCounter must be non-negative integer`,
      { startingCounter },
    );
  }
  if (!Number.isInteger(targetCounter) || targetCounter < startingCounter) {
    throw new ValidationError(
      `advanceChainKeyN: targetCounter must be >= startingCounter`,
      { startingCounter, targetCounter },
    );
  }

  const skipped: ChainKeyAdvancement[] = [];
  let ck = startingChainKey;
  let n = startingCounter;

  while (n < targetCounter) {
    const adv = advanceChainKey(ck, n);
    skipped.push(adv);
    ck = adv.nextChainKey;
    n++;
  }

  return {
    skippedKeys: skipped,
    nextChainKey: ck,
  };
}
