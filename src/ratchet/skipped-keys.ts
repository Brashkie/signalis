/**
 * Skipped Message Keys Cache
 *
 * When messages arrive out-of-order, we need to remember derived message
 * keys for messages we haven't seen yet. This cache holds them.
 *
 * Example:
 *   Sender sends   msg_0, msg_1, msg_2, msg_3
 *   Receiver gets  msg_0, msg_3 (msg_1 and msg_2 delayed)
 *
 *   On receiving msg_3, we know that msg_1 and msg_2 were skipped.
 *   We derive their message keys and store them here.
 *   When msg_1 arrives later, we look up its key and decrypt.
 *
 * ANTI-DOS: We enforce MAX_SKIPPED_MESSAGE_KEYS as a hard cap. Without this,
 * an attacker could send `header.n = 2^32 - 1` and force us to derive
 * billions of keys, exhausting memory.
 *
 * Cache keyed by (their_dh_pub_hex, counter). One sender's keys live
 * separately from another's, so the cap is global across all senders.
 *
 * @module ratchet/skipped-keys
 */

import type { MessageKey, PublicKey } from '../types';
import { MAX_SKIPPED_MESSAGE_KEYS } from '../constants';
import { ValidationError, ProtocolError } from '../errors';

// ═══════════════════════════════════════════════════════════════════════════
// SkippedMessageKeys
// ═══════════════════════════════════════════════════════════════════════════

/**
 * In-memory cache of skipped message keys.
 *
 * Insertion-ordered (Map iteration order). When the cap is hit, the OLDEST
 * key is evicted (FIFO).
 *
 * @example
 * ```ts
 * const cache = new SkippedMessageKeys();
 *
 * // Save a skipped key
 * cache.set(theirDhPub, counter, mk);
 *
 * // Try to retrieve when out-of-order message arrives
 * const mk = cache.take(theirDhPub, counter);  // removes from cache
 * if (mk) {
 *   const plaintext = decryptWithMessageKey(mk, ciphertext, mac, header);
 * }
 * ```
 */
export class SkippedMessageKeys {
  /**
   * Storage: Map<"dhHex:counter", MessageKey>
   *
   * Map preserves insertion order, so we can FIFO-evict the oldest.
   */
  private readonly store = new Map<string, MessageKey>();

  /**
   * Maximum number of keys before FIFO eviction kicks in.
   * Default: 2000 (libsignal). Configurable for testing or special cases.
   */
  public readonly maxKeys: number;

  constructor(maxKeys: number = MAX_SKIPPED_MESSAGE_KEYS) {
    if (!Number.isInteger(maxKeys) || maxKeys < 1) {
      throw new ValidationError(
        `SkippedMessageKeys: maxKeys must be a positive integer (got ${maxKeys})`,
        { maxKeys },
      );
    }
    this.maxKeys = maxKeys;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Helpers
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Build cache key from (theirDhPub, counter).
   */
  private static keyOf(dhPublicKey: PublicKey | Buffer, counter: number): string {
    return `${dhPublicKey.toString('hex')}:${counter}`;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Storage
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Store a skipped message key.
   *
   * If the cache is at capacity, evicts the OLDEST entry (FIFO) before
   * adding the new one.
   */
  public set(
    dhPublicKey: PublicKey | Buffer,
    counter: number,
    messageKey: MessageKey,
  ): void {
    if (!Number.isInteger(counter) || counter < 0) {
      throw new ValidationError(
        `SkippedMessageKeys.set: counter must be non-negative integer`,
        { counter },
      );
    }
    if (!Buffer.isBuffer(messageKey)) {
      throw new ValidationError(
        'SkippedMessageKeys.set: messageKey must be a Buffer',
      );
    }

    const cacheKey = SkippedMessageKeys.keyOf(dhPublicKey, counter);

    // FIFO eviction if at capacity (and not just updating existing key)
    if (this.store.size >= this.maxKeys && !this.store.has(cacheKey)) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) {
        this.store.delete(oldestKey);
      }
    }

    this.store.set(cacheKey, messageKey);
  }

  /**
   * Pre-flight check: would adding `count` keys exceed the cap?
   *
   * Called BEFORE deriving a batch of skipped keys to fail fast on attacks.
   *
   * @throws {ProtocolError} If count + current size would exceed maxKeys
   */
  public assertCanAdd(count: number): void {
    if (!Number.isInteger(count) || count < 0) {
      throw new ValidationError(
        `SkippedMessageKeys.assertCanAdd: count must be non-negative integer`,
        { count },
      );
    }
    if (count > this.maxKeys) {
      throw new ProtocolError(
        `Too many skipped messages: requested ${count} > max ${this.maxKeys} (possible DoS)`,
        { count, maxKeys: this.maxKeys },
      );
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Retrieval
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Retrieve (and remove) a skipped message key.
   *
   * Message keys are single-use — once consumed, they should be deleted.
   *
   * @returns The MessageKey if present, null otherwise.
   */
  public take(
    dhPublicKey: PublicKey | Buffer,
    counter: number,
  ): MessageKey | null {
    const cacheKey = SkippedMessageKeys.keyOf(dhPublicKey, counter);
    const mk = this.store.get(cacheKey);
    if (mk === undefined) return null;
    this.store.delete(cacheKey);
    return mk;
  }

  /**
   * Peek at a skipped message key without consuming it.
   * Useful for testing; production code should use `take()`.
   */
  public has(dhPublicKey: PublicKey | Buffer, counter: number): boolean {
    return this.store.has(SkippedMessageKeys.keyOf(dhPublicKey, counter));
  }

  // ───────────────────────────────────────────────────────────────────────
  // Bulk operations
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Current number of cached keys.
   */
  public get size(): number {
    return this.store.size;
  }

  /**
   * Clear all entries. (Useful for testing.)
   */
  public clear(): void {
    this.store.clear();
  }

  /**
   * List all cached entries (for serialization/debugging).
   *
   * Returns insertion-ordered array.
   */
  public entries(): Array<{
    dhPublicKeyHex: string;
    counter: number;
    messageKey: MessageKey;
  }> {
    return Array.from(this.store.entries()).map(([cacheKey, mk]) => {
      const idx = cacheKey.lastIndexOf(':');
      return {
        dhPublicKeyHex: cacheKey.slice(0, idx),
        counter: parseInt(cacheKey.slice(idx + 1), 10),
        messageKey: mk,
      };
    });
  }

  // ───────────────────────────────────────────────────────────────────────
  // Safe output
  // ───────────────────────────────────────────────────────────────────────

  public toString(): string {
    return `SkippedMessageKeys(size=${this.store.size}, max=${this.maxKeys})`;
  }

  public toJSON(): { type: string; size: number; maxKeys: number } {
    return {
      type: 'SkippedMessageKeys',
      size: this.store.size,
      maxKeys: this.maxKeys,
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
