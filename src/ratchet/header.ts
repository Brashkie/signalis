/**
 * Message Header
 *
 * The cleartext header prepended to every Double Ratchet ciphertext.
 * Tells the receiver:
 *   - dhPublicKey: the sender's CURRENT ratchet DH public key
 *   - n:  message counter within the current sending chain
 *   - pn: number of messages in the PREVIOUS chain (so the receiver knows
 *         how many "skipped" keys to derive in the previous chain before
 *         performing the DH ratchet step)
 *
 * Note: The header is NOT encrypted (this is "Double Ratchet without
 * header encryption"). The header IS authenticated by the MAC over the
 * ciphertext (it's included as the associated data).
 *
 * @module ratchet/header
 */

import type { PublicKey } from '../types';
import { asPublicKey } from '../types';
import { PUBLIC_KEY_SIZE } from '../constants';
import { ValidationError, SerializationError } from '../errors';
import type { MessageHeaderPayload } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// MessageHeader
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Structured representation of a ratchet message header.
 *
 * Wire format (binary, for MAC computation and over-the-wire transport):
 *   [ dhPublicKey (32 bytes) | n (4 bytes BE) | pn (4 bytes BE) ]
 * Total: 40 bytes
 *
 * @example
 * ```ts
 * const header = new MessageHeader({
 *   dhPublicKey: myCurrentRatchetPub,
 *   n: 5,
 *   pn: 3,
 * });
 *
 * const bytes = header.toBytes();  // 40-byte buffer for MAC
 * const json  = header.toPayload(); // wire JSON
 * ```
 */
export class MessageHeader {
  public readonly dhPublicKey: PublicKey;
  public readonly n: number;
  public readonly pn: number;

  constructor(args: {
    dhPublicKey: PublicKey | Buffer | Uint8Array;
    n: number;
    pn: number;
  }) {
    const dhBuf = Buffer.isBuffer(args.dhPublicKey)
      ? args.dhPublicKey
      : Buffer.from(args.dhPublicKey);

    if (dhBuf.length !== PUBLIC_KEY_SIZE) {
      throw ValidationError.wrongSize(
        'MessageHeader.dhPublicKey',
        PUBLIC_KEY_SIZE,
        dhBuf.length,
      );
    }
    if (!Number.isInteger(args.n) || args.n < 0 || args.n > 0xffffffff) {
      throw new ValidationError(
        `MessageHeader: n must be uint32 (0..2^32-1), got ${args.n}`,
        { n: args.n },
      );
    }
    if (!Number.isInteger(args.pn) || args.pn < 0 || args.pn > 0xffffffff) {
      throw new ValidationError(
        `MessageHeader: pn must be uint32 (0..2^32-1), got ${args.pn}`,
        { pn: args.pn },
      );
    }

    this.dhPublicKey = asPublicKey(dhBuf);
    this.n = args.n;
    this.pn = args.pn;
    Object.freeze(this);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Binary wire format (for MAC + over-the-wire)
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Serialize to compact binary: [dhPublicKey(32) | n(4 BE) | pn(4 BE)]
   *
   * This is the bytes that get fed into the MAC as associated data.
   */
  public toBytes(): Buffer {
    const buf = Buffer.alloc(PUBLIC_KEY_SIZE + 4 + 4);
    this.dhPublicKey.copy(buf, 0);
    buf.writeUInt32BE(this.n, PUBLIC_KEY_SIZE);
    buf.writeUInt32BE(this.pn, PUBLIC_KEY_SIZE + 4);
    return buf;
  }

  /**
   * Parse a 40-byte binary header.
   */
  public static fromBytes(buf: Buffer): MessageHeader {
    if (!Buffer.isBuffer(buf) || buf.length !== PUBLIC_KEY_SIZE + 8) {
      throw new SerializationError(
        `MessageHeader.fromBytes: expected ${PUBLIC_KEY_SIZE + 8} bytes (got ${buf?.length})`,
        { actual: buf?.length, expected: PUBLIC_KEY_SIZE + 8 },
      );
    }
    return new MessageHeader({
      dhPublicKey: buf.subarray(0, PUBLIC_KEY_SIZE),
      n: buf.readUInt32BE(PUBLIC_KEY_SIZE),
      pn: buf.readUInt32BE(PUBLIC_KEY_SIZE + 4),
    });
  }

  // ───────────────────────────────────────────────────────────────────────
  // JSON wire format (for storage / debugging)
  // ───────────────────────────────────────────────────────────────────────

  public toPayload(): MessageHeaderPayload {
    return {
      dhPublicKey: this.dhPublicKey.toString('hex'),
      n: this.n,
      pn: this.pn,
    };
  }

  public static fromPayload(payload: unknown): MessageHeader {
    if (payload === null || typeof payload !== 'object') {
      throw new SerializationError(
        'MessageHeader.fromPayload: expected object',
        { received: payload === null ? 'null' : typeof payload },
      );
    }
    const obj = payload as Record<string, unknown>;

    if (typeof obj['dhPublicKey'] !== 'string') {
      throw new SerializationError('MessageHeader: dhPublicKey must be hex string');
    }
    if (typeof obj['n'] !== 'number') {
      throw new SerializationError('MessageHeader: n must be a number');
    }
    if (typeof obj['pn'] !== 'number') {
      throw new SerializationError('MessageHeader: pn must be a number');
    }

    const HEX_REGEX = /^[0-9a-fA-F]+$/;
    if (!HEX_REGEX.test(obj['dhPublicKey'])) {
      throw new SerializationError('MessageHeader: dhPublicKey is not valid hex');
    }

    const dhBuf = Buffer.from(obj['dhPublicKey'] as string, 'hex');
    if (dhBuf.length !== PUBLIC_KEY_SIZE) {
      throw new SerializationError(
        `MessageHeader: dhPublicKey size ${dhBuf.length} (expected ${PUBLIC_KEY_SIZE})`,
      );
    }

    return new MessageHeader({
      dhPublicKey: dhBuf,
      n: obj['n'] as number,
      pn: obj['pn'] as number,
    });
  }

  // ───────────────────────────────────────────────────────────────────────
  // Safe output
  // ───────────────────────────────────────────────────────────────────────

  public toString(): string {
    const dhHex = this.dhPublicKey.toString('hex').slice(0, 16);
    return `MessageHeader(dh=${dhHex}..., n=${this.n}, pn=${this.pn})`;
  }

  public toJSON(): { type: string; n: number; pn: number; dhPublicKey: string } {
    return {
      type: 'MessageHeader',
      n: this.n,
      pn: this.pn,
      dhPublicKey: this.dhPublicKey.toString('hex'),
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guard
// ═══════════════════════════════════════════════════════════════════════════

export function isMessageHeader(value: unknown): value is MessageHeader {
  return value instanceof MessageHeader;
}
