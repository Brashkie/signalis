/**
 * One-Time PreKey
 *
 * Ephemeral key pairs uploaded in batches to the server. Each one is
 * consumed by exactly ONE incoming X3DH handshake and then deleted.
 *
 * One-time prekeys give X3DH its full forward-secrecy guarantee — if an
 * attacker later compromises Bob's long-term identity, they still can't
 * decrypt past messages because the one-time prekey is gone.
 *
 * Lifecycle:
 *   1. Bob generates a batch on registration (e.g., 100 keys)
 *   2. Bob uploads PUBLIC halves to the server
 *   3. Bob stores PRIVATE halves locally
 *   4. Server hands out one PUBLIC key per incoming X3DH request
 *   5. Bob uses the matching PRIVATE key once, then deletes both
 *   6. When Bob's stock runs low, he generates a new batch
 *
 * @module prekeys/one-time-prekey
 */

import { generateKeyPair, sha256 } from '../crypto';
import type { KeyPair, PublicKey, PrivateKey } from '../types';
import { asPublicKey, asPrivateKey } from '../types';
import {
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  MAX_PREKEY_ID,
  MIN_PREKEY_ID,
  MAX_ONE_TIME_PREKEYS,
  isValidPreKeyId,
} from '../constants';
import { PreKeyError, ValidationError, SerializationError, ErrorCode } from '../errors';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/** JSON-safe serialized form of a OneTimePreKey. */
export interface SerializedOneTimePreKey {
  readonly id: number;
  readonly publicKey: string; // hex
  readonly privateKey: string; // hex
}

// ═══════════════════════════════════════════════════════════════════════════
// OneTimePreKey
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A single-use Curve25519 keypair identified by a numeric ID.
 *
 * @example Generate one
 * ```ts
 * const otpk = OneTimePreKey.generate(1);
 * console.log(otpk.id);              // 1
 * console.log(otpk.publicKey.length); // 32
 * ```
 *
 * @example Generate a batch
 * ```ts
 * const batch = OneTimePreKey.generateBatch(1, 100);
 * // 100 prekeys with IDs 1..100
 * ```
 *
 * @example Upload public halves to server
 * ```ts
 * const publicBundle = batch.map(k => ({
 *   id: k.id,
 *   publicKey: k.publicKey.toString('hex'),
 * }));
 * await uploadToServer(publicBundle);
 * ```
 */
export class OneTimePreKey implements KeyPair {
  public readonly id: number;
  public readonly publicKey: PublicKey;
  public readonly privateKey: PrivateKey;

  /**
   * @internal Use static factory methods instead.
   */
  private constructor(id: number, publicKey: PublicKey, privateKey: PrivateKey) {
    this.id = id;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    Object.freeze(this);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Construction
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Generate a new one-time prekey with the given ID.
   *
   * @throws {PreKeyError} If the ID is out of range
   *
   * @example
   * ```ts
   * const otpk = OneTimePreKey.generate(42);
   * ```
   */
  public static generate(id: number): OneTimePreKey {
    if (!isValidPreKeyId(id)) {
      throw PreKeyError.invalidId(id, MIN_PREKEY_ID, MAX_PREKEY_ID);
    }
    const kp = generateKeyPair();
    return new OneTimePreKey(id, kp.publicKey, kp.privateKey);
  }

  /**
   * Generate a contiguous batch of one-time prekeys.
   *
   * @param startId - First prekey ID
   * @param count - How many to generate (1..MAX_ONE_TIME_PREKEYS)
   * @returns Array of `count` keys with IDs `startId, startId+1, ..., startId+count-1`
   *
   * @throws {PreKeyError} If `startId + count - 1` would exceed MAX_PREKEY_ID
   * @throws {ValidationError} If count is out of bounds
   *
   * @example
   * ```ts
   * const batch = OneTimePreKey.generateBatch(1, 100);
   * ```
   */
  public static generateBatch(
    startId: number,
    count: number,
  ): OneTimePreKey[] {
    if (!Number.isInteger(count) || count < 1) {
      throw new ValidationError(
        `OneTimePreKey.generateBatch: count must be a positive integer (got ${count})`,
        { count },
      );
    }
    if (count > MAX_ONE_TIME_PREKEYS) {
      throw new ValidationError(
        `OneTimePreKey.generateBatch: count ${count} exceeds MAX_ONE_TIME_PREKEYS (${MAX_ONE_TIME_PREKEYS})`,
        { count, max: MAX_ONE_TIME_PREKEYS },
      );
    }
    if (!isValidPreKeyId(startId)) {
      throw PreKeyError.invalidId(startId, MIN_PREKEY_ID, MAX_PREKEY_ID);
    }
    const endId = startId + count - 1;
    if (endId > MAX_PREKEY_ID) {
      throw new PreKeyError(
        `Batch would exceed MAX_PREKEY_ID: startId=${startId}, count=${count}, endId=${endId}`,
        ErrorCode.PREKEY_ERROR,
        { startId, count, endId, max: MAX_PREKEY_ID },
      );
    }

    const out: OneTimePreKey[] = new Array(count);
    for (let i = 0; i < count; i++) {
      out[i] = OneTimePreKey.generate(startId + i);
    }
    return out;
  }

  /**
   * Reconstruct from existing key material (e.g., loaded from storage).
   *
   * @throws {ValidationError} If keys are wrong size
   * @throws {PreKeyError} If id is invalid
   */
  public static fromKeys(
    id: number,
    publicKey: Buffer | Uint8Array,
    privateKey: Buffer | Uint8Array,
  ): OneTimePreKey {
    if (!isValidPreKeyId(id)) {
      throw PreKeyError.invalidId(id, MIN_PREKEY_ID, MAX_PREKEY_ID);
    }
    const pubBuf = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
    const privBuf = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey);
    return new OneTimePreKey(id, asPublicKey(pubBuf), asPrivateKey(privBuf));
  }

  // ───────────────────────────────────────────────────────────────────────
  // Serialization
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Serialize to JSON-safe form (includes PRIVATE key — store securely).
   */
  public serialize(): SerializedOneTimePreKey {
    return {
      id: this.id,
      publicKey: this.publicKey.toString('hex'),
      privateKey: this.privateKey.toString('hex'),
    };
  }

  /**
   * Deserialize from stored form.
   *
   * @throws {SerializationError} on malformed input
   * @throws {PreKeyError} if id is invalid
   */
  public static deserialize(data: unknown): OneTimePreKey {
    if (data === null || typeof data !== 'object') {
      throw new SerializationError(
        'Invalid OneTimePreKey data: expected object',
        { received: data === null ? 'null' : typeof data },
      );
    }

    const obj = data as Record<string, unknown>;

    if (typeof obj['id'] !== 'number') {
      throw new SerializationError('OneTimePreKey: id must be a number');
    }
    if (typeof obj['publicKey'] !== 'string') {
      throw new SerializationError('OneTimePreKey: publicKey must be a hex string');
    }
    if (typeof obj['privateKey'] !== 'string') {
      throw new SerializationError('OneTimePreKey: privateKey must be a hex string');
    }

    const HEX_REGEX = /^[0-9a-fA-F]+$/;
    if (!HEX_REGEX.test(obj['publicKey'])) {
      throw new SerializationError('OneTimePreKey: publicKey is not valid hex');
    }
    if (!HEX_REGEX.test(obj['privateKey'])) {
      throw new SerializationError('OneTimePreKey: privateKey is not valid hex');
    }

    const pubBuf = Buffer.from(obj['publicKey'], 'hex');
    const privBuf = Buffer.from(obj['privateKey'], 'hex');

    if (pubBuf.length !== PUBLIC_KEY_SIZE) {
      throw new SerializationError(
        `OneTimePreKey: publicKey size ${pubBuf.length} (expected ${PUBLIC_KEY_SIZE})`,
      );
    }
    if (privBuf.length !== PRIVATE_KEY_SIZE) {
      throw new SerializationError(
        `OneTimePreKey: privateKey size ${privBuf.length} (expected ${PRIVATE_KEY_SIZE})`,
      );
    }

    return OneTimePreKey.fromKeys(obj['id'], pubBuf, privBuf);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Accessors
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Get the public-only form (safe to upload to server).
   */
  public toPublic(): PublicOneTimePreKey {
    return new PublicOneTimePreKey(this.id, this.publicKey);
  }

  /**
   * SHA-256 hash of the public key.
   */
  public fingerprint(): string {
    return sha256(this.publicKey).toString('hex');
  }

  /**
   * Compare by ID and public key (private keys ignored).
   */
  public equals(other: OneTimePreKey | PublicOneTimePreKey | null | undefined): boolean {
    if (!other) return false;
    return this.id === other.id && this.publicKey.equals(other.publicKey);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Safe Output (does NOT leak private key)
  // ───────────────────────────────────────────────────────────────────────

  public toString(): string {
    return `OneTimePreKey(id=${this.id}, public=${this.fingerprint().slice(0, 16)}...)`;
  }

  public toJSON(): { type: string; id: number; publicKey: string } {
    return {
      type: 'OneTimePreKey',
      id: this.id,
      publicKey: this.publicKey.toString('hex'),
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PublicOneTimePreKey (server-facing — only public key + id)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The public-only portion of a one-time prekey.
 * This is what gets uploaded to the server and downloaded by peers.
 */
export class PublicOneTimePreKey {
  public readonly id: number;
  public readonly publicKey: PublicKey;

  constructor(id: number, publicKey: PublicKey | Buffer | Uint8Array) {
    if (!isValidPreKeyId(id)) {
      throw PreKeyError.invalidId(id, MIN_PREKEY_ID, MAX_PREKEY_ID);
    }
    const buf = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
    this.id = id;
    this.publicKey = asPublicKey(buf);
    Object.freeze(this);
  }

  /**
   * Create from hex.
   */
  public static fromHex(id: number, hex: string): PublicOneTimePreKey {
    if (typeof hex !== 'string') {
      throw ValidationError.wrongType('hex', 'string', hex);
    }
    const HEX_REGEX = /^[0-9a-fA-F]+$/;
    if (!HEX_REGEX.test(hex)) {
      throw new ValidationError('PublicOneTimePreKey.fromHex: invalid hex');
    }
    const buf = Buffer.from(hex, 'hex');
    if (buf.length !== PUBLIC_KEY_SIZE) {
      throw ValidationError.wrongSize('publicKey', PUBLIC_KEY_SIZE, buf.length);
    }
    return new PublicOneTimePreKey(id, asPublicKey(buf));
  }

  public toHex(): string {
    return this.publicKey.toString('hex');
  }

  public fingerprint(): string {
    return sha256(this.publicKey).toString('hex');
  }

  public equals(
    other: PublicOneTimePreKey | OneTimePreKey | null | undefined,
  ): boolean {
    if (!other) return false;
    return this.id === other.id && this.publicKey.equals(other.publicKey);
  }

  public toString(): string {
    return `PublicOneTimePreKey(id=${this.id}, public=${this.fingerprint().slice(0, 16)}...)`;
  }

  public toJSON(): { type: string; id: number; publicKey: string } {
    return {
      type: 'PublicOneTimePreKey',
      id: this.id,
      publicKey: this.publicKey.toString('hex'),
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards
// ═══════════════════════════════════════════════════════════════════════════

export function isOneTimePreKey(value: unknown): value is OneTimePreKey {
  return value instanceof OneTimePreKey;
}

export function isPublicOneTimePreKey(value: unknown): value is PublicOneTimePreKey {
  return value instanceof PublicOneTimePreKey;
}
