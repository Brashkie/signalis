/**
 * Protocol Address
 *
 * A `(userId, deviceId)` pair that identifies a specific peer in the
 * Signal Protocol world. One human user can have multiple devices, each
 * with its own ratchet session.
 *
 * Used as the key for storing sessions, trusted identities, and more.
 *
 * @module address
 */

import { ValidationError } from './errors';
import { MAX_DEVICE_ID } from './constants';

// Re-export so it's accessible from address module too
export { MAX_DEVICE_ID };

// ═══════════════════════════════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Maximum length of userId (bytes when UTF-8 encoded).
 * Prevents pathological cases when used as filesystem path.
 */
export const MAX_USER_ID_LENGTH = 256;

/**
 * userIds that contain these characters are rejected (filesystem safety).
 * Block path separators and shell-meta characters that would break
 * file-store paths or expose path traversal.
 *
 * The control-char range `\x00-\x1f` is intentional — these MUST be
 * rejected to prevent injection via newlines, null bytes, etc.
 */
// eslint-disable-next-line no-control-regex
const FORBIDDEN_USER_ID_CHARS = /[\x00-\x1f\x7f/\\:*?"<>|]/;

// ═══════════════════════════════════════════════════════════════════════════
// ProtocolAddress
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A peer identifier: `(userId, deviceId)`.
 *
 * @example
 * ```ts
 * const alicePhone = new ProtocolAddress('alice@example.com', 1);
 * const aliceLaptop = new ProtocolAddress('alice@example.com', 2);
 * // Same user, different devices → different sessions.
 *
 * console.log(alicePhone.toString());  // "alice@example.com.1"
 * console.log(alicePhone.equals(aliceLaptop));  // false
 * ```
 */
export class ProtocolAddress {
  public readonly userId: string;
  public readonly deviceId: number;

  constructor(userId: string, deviceId: number) {
    if (typeof userId !== 'string') {
      throw new ValidationError('ProtocolAddress: userId must be a string');
    }
    if (userId.length === 0) {
      throw new ValidationError('ProtocolAddress: userId cannot be empty');
    }
    if (userId.length > MAX_USER_ID_LENGTH) {
      throw new ValidationError(
        `ProtocolAddress: userId too long (max ${MAX_USER_ID_LENGTH}, got ${userId.length})`,
      );
    }
    if (FORBIDDEN_USER_ID_CHARS.test(userId)) {
      throw new ValidationError(
        'ProtocolAddress: userId contains forbidden characters ' +
        '(control chars, /, \\, :, *, ?, ", <, >, |)',
      );
    }
    if (!Number.isInteger(deviceId) || deviceId < 0 || deviceId > MAX_DEVICE_ID) {
      throw new ValidationError(
        `ProtocolAddress: deviceId must be an integer in [0, ${MAX_DEVICE_ID}]`,
      );
    }

    this.userId = userId;
    this.deviceId = deviceId;
    Object.freeze(this);
  }

  /**
   * Canonical string form: `<userId>.<deviceId>`.
   *
   * Filesystem-safe (because the constructor rejects path separators).
   * Used as the key for stores and as the directory name for file-based
   * impls.
   */
  public toString(): string {
    return `${this.userId}.${this.deviceId}`;
  }

  /**
   * Structural equality check.
   */
  public equals(other: ProtocolAddress): boolean {
    if (!(other instanceof ProtocolAddress)) return false;
    return this.userId === other.userId && this.deviceId === other.deviceId;
  }

  /**
   * Parse a canonical string back into an address.
   *
   * @throws {ValidationError} if the string is not in `userId.deviceId` form.
   */
  public static parse(s: string): ProtocolAddress {
    if (typeof s !== 'string') {
      throw new ValidationError('ProtocolAddress.parse: expected string');
    }
    const lastDot = s.lastIndexOf('.');
    if (lastDot <= 0 || lastDot === s.length - 1) {
      throw new ValidationError(
        `ProtocolAddress.parse: malformed address "${s}" (expected "userId.deviceId")`,
      );
    }
    const userId = s.substring(0, lastDot);
    const deviceIdStr = s.substring(lastDot + 1);
    const deviceId = Number.parseInt(deviceIdStr, 10);
    if (!Number.isInteger(deviceId) || `${deviceId}` !== deviceIdStr) {
      throw new ValidationError(
        `ProtocolAddress.parse: deviceId "${deviceIdStr}" is not an integer`,
      );
    }
    return new ProtocolAddress(userId, deviceId);
  }

  public toJSON(): { userId: string; deviceId: number } {
    return { userId: this.userId, deviceId: this.deviceId };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `ProtocolAddress(${this.toString()})`;
  }
}

/**
 * Type guard.
 */
export function isProtocolAddress(value: unknown): value is ProtocolAddress {
  return value instanceof ProtocolAddress;
}
