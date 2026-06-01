/**
 * X3DH Initial Message
 *
 * The payload Alice attaches to her first encrypted message to Bob.
 * Bob uses these fields (plus his private prekeys) to derive the same
 * shared secret.
 *
 * @module x3dh/initial-message
 */

import { PublicIdentityKey } from '../identity/identity-key';
import type { PublicKey } from '../types';
import { asPublicKey } from '../types';
import {
  PUBLIC_KEY_SIZE,
  MAX_PREKEY_ID,
  MIN_PREKEY_ID,
  MAX_REGISTRATION_ID,
  MAX_DEVICE_ID,
  isValidPreKeyId,
  isValidRegistrationId,
  isValidDeviceId,
} from '../constants';
import {
  ValidationError,
  SerializationError,
} from '../errors';
import type { InitialMessagePayload } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// InitialMessage
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Structured representation of an X3DH initial message.
 *
 * Construct via `fromPayload()` when receiving over the network.
 * Construct via `new InitialMessage(...)` (or via `X3DH.initiate()`) locally.
 *
 * @example Construct from wire format
 * ```ts
 * const payload: InitialMessagePayload = await receive();
 * const msg = InitialMessage.fromPayload(payload);
 * ```
 *
 * @example Convert back to wire format
 * ```ts
 * const wire = initialMessage.toPayload();
 * await sendOverNetwork(wire);
 * ```
 */
export class InitialMessage {
  public readonly identityKey: PublicIdentityKey;
  public readonly ephemeralKey: PublicKey;
  public readonly signedPreKeyId: number;
  public readonly oneTimePreKeyId: number | null;
  public readonly registrationId: number;
  public readonly deviceId: number;

  /**
   * @internal Use the static factories or `X3DH.initiate()`.
   */
  constructor(args: {
    identityKey: PublicIdentityKey;
    ephemeralKey: PublicKey | Buffer | Uint8Array;
    signedPreKeyId: number;
    oneTimePreKeyId?: number | null;
    registrationId: number;
    deviceId: number;
  }) {
    if (!(args.identityKey instanceof PublicIdentityKey)) {
      throw ValidationError.wrongType(
        'identityKey',
        'PublicIdentityKey',
        args.identityKey,
      );
    }

    const ephBuf = Buffer.isBuffer(args.ephemeralKey)
      ? args.ephemeralKey
      : Buffer.from(args.ephemeralKey);
    if (ephBuf.length !== PUBLIC_KEY_SIZE) {
      throw ValidationError.wrongSize(
        'ephemeralKey',
        PUBLIC_KEY_SIZE,
        ephBuf.length,
      );
    }

    if (!isValidPreKeyId(args.signedPreKeyId)) {
      throw new ValidationError(
        `InitialMessage: signedPreKeyId ${args.signedPreKeyId} out of range [${MIN_PREKEY_ID}, ${MAX_PREKEY_ID}]`,
        { signedPreKeyId: args.signedPreKeyId },
      );
    }

    if (args.oneTimePreKeyId !== null && args.oneTimePreKeyId !== undefined) {
      if (!isValidPreKeyId(args.oneTimePreKeyId)) {
        throw new ValidationError(
          `InitialMessage: oneTimePreKeyId ${args.oneTimePreKeyId} out of range [${MIN_PREKEY_ID}, ${MAX_PREKEY_ID}]`,
          { oneTimePreKeyId: args.oneTimePreKeyId },
        );
      }
    }

    if (!isValidRegistrationId(args.registrationId)) {
      throw new ValidationError(
        `InitialMessage: registrationId ${args.registrationId} out of range [1, ${MAX_REGISTRATION_ID}]`,
        { registrationId: args.registrationId },
      );
    }

    if (!isValidDeviceId(args.deviceId)) {
      throw new ValidationError(
        `InitialMessage: deviceId ${args.deviceId} out of range [1, ${MAX_DEVICE_ID}]`,
        { deviceId: args.deviceId },
      );
    }

    this.identityKey = args.identityKey;
    this.ephemeralKey = asPublicKey(ephBuf);
    this.signedPreKeyId = args.signedPreKeyId;
    this.oneTimePreKeyId = args.oneTimePreKeyId ?? null;
    this.registrationId = args.registrationId;
    this.deviceId = args.deviceId;

    Object.freeze(this);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Wire-format conversion
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Convert to JSON-safe wire format.
   */
  public toPayload(): InitialMessagePayload {
    const payload: InitialMessagePayload = {
      identityKey: this.identityKey.toHex(),
      ephemeralKey: this.ephemeralKey.toString('hex'),
      signedPreKeyId: this.signedPreKeyId,
      registrationId: this.registrationId,
      deviceId: this.deviceId,
      ...(this.oneTimePreKeyId !== null
        ? { oneTimePreKeyId: this.oneTimePreKeyId }
        : {}),
    };
    return payload;
  }

  /**
   * Parse from wire format. Validates field types and key sizes.
   *
   * @throws {SerializationError} on malformed input
   * @throws {ValidationError} on out-of-range values
   */
  public static fromPayload(payload: unknown): InitialMessage {
    if (payload === null || typeof payload !== 'object') {
      throw new SerializationError(
        'InitialMessage.fromPayload: expected object',
        { received: payload === null ? 'null' : typeof payload },
      );
    }
    const obj = payload as Record<string, unknown>;

    if (typeof obj['identityKey'] !== 'string') {
      throw new SerializationError('InitialMessage: identityKey must be hex string');
    }
    if (typeof obj['ephemeralKey'] !== 'string') {
      throw new SerializationError('InitialMessage: ephemeralKey must be hex string');
    }
    if (typeof obj['signedPreKeyId'] !== 'number') {
      throw new SerializationError('InitialMessage: signedPreKeyId must be a number');
    }
    if (typeof obj['registrationId'] !== 'number') {
      throw new SerializationError('InitialMessage: registrationId must be a number');
    }
    if (typeof obj['deviceId'] !== 'number') {
      throw new SerializationError('InitialMessage: deviceId must be a number');
    }
    if (
      obj['oneTimePreKeyId'] !== undefined &&
      obj['oneTimePreKeyId'] !== null &&
      typeof obj['oneTimePreKeyId'] !== 'number'
    ) {
      throw new SerializationError(
        'InitialMessage: oneTimePreKeyId must be number, null, or absent',
      );
    }

    // Validate hex on key strings
    const HEX_REGEX = /^[0-9a-fA-F]+$/;
    if (!HEX_REGEX.test(obj['identityKey'])) {
      throw new SerializationError('InitialMessage: identityKey is not valid hex');
    }
    if (!HEX_REGEX.test(obj['ephemeralKey'])) {
      throw new SerializationError('InitialMessage: ephemeralKey is not valid hex');
    }

    let identityKey: PublicIdentityKey;
    try {
      identityKey = PublicIdentityKey.fromHex(obj['identityKey'] as string);
    } catch (e) {
      throw new SerializationError(
        `InitialMessage: invalid identityKey: ${(e as Error).message}`,
      );
    }

    const ephBuf = Buffer.from(obj['ephemeralKey'] as string, 'hex');
    if (ephBuf.length !== PUBLIC_KEY_SIZE) {
      throw new SerializationError(
        `InitialMessage: ephemeralKey size ${ephBuf.length} (expected ${PUBLIC_KEY_SIZE})`,
      );
    }

    return new InitialMessage({
      identityKey,
      ephemeralKey: ephBuf,
      signedPreKeyId: obj['signedPreKeyId'] as number,
      oneTimePreKeyId: (obj['oneTimePreKeyId'] as number | undefined) ?? null,
      registrationId: obj['registrationId'] as number,
      deviceId: obj['deviceId'] as number,
    });
  }

  // ───────────────────────────────────────────────────────────────────────
  // Accessors
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Sender's address as "registrationId.deviceId".
   */
  public address(): string {
    return `${this.registrationId}.${this.deviceId}`;
  }

  /**
   * True if this message references a one-time prekey.
   *
   * Bob must look up `oneTimePreKeyId` in his store and pass the matching
   * private key to `X3DH.receive()` for full forward secrecy.
   */
  public usesOneTimePreKey(): boolean {
    return this.oneTimePreKeyId !== null;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Safe Output
  // ───────────────────────────────────────────────────────────────────────

  public toString(): string {
    const otp = this.oneTimePreKeyId !== null
      ? `, otpk=${this.oneTimePreKeyId}`
      : '';
    return `InitialMessage(from=${this.address()}, spk=${this.signedPreKeyId}${otp})`;
  }

  public toJSON(): {
    type: string;
    from: string;
    signedPreKeyId: number;
    oneTimePreKeyId: number | null;
  } {
    return {
      type: 'InitialMessage',
      from: this.address(),
      signedPreKeyId: this.signedPreKeyId,
      oneTimePreKeyId: this.oneTimePreKeyId,
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guard
// ═══════════════════════════════════════════════════════════════════════════

export function isInitialMessage(value: unknown): value is InitialMessage {
  return value instanceof InitialMessage;
}
