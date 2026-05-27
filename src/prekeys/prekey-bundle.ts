/**
 * PreKey Bundle
 *
 * The complete server-facing payload that allows another party to initiate
 * an X3DH handshake with you asynchronously.
 *
 * A bundle contains:
 *   - registrationId  → uniquely identifies the user's installation
 *   - deviceId        → distinguishes multiple devices for the same user
 *   - identityKey     → long-term public identity (Curve25519, 32 bytes)
 *   - signedPreKey    → medium-term, rotated weekly, signed by identityKey
 *   - oneTimePreKey?  → ephemeral, single-use (optional but recommended)
 *
 * The server hands out one bundle per X3DH request. The one-time prekey is
 * removed from server-side storage after being included in a bundle so each
 * one is used at most once.
 *
 * @module prekeys/prekey-bundle
 */

import { PublicIdentityKey } from '../identity/identity-key';
import {
  PublicSignedPreKey,
  type PublicSignedPreKeyPayload,
} from './signed-prekey';
import { PublicOneTimePreKey } from './one-time-prekey';
import {
  MAX_REGISTRATION_ID,
  MIN_REGISTRATION_ID,
  MAX_DEVICE_ID,
  DEFAULT_DEVICE_ID,
  isValidRegistrationId,
  isValidDeviceId,
} from '../constants';
import {
  ValidationError,
  SerializationError,
  SignatureError,
} from '../errors';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Wire-format payload for a one-time prekey within a bundle.
 */
export interface PublicOneTimePreKeyPayload {
  readonly id: number;
  readonly publicKey: string; // hex
}

/**
 * Wire-format payload of a complete PreKey Bundle as the server would
 * send it. All keys are hex-encoded.
 */
export interface PreKeyBundlePayload {
  readonly registrationId: number;
  readonly deviceId: number;
  readonly identityKey: string; // hex
  readonly signedPreKey: PublicSignedPreKeyPayload;
  readonly oneTimePreKey?: PublicOneTimePreKeyPayload;
}

// ═══════════════════════════════════════════════════════════════════════════
// PreKeyBundle (verified, ready to use for X3DH)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A fully-verified PreKey Bundle, ready to be consumed by the X3DH
 * initiator flow (Sprint 2 Part 2).
 *
 * Always construct via `fromPayload` so the signed prekey signature is
 * verified against the identity key before the bundle is trusted.
 *
 * @example Build your own bundle (the server side)
 * ```ts
 * const alice = IdentityKeyPair.generate();
 * const spk = SignedPreKey.generate(alice, 1);
 * const otpkBatch = OneTimePreKey.generateBatch(1, 100);
 *
 * // Bob's server picks one
 * const oneTimeKey = otpkBatch[0];
 *
 * const myBundle = PreKeyBundle.build({
 *   registrationId: 12345,
 *   deviceId: 1,
 *   identityKey: alice.toPublic(),
 *   signedPreKey: spk.toPublic(),
 *   oneTimePreKey: oneTimeKey.toPublic(),
 * });
 * ```
 *
 * @example Receive and verify a bundle (the client side)
 * ```ts
 * const payload = await fetchBobBundleFromServer();
 * const bundle = PreKeyBundle.fromPayload(payload);
 * // signature verified ✅
 * // ready to feed into X3DH.initiate(bundle)
 * ```
 */
export class PreKeyBundle {
  public readonly registrationId: number;
  public readonly deviceId: number;
  public readonly identityKey: PublicIdentityKey;
  public readonly signedPreKey: PublicSignedPreKey;
  public readonly oneTimePreKey: PublicOneTimePreKey | null;

  /**
   * @internal Use static factory methods instead.
   */
  private constructor(
    registrationId: number,
    deviceId: number,
    identityKey: PublicIdentityKey,
    signedPreKey: PublicSignedPreKey,
    oneTimePreKey: PublicOneTimePreKey | null,
  ) {
    this.registrationId = registrationId;
    this.deviceId = deviceId;
    this.identityKey = identityKey;
    this.signedPreKey = signedPreKey;
    this.oneTimePreKey = oneTimePreKey;
    Object.freeze(this);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Construction
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Build a bundle locally from already-instantiated objects.
   *
   * This path does NOT re-verify the signed prekey signature — it assumes
   * the caller has already done so or generated the keys themselves.
   */
  public static build(args: {
    registrationId: number;
    deviceId?: number;
    identityKey: PublicIdentityKey;
    signedPreKey: PublicSignedPreKey;
    oneTimePreKey?: PublicOneTimePreKey | null;
  }): PreKeyBundle {
    const { registrationId, identityKey, signedPreKey, oneTimePreKey } = args;
    const deviceId = args.deviceId ?? DEFAULT_DEVICE_ID;

    if (!isValidRegistrationId(registrationId)) {
      throw new ValidationError(
        `PreKeyBundle: registrationId ${registrationId} out of range [${MIN_REGISTRATION_ID}, ${MAX_REGISTRATION_ID}]`,
        { registrationId },
      );
    }
    if (!isValidDeviceId(deviceId)) {
      throw new ValidationError(
        `PreKeyBundle: deviceId ${deviceId} out of range [1, ${MAX_DEVICE_ID}]`,
        { deviceId },
      );
    }
    if (!(identityKey instanceof PublicIdentityKey)) {
      throw ValidationError.wrongType('identityKey', 'PublicIdentityKey', identityKey);
    }
    if (!(signedPreKey instanceof PublicSignedPreKey)) {
      throw ValidationError.wrongType('signedPreKey', 'PublicSignedPreKey', signedPreKey);
    }
    if (oneTimePreKey !== null && oneTimePreKey !== undefined && !(oneTimePreKey instanceof PublicOneTimePreKey)) {
      throw ValidationError.wrongType(
        'oneTimePreKey',
        'PublicOneTimePreKey | null',
        oneTimePreKey,
      );
    }

    return new PreKeyBundle(
      registrationId,
      deviceId,
      identityKey,
      signedPreKey,
      oneTimePreKey ?? null,
    );
  }

  /**
   * Parse a server payload, VERIFYING the signed prekey signature against
   * the identity key in the bundle.
   *
   * This is the recommended way to construct a bundle from untrusted input.
   *
   * @throws {SignatureError} if the signed prekey signature is invalid
   * @throws {SerializationError} on malformed input
   * @throws {ValidationError} on invalid field values
   */
  public static fromPayload(payload: unknown): PreKeyBundle {
    if (payload === null || typeof payload !== 'object') {
      throw new SerializationError(
        'PreKeyBundle.fromPayload: expected object',
        { received: payload === null ? 'null' : typeof payload },
      );
    }
    const obj = payload as Record<string, unknown>;

    // ─── Validate primitives ──────────────────────────────────────────
    if (typeof obj['registrationId'] !== 'number') {
      throw new SerializationError('PreKeyBundle: registrationId must be a number');
    }
    if (typeof obj['deviceId'] !== 'number') {
      throw new SerializationError('PreKeyBundle: deviceId must be a number');
    }
    if (typeof obj['identityKey'] !== 'string') {
      throw new SerializationError('PreKeyBundle: identityKey must be hex string');
    }
    if (obj['signedPreKey'] === null || typeof obj['signedPreKey'] !== 'object') {
      throw new SerializationError('PreKeyBundle: signedPreKey must be an object');
    }

    const registrationId = obj['registrationId'] as number;
    const deviceId = obj['deviceId'] as number;

    if (!isValidRegistrationId(registrationId)) {
      throw new ValidationError(
        `PreKeyBundle: registrationId ${registrationId} out of range`,
        { registrationId },
      );
    }
    if (!isValidDeviceId(deviceId)) {
      throw new ValidationError(
        `PreKeyBundle: deviceId ${deviceId} out of range`,
        { deviceId },
      );
    }

    // ─── Parse identity key ───────────────────────────────────────────
    let identityKey: PublicIdentityKey;
    try {
      identityKey = PublicIdentityKey.fromHex(obj['identityKey'] as string);
    } catch (e) {
      throw new SerializationError(
        `PreKeyBundle: invalid identityKey: ${(e as Error).message}`,
      );
    }

    // ─── Parse + verify signed prekey ─────────────────────────────────
    // PublicSignedPreKey.fromPayload validates the signature against identityKey
    let signedPreKey: PublicSignedPreKey;
    try {
      signedPreKey = PublicSignedPreKey.fromPayload(
        identityKey,
        obj['signedPreKey'] as PublicSignedPreKeyPayload,
      );
    } catch (e) {
      if (e instanceof SignatureError) {
        throw e; // propagate verbatim
      }
      throw new SerializationError(
        `PreKeyBundle: invalid signedPreKey: ${(e as Error).message}`,
      );
    }

    // ─── Parse optional one-time prekey ───────────────────────────────
    let oneTimePreKey: PublicOneTimePreKey | null = null;
    if (obj['oneTimePreKey'] !== null && obj['oneTimePreKey'] !== undefined) {
      const otp = obj['oneTimePreKey'];
      if (typeof otp !== 'object') {
        throw new SerializationError('PreKeyBundle: oneTimePreKey must be an object');
      }
      const otpObj = otp as Record<string, unknown>;
      if (typeof otpObj['id'] !== 'number') {
        throw new SerializationError('PreKeyBundle: oneTimePreKey.id must be a number');
      }
      if (typeof otpObj['publicKey'] !== 'string') {
        throw new SerializationError(
          'PreKeyBundle: oneTimePreKey.publicKey must be hex string',
        );
      }
      try {
        oneTimePreKey = PublicOneTimePreKey.fromHex(
          otpObj['id'] as number,
          otpObj['publicKey'] as string,
        );
      } catch (e) {
        throw new SerializationError(
          `PreKeyBundle: invalid oneTimePreKey: ${(e as Error).message}`,
        );
      }
    }

    return new PreKeyBundle(
      registrationId,
      deviceId,
      identityKey,
      signedPreKey,
      oneTimePreKey,
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // Accessors
  // ───────────────────────────────────────────────────────────────────────

  /**
   * True if this bundle includes a one-time prekey.
   *
   * X3DH gives stronger forward secrecy when a one-time prekey is present.
   * If false, the initiator should still proceed but record this state.
   */
  public hasOneTimePreKey(): boolean {
    return this.oneTimePreKey !== null;
  }

  /**
   * Serialize back to wire format (e.g., to forward to another service).
   */
  public toPayload(): PreKeyBundlePayload {
    const payload: PreKeyBundlePayload = {
      registrationId: this.registrationId,
      deviceId: this.deviceId,
      identityKey: this.identityKey.toHex(),
      signedPreKey: {
        id: this.signedPreKey.id,
        publicKey: this.signedPreKey.publicKey.toString('hex'),
        signature: this.signedPreKey.signature.toString('hex'),
        timestamp: this.signedPreKey.timestamp,
      },
      ...(this.oneTimePreKey
        ? {
            oneTimePreKey: {
              id: this.oneTimePreKey.id,
              publicKey: this.oneTimePreKey.publicKey.toString('hex'),
            },
          }
        : {}),
    };
    return payload;
  }

  /**
   * Re-verify the signed prekey signature against the bundle's identity.
   *
   * `fromPayload()` already does this — use this method only if you
   * constructed the bundle manually via `build()` and want a sanity check.
   */
  public verify(): boolean {
    return this.identityKey.verifyBool(
      this.signedPreKey.publicKey,
      this.signedPreKey.signature,
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // Address formatting (for routing)
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Human-readable address for this user/device combination.
   *
   * @example
   * ```ts
   * bundle.address(); // "12345.1"
   * ```
   */
  public address(): string {
    return `${this.registrationId}.${this.deviceId}`;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Safe Output
  // ───────────────────────────────────────────────────────────────────────

  public toString(): string {
    const otp = this.oneTimePreKey ? `, otpk=${this.oneTimePreKey.id}` : '';
    return `PreKeyBundle(addr=${this.address()}, spk=${this.signedPreKey.id}${otp})`;
  }

  public toJSON(): {
    type: string;
    registrationId: number;
    deviceId: number;
    identityKey: string;
    signedPreKeyId: number;
    oneTimePreKeyId: number | null;
  } {
    return {
      type: 'PreKeyBundle',
      registrationId: this.registrationId,
      deviceId: this.deviceId,
      identityKey: this.identityKey.toHex(),
      signedPreKeyId: this.signedPreKey.id,
      oneTimePreKeyId: this.oneTimePreKey?.id ?? null,
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards
// ═══════════════════════════════════════════════════════════════════════════

export function isPreKeyBundle(value: unknown): value is PreKeyBundle {
  return value instanceof PreKeyBundle;
}
