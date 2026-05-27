/**
 * Signed PreKey
 *
 * A medium-term Curve25519 keypair signed by the long-term identity key.
 * Rotated periodically (e.g., every 7 days) to provide forward secrecy
 * if the signed prekey is later compromised.
 *
 * The signature binds the prekey's public part to the user's identity,
 * preventing a malicious server from substituting its own keys in a
 * X3DH bundle.
 *
 * Lifecycle:
 *   1. Bob generates a Curve25519 keypair
 *   2. Bob signs the PUBLIC half with his IDENTITY key (XEd25519)
 *   3. Bob uploads {id, publicKey, signature, timestamp} to the server
 *   4. After 7 days, Bob generates a fresh one and rotates
 *   5. After 30 days, the old one is considered EXPIRED and should not be used
 *
 * ▶ This is the FIRST place where IdentityKeyPair.sign() (added in v0.2.0)
 *   gets used in the protocol. Signed prekeys are why XEd25519 exists.
 *
 * @module prekeys/signed-prekey
 */

import { generateKeyPair, sha256 } from '../crypto';
import type { KeyPair, PublicKey, PrivateKey, Signature } from '../types';
import { asPublicKey, asPrivateKey, asSignature } from '../types';
import {
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  SIGNATURE_SIZE,
  MAX_PREKEY_ID,
  MIN_PREKEY_ID,
  SIGNED_PREKEY_ROTATION_MS,
  SIGNED_PREKEY_MAX_AGE_MS,
  isValidPreKeyId,
} from '../constants';
import { PreKeyError, ValidationError, SerializationError, SignatureError } from '../errors';
import { IdentityKeyPair, PublicIdentityKey } from '../identity/identity-key';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/** JSON-safe serialized form of a SignedPreKey. */
export interface SerializedSignedPreKey {
  readonly id: number;
  readonly publicKey: string; // hex
  readonly privateKey: string; // hex
  readonly signature: string; // hex
  readonly timestamp: number; // ms epoch
}

/** Server-facing payload (no private key). */
export interface PublicSignedPreKeyPayload {
  readonly id: number;
  readonly publicKey: string; // hex
  readonly signature: string; // hex
  readonly timestamp: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// SignedPreKey
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A medium-term Curve25519 keypair whose public half is signed by the
 * owner's IDENTITY key.
 *
 * @example Generate
 * ```ts
 * const alice = IdentityKeyPair.generate();
 * const spk = SignedPreKey.generate(alice, 1);
 *
 * console.log(spk.id);              // 1
 * console.log(spk.signature.length); // 64
 * ```
 *
 * @example Verify (on Bob's side)
 * ```ts
 * const alicePub = PublicIdentityKey.fromHex(aliceIdentityHex);
 * const spk = SignedPreKey.fromPayload(alicePub, payload); // throws if invalid
 * // ... or:
 * if (spk.verify(alicePub)) { ... }
 * ```
 *
 * @example Rotation check
 * ```ts
 * if (spk.needsRotation()) {
 *   const newSpk = SignedPreKey.generate(alice, spk.id + 1);
 *   // upload newSpk to server
 * }
 * ```
 */
export class SignedPreKey implements KeyPair {
  public readonly id: number;
  public readonly publicKey: PublicKey;
  public readonly privateKey: PrivateKey;
  public readonly signature: Signature;
  public readonly timestamp: number;

  /**
   * @internal Use static factory methods instead.
   */
  private constructor(
    id: number,
    publicKey: PublicKey,
    privateKey: PrivateKey,
    signature: Signature,
    timestamp: number,
  ) {
    this.id = id;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.signature = signature;
    this.timestamp = timestamp;
    Object.freeze(this);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Construction
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Generate a new signed prekey, signing it with the given identity key.
   *
   * The signature covers the prekey's PUBLIC KEY (32 bytes) and is created
   * with the identity's XEd25519 signing capability (added in v0.2.0).
   *
   * @param identity - Long-term identity used to sign
   * @param id - Prekey ID
   * @param timestamp - Creation time in ms (defaults to Date.now())
   *
   * @throws {PreKeyError} on invalid id
   * @throws {ValidationError} on invalid timestamp
   *
   * @example
   * ```ts
   * const alice = IdentityKeyPair.generate();
   * const spk = SignedPreKey.generate(alice, 1);
   * ```
   */
  public static generate(
    identity: IdentityKeyPair,
    id: number,
    timestamp: number = Date.now(),
  ): SignedPreKey {
    if (!(identity instanceof IdentityKeyPair)) {
      throw ValidationError.wrongType('identity', 'IdentityKeyPair', identity);
    }
    if (!isValidPreKeyId(id)) {
      throw PreKeyError.invalidId(id, MIN_PREKEY_ID, MAX_PREKEY_ID);
    }
    if (!Number.isInteger(timestamp) || timestamp < 0) {
      throw new ValidationError(
        `SignedPreKey.generate: timestamp must be a non-negative integer (got ${timestamp})`,
        { timestamp },
      );
    }

    // 1. Generate a fresh Curve25519 keypair for this prekey
    const kp = generateKeyPair();

    // 2. Sign the PUBLIC key with the identity (XEd25519)
    //    This is what makes this a "signed" prekey — Bob (the relying party)
    //    can verify the prekey legitimately belongs to Alice using only her
    //    public identity key.
    const signature = identity.sign(kp.publicKey);

    return new SignedPreKey(id, kp.publicKey, kp.privateKey, signature, timestamp);
  }

  /**
   * Reconstruct from existing key material.
   *
   * Does NOT verify the signature — use `verify()` separately.
   */
  public static fromKeys(
    id: number,
    publicKey: Buffer | Uint8Array,
    privateKey: Buffer | Uint8Array,
    signature: Buffer | Uint8Array,
    timestamp: number,
  ): SignedPreKey {
    if (!isValidPreKeyId(id)) {
      throw PreKeyError.invalidId(id, MIN_PREKEY_ID, MAX_PREKEY_ID);
    }
    if (!Number.isInteger(timestamp) || timestamp < 0) {
      throw new ValidationError(
        `SignedPreKey.fromKeys: timestamp must be a non-negative integer (got ${timestamp})`,
        { timestamp },
      );
    }
    const pubBuf = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
    const privBuf = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey);
    const sigBuf = Buffer.isBuffer(signature) ? signature : Buffer.from(signature);
    if (sigBuf.length !== SIGNATURE_SIZE) {
      throw ValidationError.wrongSize('signature', SIGNATURE_SIZE, sigBuf.length);
    }
    return new SignedPreKey(
      id,
      asPublicKey(pubBuf),
      asPrivateKey(privBuf),
      asSignature(sigBuf),
      timestamp,
    );
  }

  /**
   * Construct from a received server payload, VERIFYING the signature
   * against the given public identity key.
   *
   * Use this when receiving a payload from another party.
   * Note: the resulting SignedPreKey will NOT contain a private key
   * (we received it from someone else). For local generation, use `generate()`.
   *
   * For received payloads where you only have the public side, use
   * `PublicSignedPreKey.fromPayload()` instead.
   *
   * @throws {SignatureError} if signature does not verify
   */
  public static fromVerifiedPayload(
    identityPub: PublicIdentityKey,
    payload: PublicSignedPreKeyPayload,
  ): PublicSignedPreKey {
    return PublicSignedPreKey.fromPayload(identityPub, payload);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Verification
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Verify this prekey's signature against the given identity public key.
   *
   * @returns true if the signature is valid
   *
   * @example
   * ```ts
   * const alicePub = alice.toPublic();
   * if (!spk.verify(alicePub)) {
   *   throw new Error('signed prekey is forged or corrupted');
   * }
   * ```
   */
  public verify(identityPub: PublicIdentityKey): boolean {
    if (!(identityPub instanceof PublicIdentityKey)) {
      return false;
    }
    return identityPub.verifyBool(this.publicKey, this.signature);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Lifecycle / Rotation
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Age of this prekey in milliseconds.
   *
   * @param now - Reference time (defaults to Date.now())
   */
  public ageMs(now: number = Date.now()): number {
    return Math.max(0, now - this.timestamp);
  }

  /**
   * True if this prekey is past the recommended rotation interval
   * (default: 7 days).
   *
   * @param threshold - Custom rotation threshold in ms
   */
  public needsRotation(threshold: number = SIGNED_PREKEY_ROTATION_MS): boolean {
    return this.ageMs() >= threshold;
  }

  /**
   * True if this prekey is past the hard expiration age
   * (default: 30 days). Expired prekeys MUST NOT be used for new sessions.
   *
   * @param maxAge - Custom maximum age in ms
   */
  public isExpired(maxAge: number = SIGNED_PREKEY_MAX_AGE_MS): boolean {
    return this.ageMs() >= maxAge;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Serialization
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Serialize to JSON-safe form (includes PRIVATE key — store securely).
   */
  public serialize(): SerializedSignedPreKey {
    return {
      id: this.id,
      publicKey: this.publicKey.toString('hex'),
      privateKey: this.privateKey.toString('hex'),
      signature: this.signature.toString('hex'),
      timestamp: this.timestamp,
    };
  }

  /**
   * Deserialize from stored form.
   *
   * @throws {SerializationError} on malformed input
   */
  public static deserialize(data: unknown): SignedPreKey {
    if (data === null || typeof data !== 'object') {
      throw new SerializationError(
        'Invalid SignedPreKey data: expected object',
        { received: data === null ? 'null' : typeof data },
      );
    }
    const obj = data as Record<string, unknown>;

    if (typeof obj['id'] !== 'number') {
      throw new SerializationError('SignedPreKey: id must be a number');
    }
    if (typeof obj['publicKey'] !== 'string') {
      throw new SerializationError('SignedPreKey: publicKey must be hex string');
    }
    if (typeof obj['privateKey'] !== 'string') {
      throw new SerializationError('SignedPreKey: privateKey must be hex string');
    }
    if (typeof obj['signature'] !== 'string') {
      throw new SerializationError('SignedPreKey: signature must be hex string');
    }
    if (typeof obj['timestamp'] !== 'number') {
      throw new SerializationError('SignedPreKey: timestamp must be a number');
    }

    const HEX_REGEX = /^[0-9a-fA-F]+$/;
    for (const field of ['publicKey', 'privateKey', 'signature'] as const) {
      if (!HEX_REGEX.test(obj[field] as string)) {
        throw new SerializationError(`SignedPreKey: ${field} is not valid hex`);
      }
    }

    const pubBuf = Buffer.from(obj['publicKey'], 'hex');
    const privBuf = Buffer.from(obj['privateKey'], 'hex');
    const sigBuf = Buffer.from(obj['signature'], 'hex');

    if (pubBuf.length !== PUBLIC_KEY_SIZE) {
      throw new SerializationError(
        `SignedPreKey: publicKey size ${pubBuf.length} (expected ${PUBLIC_KEY_SIZE})`,
      );
    }
    if (privBuf.length !== PRIVATE_KEY_SIZE) {
      throw new SerializationError(
        `SignedPreKey: privateKey size ${privBuf.length} (expected ${PRIVATE_KEY_SIZE})`,
      );
    }
    if (sigBuf.length !== SIGNATURE_SIZE) {
      throw new SerializationError(
        `SignedPreKey: signature size ${sigBuf.length} (expected ${SIGNATURE_SIZE})`,
      );
    }

    return SignedPreKey.fromKeys(obj['id'], pubBuf, privBuf, sigBuf, obj['timestamp']);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Accessors
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Get the public-facing payload (safe to upload to server).
   */
  public toPayload(): PublicSignedPreKeyPayload {
    return {
      id: this.id,
      publicKey: this.publicKey.toString('hex'),
      signature: this.signature.toString('hex'),
      timestamp: this.timestamp,
    };
  }

  /**
   * Get the public form (without private key).
   */
  public toPublic(): PublicSignedPreKey {
    return new PublicSignedPreKey(this.id, this.publicKey, this.signature, this.timestamp);
  }

  /**
   * SHA-256 hash of the public key.
   */
  public fingerprint(): string {
    return sha256(this.publicKey).toString('hex');
  }

  // ───────────────────────────────────────────────────────────────────────
  // Safe Output (does NOT leak private key)
  // ───────────────────────────────────────────────────────────────────────

  public toString(): string {
    return `SignedPreKey(id=${this.id}, public=${this.fingerprint().slice(0, 16)}..., timestamp=${this.timestamp})`;
  }

  public toJSON(): { type: string; id: number; publicKey: string; signature: string; timestamp: number } {
    return {
      type: 'SignedPreKey',
      id: this.id,
      publicKey: this.publicKey.toString('hex'),
      signature: this.signature.toString('hex'),
      timestamp: this.timestamp,
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PublicSignedPreKey (received payload, signature verified)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A signed prekey from another party — only the public side and the
 * signature. The signature has already been verified against the
 * identity public key.
 */
export class PublicSignedPreKey {
  public readonly id: number;
  public readonly publicKey: PublicKey;
  public readonly signature: Signature;
  public readonly timestamp: number;

  constructor(
    id: number,
    publicKey: PublicKey | Buffer | Uint8Array,
    signature: Signature | Buffer | Uint8Array,
    timestamp: number,
  ) {
    if (!isValidPreKeyId(id)) {
      throw PreKeyError.invalidId(id, MIN_PREKEY_ID, MAX_PREKEY_ID);
    }
    if (!Number.isInteger(timestamp) || timestamp < 0) {
      throw new ValidationError(
        `PublicSignedPreKey: timestamp must be a non-negative integer (got ${timestamp})`,
        { timestamp },
      );
    }
    const pubBuf = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
    const sigBuf = Buffer.isBuffer(signature) ? signature : Buffer.from(signature);
    if (sigBuf.length !== SIGNATURE_SIZE) {
      throw ValidationError.wrongSize('signature', SIGNATURE_SIZE, sigBuf.length);
    }
    this.id = id;
    this.publicKey = asPublicKey(pubBuf);
    this.signature = asSignature(sigBuf);
    this.timestamp = timestamp;
    Object.freeze(this);
  }

  /**
   * Construct from a received payload, VERIFYING the signature.
   *
   * This is the recommended path for handling untrusted input.
   *
   * @throws {SignatureError} if signature is invalid
   * @throws {SerializationError} on malformed input
   */
  public static fromPayload(
    identityPub: PublicIdentityKey,
    payload: PublicSignedPreKeyPayload,
  ): PublicSignedPreKey {
    if (!(identityPub instanceof PublicIdentityKey)) {
      throw ValidationError.wrongType('identityPub', 'PublicIdentityKey', identityPub);
    }
    if (payload === null || typeof payload !== 'object') {
      throw new SerializationError('Invalid signed prekey payload');
    }
    if (typeof payload.id !== 'number') {
      throw new SerializationError('SignedPreKey payload: id must be a number');
    }
    if (typeof payload.publicKey !== 'string') {
      throw new SerializationError('SignedPreKey payload: publicKey must be hex');
    }
    if (typeof payload.signature !== 'string') {
      throw new SerializationError('SignedPreKey payload: signature must be hex');
    }
    if (typeof payload.timestamp !== 'number') {
      throw new SerializationError('SignedPreKey payload: timestamp must be a number');
    }

    const HEX_REGEX = /^[0-9a-fA-F]+$/;
    if (!HEX_REGEX.test(payload.publicKey)) {
      throw new SerializationError('SignedPreKey payload: publicKey is not valid hex');
    }
    if (!HEX_REGEX.test(payload.signature)) {
      throw new SerializationError('SignedPreKey payload: signature is not valid hex');
    }

    const pubBuf = Buffer.from(payload.publicKey, 'hex');
    const sigBuf = Buffer.from(payload.signature, 'hex');

    if (pubBuf.length !== PUBLIC_KEY_SIZE) {
      throw new SerializationError(
        `SignedPreKey payload: publicKey size ${pubBuf.length} (expected ${PUBLIC_KEY_SIZE})`,
      );
    }
    if (sigBuf.length !== SIGNATURE_SIZE) {
      throw new SerializationError(
        `SignedPreKey payload: signature size ${sigBuf.length} (expected ${SIGNATURE_SIZE})`,
      );
    }

    // VERIFY the signature against the identity
    if (!identityPub.verifyBool(pubBuf, sigBuf)) {
      throw new SignatureError(
        `SignedPreKey signature verification failed for prekey id ${payload.id}`,
        { id: payload.id },
      );
    }

    return new PublicSignedPreKey(payload.id, pubBuf, sigBuf, payload.timestamp);
  }

  public ageMs(now: number = Date.now()): number {
    return Math.max(0, now - this.timestamp);
  }

  public isExpired(maxAge: number = SIGNED_PREKEY_MAX_AGE_MS): boolean {
    return this.ageMs() >= maxAge;
  }

  public fingerprint(): string {
    return sha256(this.publicKey).toString('hex');
  }

  public toString(): string {
    return `PublicSignedPreKey(id=${this.id}, public=${this.fingerprint().slice(0, 16)}..., timestamp=${this.timestamp})`;
  }

  public toJSON(): { type: string; id: number; publicKey: string; signature: string; timestamp: number } {
    return {
      type: 'PublicSignedPreKey',
      id: this.id,
      publicKey: this.publicKey.toString('hex'),
      signature: this.signature.toString('hex'),
      timestamp: this.timestamp,
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards
// ═══════════════════════════════════════════════════════════════════════════

export function isSignedPreKey(value: unknown): value is SignedPreKey {
  return value instanceof SignedPreKey;
}

export function isPublicSignedPreKey(value: unknown): value is PublicSignedPreKey {
  return value instanceof PublicSignedPreKey;
}
