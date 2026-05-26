/**
 * Identity Key Pair
 *
 * The long-term identity key for a user. Generated once at registration
 * and never rotated.
 *
 * Used to:
 *   1. Identify the user across sessions
 *   2. Sign signed pre-keys (XEd25519)
 *   3. Participate in X3DH key agreement (ECDH on Curve25519)
 *   4. Provide a stable identity for safety number verification
 *
 * The Signal Protocol uses ONE Curve25519 keypair for both ECDH and
 * signing (via XEd25519). This module exposes `sign()` and `verify()`
 * methods on identity keys to support this.
 *
 * @security The private key MUST be stored securely (encrypted at rest)
 *           and never transmitted over the network.
 *
 * @module identity/identity-key
 */

import {
  generateKeyPair,
  sha256,
  signXEd25519,
  signXEd25519WithRandom,
  verifyXEd25519,
  verifyXEd25519Bool,
} from '../crypto';
import type { KeyPair, PublicKey, PrivateKey, Signature, SerializedKeyPair } from '../types';
import { asPublicKey, asPrivateKey } from '../types';
import { PUBLIC_KEY_SIZE, PRIVATE_KEY_SIZE } from '../constants';
import { ValidationError, SerializationError } from '../errors';

// ═══════════════════════════════════════════════════════════════════════════
// IdentityKeyPair (long-term identity)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A user's long-term identity key pair.
 *
 * @example Generate
 * ```ts
 * const identity = IdentityKeyPair.generate();
 * console.log(identity.fingerprint());
 * ```
 *
 * @example Sign data
 * ```ts
 * const sig = identity.sign(Buffer.from('hello'));
 * ```
 *
 * @example Persist
 * ```ts
 * // Save
 * const data = identity.serialize();
 * await db.save('identity', data);
 *
 * // Load
 * const data = await db.load('identity');
 * const identity = IdentityKeyPair.deserialize(data);
 * ```
 *
 * @example Share publicly
 * ```ts
 * const publicOnly = identity.toPublic();
 * sendToServer(publicOnly.toHex());
 * ```
 */
export class IdentityKeyPair implements KeyPair {
  public readonly publicKey: PublicKey;
  public readonly privateKey: PrivateKey;

  /**
   * @internal Use static factory methods instead.
   */
  private constructor(publicKey: PublicKey, privateKey: PrivateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;

    // Freeze to prevent reassignment (but doesn't freeze the underlying Buffers)
    Object.freeze(this);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Construction
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Generate a new random identity key pair.
   *
   * @example
   * ```ts
   * const identity = IdentityKeyPair.generate();
   * ```
   */
  public static generate(): IdentityKeyPair {
    const kp = generateKeyPair();
    return new IdentityKeyPair(kp.publicKey, kp.privateKey);
  }

  /**
   * Create an IdentityKeyPair from existing key material.
   * Use this when loading from storage.
   *
   * @throws {ValidationError} if either key is invalid
   *
   * @example
   * ```ts
   * const identity = IdentityKeyPair.fromKeys(
   *   storedPublicKey,
   *   storedPrivateKey
   * );
   * ```
   */
  public static fromKeys(
    publicKey: Buffer | Uint8Array,
    privateKey: Buffer | Uint8Array,
  ): IdentityKeyPair {
    const pubBuf = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
    const privBuf = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey);

    return new IdentityKeyPair(asPublicKey(pubBuf), asPrivateKey(privBuf));
  }

  // ───────────────────────────────────────────────────────────────────────
  // Signing & Verification (XEd25519 — Signal Protocol style)
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Sign a message with this identity key (XEd25519).
   *
   * Uses the SAME Curve25519 private key that participates in ECDH —
   * this is what the Signal Protocol does for identity keys.
   *
   * Signatures are non-deterministic (use OS RNG). Two signatures of the
   * same message will differ, but both verify against the public key.
   *
   * @param message - Bytes to sign
   * @returns 64-byte signature
   *
   * @example
   * ```ts
   * const alice = IdentityKeyPair.generate();
   * const sig = alice.sign(Buffer.from('I am alice'));
   *
   * // Bob verifies with Alice's PUBLIC key
   * alice.toPublic().verify(Buffer.from('I am alice'), sig); // ok
   * ```
   */
  public sign(message: Buffer): Signature {
    if (!Buffer.isBuffer(message)) {
      throw ValidationError.wrongType('message', 'Buffer', message);
    }
    return signXEd25519(this.privateKey, message);
  }

  /**
   * Deterministic signing with explicit randomness (mostly for testing).
   *
   * Same `random` + same `message` always produces the same signature.
   * In production, prefer `sign()` which uses OS randomness.
   *
   * @param message - Bytes to sign
   * @param random - 64-byte randomness
   * @returns 64-byte signature
   */
  public signWithRandom(message: Buffer, random: Buffer): Signature {
    if (!Buffer.isBuffer(message)) {
      throw ValidationError.wrongType('message', 'Buffer', message);
    }
    if (!Buffer.isBuffer(random)) {
      throw ValidationError.wrongType('random', 'Buffer', random);
    }
    if (random.length !== 64) {
      throw ValidationError.wrongSize('random', 64, random.length);
    }
    return signXEd25519WithRandom(this.privateKey, message, random);
  }

  /**
   * Verify a signature against this identity's PUBLIC key.
   *
   * Convenience method; for symmetry with `PublicIdentityKey.verify()`.
   *
   * @throws {SignatureError} If verification fails
   */
  public verify(message: Buffer, signature: Buffer): void {
    this.toPublic().verify(message, signature);
  }

  /**
   * Verify a signature, returning a boolean (no throw).
   */
  public verifyBool(message: Buffer, signature: Buffer): boolean {
    return this.toPublic().verifyBool(message, signature);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Serialization
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Serialize to a JSON-safe object for storage.
   *
   * @warning The result includes the PRIVATE KEY. Store securely!
   *
   * @example
   * ```ts
   * const data = identity.serialize();
   * await encryptedStorage.save(data);
   * ```
   */
  public serialize(): SerializedKeyPair {
    return {
      publicKey: this.publicKey.toString('hex'),
      privateKey: this.privateKey.toString('hex'),
    };
  }

  /**
   * Deserialize from stored format.
   *
   * @throws {SerializationError} if data is malformed
   *
   * @example
   * ```ts
   * const data = await encryptedStorage.load();
   * const identity = IdentityKeyPair.deserialize(data);
   * ```
   */
  public static deserialize(data: unknown): IdentityKeyPair {
    // Validate shape
    if (data === null || typeof data !== 'object') {
      throw new SerializationError(
        'Invalid identity key data: expected object',
        { received: data === null ? 'null' : typeof data },
      );
    }

    const obj = data as Record<string, unknown>;

    if (typeof obj['publicKey'] !== 'string') {
      throw new SerializationError(
        'Invalid identity key data: publicKey must be a hex string',
        { receivedType: typeof obj['publicKey'] },
      );
    }
    if (typeof obj['privateKey'] !== 'string') {
      throw new SerializationError(
        'Invalid identity key data: privateKey must be a hex string',
        { receivedType: typeof obj['privateKey'] },
      );
    }

    // Validate hex format
    const HEX_REGEX = /^[0-9a-fA-F]+$/;
    if (!HEX_REGEX.test(obj['publicKey'])) {
      throw new SerializationError('publicKey is not valid hex');
    }
    if (!HEX_REGEX.test(obj['privateKey'])) {
      throw new SerializationError('privateKey is not valid hex');
    }

    // Decode
    let pubBuf: Buffer;
    let privBuf: Buffer;
    try {
      pubBuf = Buffer.from(obj['publicKey'], 'hex');
      privBuf = Buffer.from(obj['privateKey'], 'hex');
    } catch (e) {
      throw new SerializationError(
        `Hex decoding failed: ${(e as Error).message}`,
      );
    }

    // Validate sizes
    if (pubBuf.length !== PUBLIC_KEY_SIZE) {
      throw new SerializationError(
        `Public key size mismatch: ${pubBuf.length} bytes (expected ${PUBLIC_KEY_SIZE})`,
        { actual: pubBuf.length, expected: PUBLIC_KEY_SIZE },
      );
    }
    if (privBuf.length !== PRIVATE_KEY_SIZE) {
      throw new SerializationError(
        `Private key size mismatch: ${privBuf.length} bytes (expected ${PRIVATE_KEY_SIZE})`,
        { actual: privBuf.length, expected: PRIVATE_KEY_SIZE },
      );
    }

    return IdentityKeyPair.fromKeys(pubBuf, privBuf);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Accessors & Comparison
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Get just the public part (safe to share over the network).
   */
  public toPublic(): PublicIdentityKey {
    return new PublicIdentityKey(this.publicKey);
  }

  /**
   * Check if this identity matches another (by public key only).
   */
  public equals(other: IdentityKeyPair | PublicIdentityKey | null | undefined): boolean {
    if (!other) return false;
    return this.publicKey.equals(other.publicKey);
  }

  /**
   * Compute a fingerprint for visual verification by users.
   *
   * Returns a SHA-256 hash of the public key as hex.
   * Compare these fingerprints between users to verify identity.
   *
   * @example
   * ```ts
   * console.log('My fingerprint:', identity.fingerprint());
   * // Compare with: contact.fingerprint()
   * ```
   */
  public fingerprint(): string {
    return sha256(this.publicKey).toString('hex');
  }

  /**
   * Get a short fingerprint (first 16 hex chars) for casual display.
   */
  public shortFingerprint(): string {
    return this.fingerprint().slice(0, 16);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Safe Output (does NOT leak private key)
  // ───────────────────────────────────────────────────────────────────────

  /**
   * String representation. Does NOT include the private key.
   */
  public toString(): string {
    return `IdentityKeyPair(public=${this.shortFingerprint()}...)`;
  }

  /**
   * JSON serialization. Does NOT include the private key.
   * Use serialize() when you need to persist the private key.
   */
  public toJSON(): { type: string; publicKey: string } {
    return {
      type: 'IdentityKeyPair',
      publicKey: this.publicKey.toString('hex'),
    };
  }

  /**
   * Inspect representation for Node.js console.log.
   * Does NOT include the private key.
   */
  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PublicIdentityKey (just the public key, safe to share)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The public portion of an identity key.
 *
 * This is what you share with other users to let them verify
 * your messages and start sessions with you.
 *
 * @example
 * ```ts
 * // Receive from contact
 * const contactKey = PublicIdentityKey.fromHex(receivedHex);
 *
 * // Verify a signature from that contact
 * contactKey.verify(message, signature); // throws SignatureError if invalid
 *
 * // Verify fingerprint with user
 * console.log('Verify:', contactKey.fingerprint());
 * ```
 */
export class PublicIdentityKey {
  public readonly publicKey: PublicKey;

  /**
   * Create from a PublicKey or raw Buffer.
   *
   * @throws {ValidationError} if input is not a valid 32-byte key
   */
  constructor(publicKey: PublicKey | Buffer | Uint8Array) {
    const buf = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
    this.publicKey = asPublicKey(buf);
    Object.freeze(this);
  }

  /**
   * Create from a hex string.
   *
   * @throws {ValidationError} if hex is invalid or wrong size
   *
   * @example
   * ```ts
   * const key = PublicIdentityKey.fromHex('abc123...');
   * ```
   */
  public static fromHex(hex: string): PublicIdentityKey {
    if (typeof hex !== 'string') {
      throw ValidationError.wrongType('fromHex input', 'string', hex);
    }

    const HEX_REGEX = /^[0-9a-fA-F]+$/;
    if (!HEX_REGEX.test(hex)) {
      throw new ValidationError('fromHex: invalid hex string (non-hex characters)');
    }

    const buf = Buffer.from(hex, 'hex');
    if (buf.length !== PUBLIC_KEY_SIZE) {
      throw ValidationError.wrongSize('public key hex', PUBLIC_KEY_SIZE, buf.length);
    }

    return new PublicIdentityKey(asPublicKey(buf));
  }

  /**
   * Create from base64.
   */
  public static fromBase64(b64: string): PublicIdentityKey {
    if (typeof b64 !== 'string') {
      throw ValidationError.wrongType('fromBase64 input', 'string', b64);
    }
    const buf = Buffer.from(b64, 'base64');
    if (buf.length !== PUBLIC_KEY_SIZE) {
      throw ValidationError.wrongSize('public key base64', PUBLIC_KEY_SIZE, buf.length);
    }
    return new PublicIdentityKey(asPublicKey(buf));
  }

  // ───────────────────────────────────────────────────────────────────────
  // Verification (XEd25519)
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Verify a signature against this public identity key.
   *
   * @param message - The data that was signed
   * @param signature - The signature to verify (64 bytes)
   * @throws {SignatureError} If verification fails
   *
   * @example
   * ```ts
   * const alicePub = PublicIdentityKey.fromHex(aliceHex);
   * try {
   *   alicePub.verify(message, signature);
   *   console.log('Signature is valid');
   * } catch (e) {
   *   console.error('Invalid signature!');
   * }
   * ```
   */
  public verify(message: Buffer, signature: Buffer): void {
    if (!Buffer.isBuffer(message)) {
      throw ValidationError.wrongType('message', 'Buffer', message);
    }
    if (!Buffer.isBuffer(signature)) {
      throw ValidationError.wrongType('signature', 'Buffer', signature);
    }
    verifyXEd25519(this.publicKey, message, signature as unknown as Signature);
  }

  /**
   * Verify a signature, returning a boolean instead of throwing.
   *
   * @example
   * ```ts
   * if (alicePub.verifyBool(message, signature)) {
   *   // valid
   * } else {
   *   // invalid
   * }
   * ```
   */
  public verifyBool(message: Buffer, signature: Buffer): boolean {
    if (!Buffer.isBuffer(message) || !Buffer.isBuffer(signature)) {
      return false;
    }
    if (signature.length !== 64) {
      return false;
    }
    return verifyXEd25519Bool(this.publicKey, message, signature);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Serialization & Output
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Serialize as hex string.
   */
  public toHex(): string {
    return this.publicKey.toString('hex');
  }

  /**
   * Serialize as base64.
   */
  public toBase64(): string {
    return this.publicKey.toString('base64');
  }

  /**
   * Compare with another key.
   */
  public equals(other: PublicIdentityKey | IdentityKeyPair | null | undefined): boolean {
    if (!other) return false;
    return this.publicKey.equals(other.publicKey);
  }

  /**
   * Compute full fingerprint (SHA-256 of public key).
   */
  public fingerprint(): string {
    return sha256(this.publicKey).toString('hex');
  }

  /**
   * Short fingerprint for casual display.
   */
  public shortFingerprint(): string {
    return this.fingerprint().slice(0, 16);
  }

  public toString(): string {
    return `PublicIdentityKey(${this.shortFingerprint()}...)`;
  }

  public toJSON(): { type: string; publicKey: string } {
    return {
      type: 'PublicIdentityKey',
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

/**
 * Type guard: check if a value is an IdentityKeyPair.
 */
export function isIdentityKeyPair(value: unknown): value is IdentityKeyPair {
  return value instanceof IdentityKeyPair;
}

/**
 * Type guard: check if a value is a PublicIdentityKey.
 */
export function isPublicIdentityKey(value: unknown): value is PublicIdentityKey {
  return value instanceof PublicIdentityKey;
}
