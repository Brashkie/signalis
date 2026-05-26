/**
 * Signalis Type Definitions
 *
 * Uses branded types for compile-time safety, ensuring you cannot
 * accidentally swap a PublicKey with a PrivateKey.
 *
 * @module types
 */

import {
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  SIGNATURE_SIZE,
  HASH_SIZE,
  MAC_SIZE,
  AES_KEY_SIZE,
  AES_NONCE_SIZE,
} from './constants';
import { ValidationError } from './errors';

// ═══════════════════════════════════════════════════════════════════════════
// Branded Types
//
// These nominal types prevent mixing up buffer types that have the same
// underlying representation but different semantic meaning.
// ═══════════════════════════════════════════════════════════════════════════

const __publicKeyBrand: unique symbol = Symbol('PublicKey');
const __privateKeyBrand: unique symbol = Symbol('PrivateKey');
const __signatureBrand: unique symbol = Symbol('Signature');
const __sharedSecretBrand: unique symbol = Symbol('SharedSecret');
const __chainKeyBrand: unique symbol = Symbol('ChainKey');
const __messageKeyBrand: unique symbol = Symbol('MessageKey');
const __rootKeyBrand: unique symbol = Symbol('RootKey');

/** A 32-byte Curve25519 public key. */
export type PublicKey = Buffer & { readonly [__publicKeyBrand]: true };

/** A 32-byte Curve25519 private key. */
export type PrivateKey = Buffer & { readonly [__privateKeyBrand]: true };

/** A 64-byte signature. */
export type Signature = Buffer & { readonly [__signatureBrand]: true };

/** A 32-byte shared secret from ECDH. */
export type SharedSecret = Buffer & { readonly [__sharedSecretBrand]: true };

/** A 32-byte chain key (Double Ratchet). */
export type ChainKey = Buffer & { readonly [__chainKeyBrand]: true };

/** A 32-byte message key (Double Ratchet). */
export type MessageKey = Buffer & { readonly [__messageKeyBrand]: true };

/** A 32-byte root key (Double Ratchet). */
export type RootKey = Buffer & { readonly [__rootKeyBrand]: true };

// ═══════════════════════════════════════════════════════════════════════════
// Validation & Branded Type Constructors
//
// Each `asXxx` function performs runtime validation and returns the buffer
// with a brand applied (a no-op at runtime, type-only at compile time).
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Internal validator for buffer of specific size.
 * @internal
 */
function assertBufferOfSize(
  buf: unknown,
  size: number,
  fieldName: string,
): asserts buf is Buffer {
  if (!Buffer.isBuffer(buf)) {
    throw ValidationError.wrongType(fieldName, 'Buffer', buf);
  }
  if (buf.length !== size) {
    throw ValidationError.wrongSize(fieldName, size, buf.length);
  }
}

/**
 * Convert a Buffer to a PublicKey (with validation).
 *
 * @throws ValidationError if buffer is not 32 bytes or not a Buffer
 */
export function asPublicKey(buf: unknown): PublicKey {
  assertBufferOfSize(buf, PUBLIC_KEY_SIZE, 'PublicKey');
  return buf as PublicKey;
}

/**
 * Convert a Buffer to a PrivateKey (with validation).
 *
 * @throws ValidationError if buffer is not 32 bytes or not a Buffer
 */
export function asPrivateKey(buf: unknown): PrivateKey {
  assertBufferOfSize(buf, PRIVATE_KEY_SIZE, 'PrivateKey');
  return buf as PrivateKey;
}

/**
 * Convert a Buffer to a Signature (with validation).
 *
 * @throws ValidationError if buffer is not 64 bytes or not a Buffer
 */
export function asSignature(buf: unknown): Signature {
  assertBufferOfSize(buf, SIGNATURE_SIZE, 'Signature');
  return buf as Signature;
}

/**
 * Convert a Buffer to a SharedSecret (with validation).
 */
export function asSharedSecret(buf: unknown): SharedSecret {
  assertBufferOfSize(buf, 32, 'SharedSecret');
  return buf as SharedSecret;
}

/**
 * Convert a Buffer to a ChainKey (with validation).
 */
export function asChainKey(buf: unknown): ChainKey {
  assertBufferOfSize(buf, 32, 'ChainKey');
  return buf as ChainKey;
}

/**
 * Convert a Buffer to a MessageKey (with validation).
 */
export function asMessageKey(buf: unknown): MessageKey {
  assertBufferOfSize(buf, 32, 'MessageKey');
  return buf as MessageKey;
}

/**
 * Convert a Buffer to a RootKey (with validation).
 */
export function asRootKey(buf: unknown): RootKey {
  assertBufferOfSize(buf, 32, 'RootKey');
  return buf as RootKey;
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if a value is a valid public key.
 */
export function isPublicKey(value: unknown): value is PublicKey {
  return Buffer.isBuffer(value) && value.length === PUBLIC_KEY_SIZE;
}

/**
 * Check if a value is a valid private key.
 */
export function isPrivateKey(value: unknown): value is PrivateKey {
  return Buffer.isBuffer(value) && value.length === PRIVATE_KEY_SIZE;
}

/**
 * Check if a value is a valid signature.
 */
export function isSignature(value: unknown): value is Signature {
  return Buffer.isBuffer(value) && value.length === SIGNATURE_SIZE;
}

// ═══════════════════════════════════════════════════════════════════════════
// Core Interfaces
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A Curve25519 key pair.
 */
export interface KeyPair {
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
}

/**
 * Identity information for a user/device.
 */
export interface IdentityInfo {
  readonly registrationId: number;
  readonly deviceId: number;
}

/**
 * Serialized form of a key pair (for storage).
 * Both keys are hex-encoded strings.
 */
export interface SerializedKeyPair {
  readonly publicKey: string;
  readonly privateKey: string;
}

/**
 * Type re-exports of constants for convenience.
 */
export type {
  // Numeric constants don't need to be re-exported as types,
  // but we can re-export from here for ergonomic imports.
};

// Convenience re-exports of size constants
export { PUBLIC_KEY_SIZE, PRIVATE_KEY_SIZE, SIGNATURE_SIZE, HASH_SIZE, MAC_SIZE, AES_KEY_SIZE, AES_NONCE_SIZE };
