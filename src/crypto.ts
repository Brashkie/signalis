/**
 * Cryptographic Primitives (wraps @brashkie/signalis-core)
 *
 * This module re-exports the cryptographic primitives we need from
 * signalis-core, with type-safe wrappers using our branded types.
 *
 * @module crypto
 */

import {
  Curve25519 as CoreCurve25519,
  Ed25519 as CoreEd25519,
  XEd25519 as CoreXEd25519,
  HKDF as CoreHKDF,
  HMAC as CoreHMAC,
  SHA256 as CoreSHA256,
  AES_GCM as CoreAESGCM,
  secureRandom as coreSecureRandom,
} from '@brashkie/signalis-core';

import type { KeyPair, PublicKey, PrivateKey, Signature } from './types';
import { asPublicKey, asPrivateKey, asSignature } from './types';
import { ValidationError, SignatureError } from './errors';

// ─── Random ───────────────────────────────────────────────────────────────
/**
 * Generate cryptographically secure random bytes.
 */
export function randomBytes(size: number): Buffer {
  if (!Number.isInteger(size) || size < 0) {
    throw new ValidationError(`randomBytes: invalid size ${size}`);
  }
  return coreSecureRandom(size);
}

// ─── Curve25519 ───────────────────────────────────────────────────────────
/**
 * Generate a new Curve25519 key pair.
 */
export function generateKeyPair(): KeyPair {
  const kp = CoreCurve25519.generateKeyPair();
  return {
    publicKey: asPublicKey(kp.publicKey),
    privateKey: asPrivateKey(kp.privateKey),
  };
}

/**
 * Compute the Diffie-Hellman shared secret.
 */
export function diffieHellman(privateKey: PrivateKey, publicKey: PublicKey): Buffer {
  return CoreCurve25519.diffieHellman(privateKey, publicKey);
}

// ─── XEd25519 (Signal-style signatures with Curve25519 keys) ──────────────
/**
 * Sign data with a Curve25519 private key using XEd25519.
 *
 * This is the Signal Protocol's approach: the SAME Curve25519 keypair used
 * for ECDH (`diffieHellman`) is also used for signing. One identity key
 * serves both purposes.
 *
 * XEd25519 signatures are non-deterministic (use OS RNG).
 *
 * @param privateKey - Curve25519 private key (32 bytes)
 * @param message - The data to sign
 * @returns A 64-byte signature
 *
 * @example
 * ```ts
 * const identity = generateKeyPair();
 * const sig = signXEd25519(identity.privateKey, Buffer.from('I am alice'));
 * ```
 */
export function signXEd25519(privateKey: PrivateKey, message: Buffer): Signature {
  const sig = CoreXEd25519.sign(privateKey, message);
  return asSignature(sig);
}

/**
 * Deterministic XEd25519 signing — provide your own 64-byte random.
 *
 * Same `random` + same `privateKey` + same `message` always produces the
 * same signature. Useful for tests / reproducibility. For normal use,
 * prefer `signXEd25519`.
 *
 * @param privateKey - Curve25519 private key (32 bytes)
 * @param message - The data to sign
 * @param random - 64-byte randomness
 * @returns A 64-byte signature
 */
export function signXEd25519WithRandom(
  privateKey: PrivateKey,
  message: Buffer,
  random: Buffer,
): Signature {
  const sig = CoreXEd25519.signWithRandom(privateKey, message, random);
  return asSignature(sig);
}

/**
 * Verify an XEd25519 signature.
 *
 * @param publicKey - Curve25519 public key (32 bytes)
 * @param message - The data that was signed
 * @param signature - The signature to verify (64 bytes)
 * @throws {SignatureError} If verification fails
 */
export function verifyXEd25519(
  publicKey: PublicKey,
  message: Buffer,
  signature: Signature,
): void {
  try {
    CoreXEd25519.verify(publicKey, message, signature);
  } catch (e) {
    throw new SignatureError(
      `XEd25519 signature verification failed: ${(e as Error).message}`,
    );
  }
}

/**
 * Verify an XEd25519 signature, returning a boolean (no throw).
 */
export function verifyXEd25519Bool(
  publicKey: PublicKey,
  message: Buffer,
  signature: Buffer,
): boolean {
  return CoreXEd25519.verifyBool(publicKey, message, signature);
}

// ─── Ed25519 (standard signatures, separate keypair) ──────────────────────
/**
 * Generate a fresh Ed25519 keypair (separate from Curve25519).
 *
 * Most Signal-style code uses XEd25519 (above) so the same Curve25519 key
 * works for both ECDH and signing. Use Ed25519 only when you need:
 *   - Deterministic signatures (RFC 8032 compliance)
 *   - Reproducible keypairs from a seed
 *   - Separation between signing and ECDH keys
 *
 * @returns Object with `privateKey` (32 bytes) and `publicKey` (32 bytes)
 */
export function generateEd25519KeyPair(): { privateKey: Buffer; publicKey: Buffer } {
  const kp = CoreEd25519.generateKeyPair();
  return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

/**
 * Deterministically derive an Ed25519 keypair from a 32-byte seed.
 */
export function ed25519FromSeed(
  seed: Buffer,
): { privateKey: Buffer; publicKey: Buffer } {
  const kp = CoreEd25519.keyPairFromSeed(seed);
  return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

/**
 * Sign with an Ed25519 private key (deterministic, RFC 8032).
 */
export function signEd25519(privateKey: Buffer, message: Buffer): Signature {
  const sig = CoreEd25519.sign(privateKey, message);
  return asSignature(sig);
}

/**
 * Verify an Ed25519 signature.
 *
 * @throws {SignatureError} If verification fails
 */
export function verifyEd25519(
  publicKey: Buffer,
  message: Buffer,
  signature: Buffer,
): void {
  try {
    CoreEd25519.verify(publicKey, message, signature);
  } catch (e) {
    throw new SignatureError(
      `Ed25519 signature verification failed: ${(e as Error).message}`,
    );
  }
}

/**
 * Verify an Ed25519 signature, returning a boolean (no throw).
 */
export function verifyEd25519Bool(
  publicKey: Buffer,
  message: Buffer,
  signature: Buffer,
): boolean {
  return CoreEd25519.verifyBool(publicKey, message, signature);
}

// ─── HKDF ─────────────────────────────────────────────────────────────────
/**
 * HKDF-SHA256 key derivation.
 */
export function hkdf(
  salt: Buffer,
  ikm: Buffer,
  info: Buffer,
  outputLength: number,
): Buffer {
  return CoreHKDF.derive(salt, ikm, info, outputLength);
}

/**
 * Derive multiple keys at once using HKDF-SHA256.
 */
export function hkdfMultiple(
  salt: Buffer,
  ikm: Buffer,
  info: Buffer,
  lengths: number[],
): Buffer[] {
  return CoreHKDF.deriveMultiple(salt, ikm, info, lengths);
}

// ─── HMAC ─────────────────────────────────────────────────────────────────
/**
 * Compute HMAC-SHA256.
 */
export function hmac(key: Buffer, data: Buffer): Buffer {
  return CoreHMAC.sha256(key, data);
}

/**
 * Verify HMAC-SHA256 (constant-time).
 */
export function hmacVerify(key: Buffer, data: Buffer, tag: Buffer): boolean {
  return CoreHMAC.verifySha256(key, data, tag);
}

// ─── SHA-256 ──────────────────────────────────────────────────────────────
/**
 * Compute SHA-256 hash.
 */
export function sha256(data: Buffer): Buffer {
  return CoreSHA256.hash(data);
}

/**
 * Compute SHA-256 hash of multiple buffers (concatenated).
 */
export function sha256Multiple(...buffers: Buffer[]): Buffer {
  return CoreSHA256.hashAll(buffers);
}

// ─── AES-GCM ──────────────────────────────────────────────────────────────
/**
 * Encrypt with AES-256-GCM.
 */
export function aesGcmEncrypt(
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
): Buffer {
  return CoreAESGCM.encrypt(key, nonce, plaintext);
}

/**
 * Decrypt with AES-256-GCM.
 */
export function aesGcmDecrypt(
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
): Buffer {
  return CoreAESGCM.decrypt(key, nonce, ciphertext);
}

/**
 * Encrypt with AES-256-GCM and Additional Authenticated Data (AAD).
 *
 * The AAD is authenticated but NOT encrypted. Use for binding message
 * headers (or any context that must be tamper-evident) to the ciphertext.
 *
 * The same `aad` must be passed to `aesGcmDecryptWithAad` for decryption
 * to succeed.
 */
export function aesGcmEncryptWithAad(
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
  aad: Buffer,
): Buffer {
  return CoreAESGCM.encryptWithAad(key, nonce, plaintext, aad);
}

/**
 * Decrypt with AES-256-GCM and Additional Authenticated Data (AAD).
 *
 * The same `aad` used during encryption must be provided. Mismatched or
 * tampered AAD will cause decryption to fail with an AuthenticationError
 * (re-thrown from signalis-core).
 */
export function aesGcmDecryptWithAad(
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  aad: Buffer,
): Buffer {
  return CoreAESGCM.decryptWithAad(key, nonce, ciphertext, aad);
}

// ─── Re-export core for direct access if needed ───────────────────────────
export {
  CoreCurve25519 as Curve25519,
  CoreEd25519 as Ed25519,
  CoreXEd25519 as XEd25519,
  CoreHKDF as HKDF,
  CoreHMAC as HMAC,
  CoreSHA256 as SHA256,
  CoreAESGCM as AES_GCM,
};
