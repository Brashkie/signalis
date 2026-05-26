/**
 * Signalis Protocol Constants
 *
 * All constants are typed as `readonly` and defined `as const` for
 * compile-time immutability. Buffer constants use getters to return
 * fresh copies, preventing accidental mutation.
 *
 * @module constants
 */

// ═══════════════════════════════════════════════════════════════════════════
// Key Sizes (bytes)
// ═══════════════════════════════════════════════════════════════════════════

/** Curve25519 public key size in bytes */
export const PUBLIC_KEY_SIZE = 32 as const;

/** Curve25519 private key size in bytes */
export const PRIVATE_KEY_SIZE = 32 as const;

/** Ed25519/XEd25519 signature size in bytes */
export const SIGNATURE_SIZE = 64 as const;

/** SHA-256 hash output size in bytes */
export const HASH_SIZE = 32 as const;

/** HMAC-SHA256 tag size in bytes */
export const MAC_SIZE = 32 as const;

/** AES-256 key size in bytes */
export const AES_KEY_SIZE = 32 as const;

/** AES-GCM nonce size in bytes */
export const AES_NONCE_SIZE = 12 as const;

/** AES-GCM authentication tag size in bytes */
export const AES_TAG_SIZE = 16 as const;

// ═══════════════════════════════════════════════════════════════════════════
// PreKey Constants
// ═══════════════════════════════════════════════════════════════════════════

/** Maximum number of one-time pre-keys to generate at once */
export const MAX_ONE_TIME_PREKEYS = 100 as const;

/** Minimum number of one-time pre-keys to maintain on server */
export const MIN_ONE_TIME_PREKEYS = 10 as const;

/** Default batch size when generating one-time pre-keys */
export const DEFAULT_PREKEY_BATCH = 100 as const;

/** Maximum valid pre-key ID (2^24 - 1, like libsignal) */
export const MAX_PREKEY_ID = 0xffffff as const;

/** Minimum valid pre-key ID (must be >= 1) */
export const MIN_PREKEY_ID = 1 as const;

// ═══════════════════════════════════════════════════════════════════════════
// Signed PreKey Rotation
// ═══════════════════════════════════════════════════════════════════════════

/** Recommended signed pre-key rotation interval (7 days in ms) */
export const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;

/** Maximum age before forcing signed pre-key rotation (30 days in ms) */
export const SIGNED_PREKEY_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

// ═══════════════════════════════════════════════════════════════════════════
// Registration
// ═══════════════════════════════════════════════════════════════════════════

/** Maximum registration ID (14-bit value, like libsignal) */
export const MAX_REGISTRATION_ID = 16380 as const;

/** Minimum registration ID */
export const MIN_REGISTRATION_ID = 1 as const;

/** Default device ID (primary device) */
export const DEFAULT_DEVICE_ID = 1 as const;

/** Maximum device ID */
export const MAX_DEVICE_ID = 0x7fffffff as const;

// ═══════════════════════════════════════════════════════════════════════════
// Versioning
// ═══════════════════════════════════════════════════════════════════════════

/** Signalis library version */
export const VERSION = '0.2.0' as const;

/** Signal Protocol version */
export const PROTOCOL_VERSION = 3 as const;

// ═══════════════════════════════════════════════════════════════════════════
// Domain Separation (HKDF info strings)
//
// IMPORTANT: These are returned as getters that produce fresh Buffer copies,
// preventing accidental mutation of shared state.
// ═══════════════════════════════════════════════════════════════════════════

const X3DH_INFO_STR = 'Signalis_X3DH_Key';
const RATCHET_INFO_STR = 'Signalis_Ratchet_Root';
const CHAIN_INFO_STR = 'Signalis_Chain_Key';
const MESSAGE_INFO_STR = 'Signalis_Message_Key';
const SIGNED_PREKEY_CONTEXT_STR = 'Signalis_SPK_Sig_v1';

/** HKDF info string for X3DH key derivation (returns fresh copy each call) */
export function getX3DHInfo(): Buffer {
  return Buffer.from(X3DH_INFO_STR, 'utf-8');
}

/** HKDF info string for Double Ratchet root key */
export function getRatchetInfo(): Buffer {
  return Buffer.from(RATCHET_INFO_STR, 'utf-8');
}

/** HKDF info string for chain keys */
export function getChainInfo(): Buffer {
  return Buffer.from(CHAIN_INFO_STR, 'utf-8');
}

/** HKDF info string for message keys */
export function getMessageInfo(): Buffer {
  return Buffer.from(MESSAGE_INFO_STR, 'utf-8');
}

/** Domain separator for signed pre-key signatures */
export function getSignedPreKeyContext(): Buffer {
  return Buffer.from(SIGNED_PREKEY_CONTEXT_STR, 'utf-8');
}

// Also export the string forms for use cases where Buffer isn't needed
export const INFO_STRINGS = Object.freeze({
  X3DH: X3DH_INFO_STR,
  RATCHET: RATCHET_INFO_STR,
  CHAIN: CHAIN_INFO_STR,
  MESSAGE: MESSAGE_INFO_STR,
  SIGNED_PREKEY: SIGNED_PREKEY_CONTEXT_STR,
} as const);

// ═══════════════════════════════════════════════════════════════════════════
// Validation Helpers (used by other modules)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if a number is a valid pre-key ID.
 */
export function isValidPreKeyId(id: unknown): id is number {
  return (
    typeof id === 'number' &&
    Number.isInteger(id) &&
    id >= MIN_PREKEY_ID &&
    id <= MAX_PREKEY_ID
  );
}

/**
 * Check if a number is a valid registration ID.
 */
export function isValidRegistrationId(id: unknown): id is number {
  return (
    typeof id === 'number' &&
    Number.isInteger(id) &&
    id >= MIN_REGISTRATION_ID &&
    id <= MAX_REGISTRATION_ID
  );
}

/**
 * Check if a number is a valid device ID.
 */
export function isValidDeviceId(id: unknown): id is number {
  return (
    typeof id === 'number' &&
    Number.isInteger(id) &&
    id >= 1 &&
    id <= MAX_DEVICE_ID
  );
}
