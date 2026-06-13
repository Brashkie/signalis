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

/** AES-CBC IV size in bytes (16 = 1 AES block) */
export const AES_CBC_IV_SIZE = 16 as const;

/** AES-GCM nonce size in bytes (12, NOT 16) */
export const AES_NONCE_SIZE = 12 as const;

/** AES-GCM auth tag size in bytes */
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
export const VERSION = '0.6.0' as const;

/** Signal Protocol version */
export const PROTOCOL_VERSION = 3 as const;

// ═══════════════════════════════════════════════════════════════════════════
// Domain Separation (HKDF info strings)
//
// IMPORTANT: These are returned as getters that produce fresh Buffer copies,
// preventing accidental mutation of shared state.
// ═══════════════════════════════════════════════════════════════════════════

const X3DH_INFO_STR = 'Signalis_X3DH_v1';
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

// ═══════════════════════════════════════════════════════════════════════════
// X3DH Constants (NEW v0.4.0)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * X3DH derived shared secret size in bytes (32).
 *
 * This is the size of the root key fed into the Double Ratchet.
 */
export const X3DH_SECRET_SIZE = 32 as const;

/**
 * X3DH HKDF salt — a string of zero bytes of length HASH_SIZE (32).
 *
 * The Signal X3DH spec requires the salt to be 32 zero bytes:
 * https://signal.org/docs/specifications/x3dh/#sending-the-initial-message
 *
 * Returns a fresh Buffer each call to prevent accidental mutation.
 */
export function getX3DHSalt(): Buffer {
  return Buffer.alloc(HASH_SIZE, 0x00);
}

/**
 * X3DH HKDF prefix — a string of 32 0xFF bytes prepended to the DH outputs.
 *
 * The Signal X3DH spec for Curve25519 requires F = 0xFF * 32 to differentiate
 * X3DH HKDF inputs from typical Curve25519 byte strings:
 * https://signal.org/docs/specifications/x3dh/#cryptographic-notation
 *
 * Returns a fresh Buffer each call.
 */
export function getX3DHPrefix(): Buffer {
  return Buffer.alloc(HASH_SIZE, 0xff);
}

/**
 * Maximum age (ms) of a one-time prekey id reference in initial messages,
 * after which the message should be considered stale.
 *
 * Default: 30 days. Implementations can override.
 */
export const X3DH_INITIAL_MESSAGE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

// ═══════════════════════════════════════════════════════════════════════════
// Double Ratchet Constants (NEW v0.5.0)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Size of a RootKey in bytes (32 — same as SHA-256 output).
 */
export const ROOT_KEY_SIZE = 32 as const;

/**
 * Size of a ChainKey in bytes (32).
 */
export const CHAIN_KEY_SIZE = 32 as const;

/**
 * Material derived per message: 32 bytes AES key + 32 bytes HMAC key + 16 bytes IV.
 *
 * Total = 80 bytes from HKDF-SHA256(MK_seed).
 */
export const MESSAGE_KEY_MATERIAL_SIZE = 80 as const;

/** AES-256 key portion of MessageKey material (first 32 bytes). */
export const MESSAGE_KEY_AES_OFFSET = 0;
/** HMAC-SHA256 key portion of MessageKey material (bytes 32-63). */
export const MESSAGE_KEY_HMAC_OFFSET = 32;
/** AES-CBC IV portion of MessageKey material (bytes 64-79). */
export const MESSAGE_KEY_IV_OFFSET = 64;

/**
 * Truncated MAC size for over-the-wire messages.
 *
 * Signal spec truncates the 32-byte HMAC-SHA256 output to 8 bytes for
 * bandwidth savings. Still cryptographically secure for authentication.
 */
export const MAC_TRUNCATE_SIZE = 8 as const;

/**
 * Maximum number of out-of-order messages whose keys we'll buffer.
 *
 * This is an anti-DoS limit: an attacker could send `header.n = 2^32 - 1`
 * to force us to derive billions of message keys. By capping at 2000 (the
 * value libsignal uses), we balance practical out-of-order delivery
 * tolerance against memory/CPU consumption.
 *
 * If a legitimate scenario requires higher, set it per-session in Sprint 3
 * Part 2 (Session class config).
 */
export const MAX_SKIPPED_MESSAGE_KEYS = 2000 as const;

/**
 * HMAC inputs for chain-key advancement (Signal spec § "Symmetric-key ratchet").
 *
 *   CK_next   = HMAC-SHA256(CK, 0x02)
 *   MK_seed   = HMAC-SHA256(CK, 0x01)
 */
export const KDF_CK_NEXT_INPUT = 0x02;
export const KDF_CK_MESSAGE_INPUT = 0x01;

/**
 * HKDF info string for root-key derivation (DH ratchet step).
 *
 *   (RK_new, CK_new) = KDF_RK(RK_old, DH_output)
 */
const KDF_RK_INFO_STR = 'Signalis_RatchetRoot_v1';
export function getRatchetRootInfo(): Buffer {
  return Buffer.from(KDF_RK_INFO_STR, 'utf-8');
}

/**
 * HKDF info string for deriving (AES key, HMAC key, IV) from a MessageKey seed.
 */
const MESSAGE_KEY_INFO_STR = 'Signalis_MessageKeys_v1';
export function getMessageKeyInfo(): Buffer {
  return Buffer.from(MESSAGE_KEY_INFO_STR, 'utf-8');
}
