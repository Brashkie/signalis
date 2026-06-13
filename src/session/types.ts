/**
 * Double Ratchet Session Types
 *
 * Public types for the Session module.
 *
 * @module session/types
 */

import type { PublicIdentityKey } from '../identity/identity-key';

// ═══════════════════════════════════════════════════════════════════════════
// Encrypted Message (wire format)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The structure produced by `session.encrypt()` and consumed by
 * `session.decrypt()`.
 *
 * Serialized over the wire as JSON, or as a binary blob if you prefer.
 */
export interface EncryptedMessage {
  /** Header (binary, hex-encoded): dhPublicKey(32) || n(4 BE) || pn(4 BE) */
  readonly header: string;
  /** Ciphertext (hex-encoded), AES-256-CBC + PKCS#7 padded */
  readonly ciphertext: string;
  /** Truncated HMAC-SHA256 tag (16 hex chars = 8 bytes) */
  readonly mac: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// Init args
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Args for `Session.initiateFromX3DH(...)` — Alice's first session with Bob.
 *
 * Alice generates her first ratchet DH key and runs the FIRST DH ratchet
 * step against Bob's signed prekey, seeding her sending chain.
 */
export interface SessionInitiateArgs {
  /** The 32-byte secret produced by X3DH.initiate() */
  sharedSecret: Buffer;
  /** Bob's identity (for fingerprint tracking / display) */
  theirIdentityKey: PublicIdentityKey;
  /** Bob's signed prekey public — Alice's first DH target */
  theirSignedPreKeyPublic: Buffer;
  /** Optional: cap on cached skipped-message-keys (default: MAX_SKIPPED_MESSAGE_KEYS = 2000) */
  maxSkippedKeys?: number;
}

/**
 * Args for `Session.receiveFromX3DH(...)` — Bob's first session with Alice.
 *
 * Bob seeds his receiving chain. He doesn't have a sending chain yet —
 * it gets initialized when he calls `session.encrypt()` for the first time,
 * which triggers a DH ratchet rotation.
 */
export interface SessionReceiveArgs {
  /** The 32-byte secret derived by X3DH.receive() */
  sharedSecret: Buffer;
  /** My (Bob's) identity */
  myIdentityKey: PublicIdentityKey;
  /** My signed prekey private (paired with sharedSecret derivation) */
  mySignedPreKeyPrivate: Buffer;
  /** My signed prekey public (Alice's first DH target on her side) */
  mySignedPreKeyPublic: Buffer;
  /** Their (Alice's) identity */
  theirIdentityKey: PublicIdentityKey;
  /** Optional: cap on cached skipped-message-keys */
  maxSkippedKeys?: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// Serialization
// ═══════════════════════════════════════════════════════════════════════════

/**
 * JSON-safe snapshot of a Session for storage.
 *
 * All key material is hex-encoded; numbers are inline; arrays of skipped
 * keys preserve insertion order.
 *
 * Treat this as SECRET — if leaked, all session messages can be decrypted
 * by an attacker who also has the ciphertext history.
 */
export interface SerializedSession {
  readonly version: 1;
  readonly rootKey: string;
  readonly theirIdentityKeyHex: string;

  // Sending state
  readonly myCurrentDhPublicHex: string;
  readonly myCurrentDhPrivateHex: string;
  readonly sendingChainKey: string | null;
  readonly sendingCounter: number;
  readonly previousSendingCounter: number;

  // Receiving state
  readonly receivingChainKey: string | null;
  readonly receivingCounter: number;
  readonly lastReceivedDhPublicHex: string | null;

  // Skipped keys cache
  readonly skippedKeys: ReadonlyArray<{
    readonly dhPublicKeyHex: string;
    readonly counter: number;
    readonly messageKeyHex: string;
  }>;
  readonly maxSkippedKeys: number;
}
