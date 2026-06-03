/**
 * Double Ratchet Type Definitions
 *
 * Interface types used across the ratchet module.
 *
 * @module ratchet/types
 */

import type { ChainKey, MessageKey, RootKey } from '../types';

/**
 * Output of the DH ratchet step: a new root key + new chain key.
 *
 * Spec:
 *   (RK_new, CK_new) = KDF_RK(RK_old, DH(my_priv, their_pub))
 */
export interface RootKeyDerivation {
  readonly rootKey: RootKey;
  readonly chainKey: ChainKey;
}

/**
 * Output of the symmetric chain ratchet step.
 *
 * Spec:
 *   CK_next  = HMAC-SHA256(CK, 0x02)
 *   MK_seed  = HMAC-SHA256(CK, 0x01)
 */
export interface ChainKeyAdvancement {
  readonly nextChainKey: ChainKey;
  readonly messageKey: MessageKey;
  /** The counter value before advancing (i.e. the message number THIS key encrypts) */
  readonly counter: number;
}

/**
 * Concrete encryption material derived from a MessageKey via HKDF.
 *
 * Layout from the 80-byte HKDF output:
 *   aesKey:  bytes 0..31  (AES-256-CBC)
 *   hmacKey: bytes 32..63 (HMAC-SHA256 for MAC)
 *   iv:      bytes 64..79 (AES-CBC IV)
 */
export interface MessageKeyMaterial {
  readonly aesKey: Buffer;
  readonly hmacKey: Buffer;
  readonly iv: Buffer;
}

/**
 * Wire-format message header (sent in front of every encrypted message).
 *
 * Fields:
 *   - dhPublicKey: sender's current ratchet DH public key
 *   - n: message counter in the current sending chain
 *   - pn: number of messages in the PREVIOUS chain (for skipped-key recovery)
 */
export interface MessageHeaderPayload {
  readonly dhPublicKey: string; // hex
  readonly n: number;
  readonly pn: number;
}

/**
 * Identifier for a skipped message key in the cache.
 *
 * We index skipped keys by (their_dh_pub_hex, message_number) so we can
 * recover the right key when an out-of-order message arrives.
 */
export interface SkippedKeyId {
  readonly dhPublicKeyHex: string;
  readonly counter: number;
}
