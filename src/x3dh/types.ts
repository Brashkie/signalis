/**
 * X3DH Protocol Types
 *
 * Type definitions used across the X3DH module.
 *
 * @module x3dh/types
 */

import type { PublicKey, SharedSecret } from '../types';

/**
 * The initial message Alice sends to Bob to start an X3DH session.
 *
 * Bob uses these fields plus his own private keys to derive the same
 * shared secret that Alice computed.
 *
 * @example
 * ```ts
 * // What Alice produces
 * const { sharedSecret, initialMessage } = X3DH.initiate(alice, bobBundle);
 *
 * // What gets sent over the network (initialMessage.toPayload())
 * {
 *   identityKey: '<alice IK hex>',
 *   ephemeralKey: '<alice EK hex>',
 *   signedPreKeyId: 1,
 *   oneTimePreKeyId: 42,  // or undefined
 *   registrationId: 12345,
 *   deviceId: 1,
 * }
 * ```
 */
export interface InitialMessagePayload {
  /** Alice's long-term identity key (public, hex-encoded) */
  readonly identityKey: string;
  /** Alice's fresh ephemeral key for this session (public, hex-encoded) */
  readonly ephemeralKey: string;
  /** The ID of Bob's signed pre-key Alice used */
  readonly signedPreKeyId: number;
  /** The ID of Bob's one-time pre-key Alice used (if any) */
  readonly oneTimePreKeyId?: number;
  /** Alice's registration ID (for routing/anti-spam) */
  readonly registrationId: number;
  /** Alice's device ID (for multi-device) */
  readonly deviceId: number;
}

/**
 * Result of `X3DH.initiate()`.
 *
 * - `sharedSecret`: 32-byte secret to seed the Double Ratchet root key
 * - `initialMessage`: payload to attach to the first encrypted message
 * - `ephemeralKeyPair`: the ephemeral key Alice generated (private side held
 *   only for the duration of the initial message; usually discarded after)
 */
export interface X3DHInitiateResult {
  readonly sharedSecret: SharedSecret;
  readonly initialMessage: InitialMessagePayload;
  readonly ephemeralPublicKey: PublicKey;
}

/**
 * Result of `X3DH.receive()` — just the derived shared secret.
 *
 * Bob doesn't produce a new message in X3DH (he just decrypts what Alice
 * sent and starts the Double Ratchet on the same secret).
 */
export interface X3DHReceiveResult {
  readonly sharedSecret: SharedSecret;
  /** Whether a one-time prekey was consumed (caller should delete it) */
  readonly oneTimePreKeyId: number | null;
}
