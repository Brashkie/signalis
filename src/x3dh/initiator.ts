/**
 * X3DH Initiator (Alice)
 *
 * Alice fetches Bob's PreKeyBundle from a server, verifies it, generates
 * an ephemeral keypair, performs the 4 Diffie-Hellman operations, derives
 * the shared secret via HKDF, and produces an `InitialMessage` to send to
 * Bob along with her first encrypted message.
 *
 * @module x3dh/initiator
 */

import { generateKeyPair } from '../crypto';
import { IdentityKeyPair } from '../identity/identity-key';
import { PreKeyBundle } from '../prekeys/prekey-bundle';
import { ValidationError, ProtocolError } from '../errors';
import { computeInitiatorSharedSecret } from './shared-secret';
import { InitialMessage } from './initial-message';
import type { X3DHInitiateResult } from './types';
import { SIGNED_PREKEY_MAX_AGE_MS } from '../constants';

// ═══════════════════════════════════════════════════════════════════════════
// Options
// ═══════════════════════════════════════════════════════════════════════════

export interface X3DHInitiateOptions {
  /**
   * My (Alice's) registration ID. Used to populate the initial message
   * so Bob knows which device/account to associate with this session.
   */
  myRegistrationId: number;

  /** My device ID. Defaults to 1. */
  myDeviceId?: number;

  /**
   * If true (default), reject bundles whose SignedPreKey is older than
   * SIGNED_PREKEY_MAX_AGE_MS. Set to false only for testing/debugging.
   */
  rejectExpiredSignedPreKey?: boolean;

  /**
   * Custom max age for the signed prekey (defaults to SIGNED_PREKEY_MAX_AGE_MS).
   * Only used when `rejectExpiredSignedPreKey` is true.
   */
  signedPreKeyMaxAgeMs?: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// initiate()
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Run the X3DH handshake as the initiator (Alice).
 *
 * @param myIdentity   My long-term identity key pair
 * @param theirBundle  The peer's verified PreKey Bundle (use PreKeyBundle.fromPayload)
 * @param options      Required registration ID, optional flags
 *
 * @returns
 *   - `sharedSecret`: 32-byte secret to seed the Double Ratchet root key
 *   - `initialMessage`: payload to send with the first encrypted message
 *   - `ephemeralPublicKey`: the public part of the ephemeral key
 *
 * @throws {ValidationError} On malformed inputs
 * @throws {ProtocolError}   If the bundle's signed prekey is expired (when checked)
 *
 * @example
 * ```ts
 * // Alice fetched Bob's bundle from a server
 * const bobBundle = PreKeyBundle.fromPayload(serverPayload);
 *
 * // Run the handshake
 * const result = X3DH.initiate(alice, bobBundle, {
 *   myRegistrationId: 12345,
 *   myDeviceId: 1,
 * });
 *
 * // result.sharedSecret will seed the Double Ratchet (Sprint 3)
 * // result.initialMessage goes alongside the first encrypted message
 * ```
 */
export function initiate(
  myIdentity: IdentityKeyPair,
  theirBundle: PreKeyBundle,
  options: X3DHInitiateOptions,
): X3DHInitiateResult {
  // ─── Input validation ─────────────────────────────────────────────────
  if (!(myIdentity instanceof IdentityKeyPair)) {
    throw ValidationError.wrongType('myIdentity', 'IdentityKeyPair', myIdentity);
  }
  if (!(theirBundle instanceof PreKeyBundle)) {
    throw ValidationError.wrongType('theirBundle', 'PreKeyBundle', theirBundle);
  }
  if (
    options === null ||
    typeof options !== 'object' ||
    typeof options.myRegistrationId !== 'number'
  ) {
    throw new ValidationError(
      'X3DH.initiate: options.myRegistrationId is required (number)',
      { options },
    );
  }

  // ─── Check signed prekey age (security gate) ──────────────────────────
  const rejectExpired = options.rejectExpiredSignedPreKey ?? true;
  const maxAge = options.signedPreKeyMaxAgeMs ?? SIGNED_PREKEY_MAX_AGE_MS;
  if (rejectExpired && theirBundle.signedPreKey.isExpired(maxAge)) {
    throw new ProtocolError(
      `X3DH.initiate: peer's signed prekey is expired (age ${theirBundle.signedPreKey.ageMs()}ms > ${maxAge}ms)`,
      {
        signedPreKeyId: theirBundle.signedPreKey.id,
        ageMs: theirBundle.signedPreKey.ageMs(),
        maxAgeMs: maxAge,
      },
    );
  }

  // ─── Generate ephemeral keypair (EK_A) ────────────────────────────────
  // This key is used once and discarded. Forward secrecy depends on it
  // being thrown away after deriving the secret.
  const ephemeral = generateKeyPair();

  // ─── Compute shared secret via 4 DHs + HKDF ───────────────────────────
  const sharedSecret = computeInitiatorSharedSecret(
    myIdentity.privateKey,
    ephemeral.privateKey,
    theirBundle.identityKey.publicKey,
    theirBundle.signedPreKey.publicKey,
    theirBundle.oneTimePreKey?.publicKey ?? null,
  );

  // ─── Build the initial message Bob will need ──────────────────────────
  const initialMessage = new InitialMessage({
    identityKey: myIdentity.toPublic(),
    ephemeralKey: ephemeral.publicKey,
    signedPreKeyId: theirBundle.signedPreKey.id,
    oneTimePreKeyId: theirBundle.oneTimePreKey?.id ?? null,
    registrationId: options.myRegistrationId,
    deviceId: options.myDeviceId ?? 1,
  });

  return {
    sharedSecret,
    initialMessage: initialMessage.toPayload(),
    ephemeralPublicKey: ephemeral.publicKey,
  };
}
