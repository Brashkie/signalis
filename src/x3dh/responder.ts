/**
 * X3DH Responder (Bob)
 *
 * Bob receives Alice's `InitialMessage`, looks up his own private prekeys
 * (signed pre-key + optional one-time pre-key) using the IDs in the message,
 * and derives the same shared secret Alice produced.
 *
 * @module x3dh/responder
 */

import { IdentityKeyPair } from '../identity/identity-key';
import { SignedPreKey } from '../prekeys/signed-prekey';
import { OneTimePreKey } from '../prekeys/one-time-prekey';
import { ValidationError, PreKeyError } from '../errors';
import { computeResponderSharedSecret } from './shared-secret';
import { InitialMessage } from './initial-message';
import type { InitialMessagePayload, X3DHReceiveResult } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// receive()
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Run the X3DH handshake as the responder (Bob).
 *
 * Bob has stored his identity key, signed pre-key, and a pool of one-time
 * pre-keys. When Alice's initial message arrives, Bob looks up the SPK and
 * OPK referenced by ID and uses them with his identity to derive the shared
 * secret.
 *
 * @param myIdentity         My (Bob's) long-term identity
 * @param mySignedPreKey     The SignedPreKey whose ID matches `initialMessage.signedPreKeyId`
 * @param myOneTimePreKey    The OneTimePreKey whose ID matches `initialMessage.oneTimePreKeyId`, or null
 * @param initialMessage     Alice's initial message payload (or constructed object)
 *
 * @returns sharedSecret (32 bytes) + oneTimePreKeyId consumed (caller should delete)
 *
 * @throws {ValidationError} on malformed inputs
 * @throws {PreKeyError}     if the referenced one-time prekey is missing/wrong-id
 *
 * @example
 * ```ts
 * // Bob receives the initial message
 * const payload: InitialMessagePayload = await receive();
 *
 * // Look up the SPK + OPK from his store
 * const mySpk = await db.getSignedPreKey(payload.signedPreKeyId);
 * const myOpk = payload.oneTimePreKeyId !== undefined
 *   ? await db.getOneTimePreKey(payload.oneTimePreKeyId)
 *   : null;
 *
 * // Derive the secret
 * const { sharedSecret, oneTimePreKeyId } = X3DH.receive(
 *   bob, mySpk, myOpk, payload,
 * );
 *
 * // Delete the consumed one-time prekey (forward secrecy)
 * if (oneTimePreKeyId !== null) {
 *   await db.deleteOneTimePreKey(oneTimePreKeyId);
 * }
 * ```
 */
export function receive(
  myIdentity: IdentityKeyPair,
  mySignedPreKey: SignedPreKey,
  myOneTimePreKey: OneTimePreKey | null,
  initialMessage: InitialMessage | InitialMessagePayload,
): X3DHReceiveResult {
  // ─── Input validation ─────────────────────────────────────────────────
  if (!(myIdentity instanceof IdentityKeyPair)) {
    throw ValidationError.wrongType('myIdentity', 'IdentityKeyPair', myIdentity);
  }
  if (!(mySignedPreKey instanceof SignedPreKey)) {
    throw ValidationError.wrongType(
      'mySignedPreKey',
      'SignedPreKey',
      mySignedPreKey,
    );
  }
  if (
    myOneTimePreKey !== null &&
    myOneTimePreKey !== undefined &&
    !(myOneTimePreKey instanceof OneTimePreKey)
  ) {
    throw ValidationError.wrongType(
      'myOneTimePreKey',
      'OneTimePreKey | null',
      myOneTimePreKey,
    );
  }

  // Coerce payload-or-instance to InitialMessage
  const msg =
    initialMessage instanceof InitialMessage
      ? initialMessage
      : InitialMessage.fromPayload(initialMessage);

  // ─── Verify referenced SPK matches ────────────────────────────────────
  if (mySignedPreKey.id !== msg.signedPreKeyId) {
    throw new PreKeyError(
      `X3DH.receive: provided SignedPreKey id ${mySignedPreKey.id} does not match initial message id ${msg.signedPreKeyId}`,
      undefined,
      { provided: mySignedPreKey.id, expected: msg.signedPreKeyId },
    );
  }

  // ─── Verify OPK matches (or absence matches) ──────────────────────────
  if (msg.oneTimePreKeyId !== null) {
    // Alice claims to have used a OPK; Bob must provide the matching one
    if (myOneTimePreKey === null || myOneTimePreKey === undefined) {
      throw PreKeyError.notFound(msg.oneTimePreKeyId);
    }
    if (myOneTimePreKey.id !== msg.oneTimePreKeyId) {
      throw new PreKeyError(
        `X3DH.receive: provided OneTimePreKey id ${myOneTimePreKey.id} does not match initial message id ${msg.oneTimePreKeyId}`,
        undefined,
        { provided: myOneTimePreKey.id, expected: msg.oneTimePreKeyId },
      );
    }
  } else {
    // Alice didn't use a OPK; Bob shouldn't try to provide one
    // (warn — but don't throw; OPK is just discarded if extra)
    // We tolerate this: if Bob accidentally provides one, we just ignore it.
    // The shared secret is still derived correctly (without DH4).
  }

  // ─── Compute the same shared secret Alice computed ────────────────────
  const opkPrivate =
    msg.oneTimePreKeyId !== null && myOneTimePreKey
      ? myOneTimePreKey.privateKey
      : null;

  const sharedSecret = computeResponderSharedSecret(
    myIdentity.privateKey,
    mySignedPreKey.privateKey,
    opkPrivate,
    msg.identityKey.publicKey,
    msg.ephemeralKey,
  );

  return {
    sharedSecret,
    oneTimePreKeyId: msg.oneTimePreKeyId,
  };
}
