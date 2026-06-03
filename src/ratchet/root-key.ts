/**
 * Root Key Derivation (DH Ratchet Step)
 *
 * Implements the DH ratchet of the Double Ratchet algorithm.
 *
 * When one party sends a message with a NEW DH public key, both parties
 * run this step to derive:
 *   1. A new RootKey (chained from the previous root key)
 *   2. A new ChainKey (seeds the next symmetric ratchet)
 *
 * Spec:
 *   dh_output = DH(my_dh_private, their_dh_public)
 *   (RK_new, CK_new) = KDF_RK(RK_old, dh_output)
 *
 * Where:
 *   KDF_RK(rk, dh) = HKDF-SHA256(
 *     salt = rk,                  // the OLD root key is the HKDF salt
 *     ikm  = dh,                  // the DH output is the input key material
 *     info = "Signalis_RatchetRoot_v1",
 *     L    = 64                   // 32 bytes for new RK + 32 bytes for new CK
 *   )
 *
 * @module ratchet/root-key
 */

import { diffieHellman, hkdf } from '../crypto';
import type { PrivateKey, PublicKey, RootKey } from '../types';
import { asRootKey, asChainKey } from '../types';
import {
  ROOT_KEY_SIZE,
  CHAIN_KEY_SIZE,
  getRatchetRootInfo,
} from '../constants';
import { ValidationError } from '../errors';
import type { RootKeyDerivation } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// deriveRootKey
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Perform one DH ratchet step.
 *
 * @param previousRootKey The current/previous root key (32 bytes)
 * @param myDhPrivate     My current ratchet DH private key
 * @param theirDhPublic   Their ratchet DH public key (just received)
 *
 * @returns
 *   - `rootKey`: new 32-byte root key for the next DH ratchet step
 *   - `chainKey`: new 32-byte chain key seeding the next symmetric chain
 *
 * @throws {ValidationError} On wrong key sizes
 *
 * @example
 * ```ts
 * const { rootKey: newRK, chainKey: newCK } = deriveRootKey(
 *   currentRootKey,
 *   myRatchetKp.privateKey,
 *   theirRatchetPub,
 * );
 * ```
 */
export function deriveRootKey(
  previousRootKey: RootKey,
  myDhPrivate: PrivateKey,
  theirDhPublic: PublicKey,
): RootKeyDerivation {
  // ─── Validate sizes ───────────────────────────────────────────────────
  if (!Buffer.isBuffer(previousRootKey) || previousRootKey.length !== ROOT_KEY_SIZE) {
    throw new ValidationError(
      `deriveRootKey: previousRootKey must be ${ROOT_KEY_SIZE} bytes`,
      { actual: previousRootKey?.length, expected: ROOT_KEY_SIZE },
    );
  }

  // ─── 1. Run DH to get shared output ───────────────────────────────────
  const dhOutput = diffieHellman(myDhPrivate, theirDhPublic);

  // ─── 2. HKDF: salt = old RK, ikm = DH output, info = ratchet info ─────
  // Output is 64 bytes: first 32 = new RK, last 32 = new CK
  const derived = hkdf(
    previousRootKey,        // salt = old root key
    dhOutput,               // ikm  = DH output
    getRatchetRootInfo(),   // info = "Signalis_RatchetRoot_v1"
    ROOT_KEY_SIZE + CHAIN_KEY_SIZE,  // L = 64
  );

  const newRootKey = asRootKey(derived.subarray(0, ROOT_KEY_SIZE));
  const newChainKey = asChainKey(
    derived.subarray(ROOT_KEY_SIZE, ROOT_KEY_SIZE + CHAIN_KEY_SIZE),
  );

  return {
    rootKey: newRootKey,
    chainKey: newChainKey,
  };
}
