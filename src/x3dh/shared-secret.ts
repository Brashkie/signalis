/**
 * X3DH Shared Secret Derivation
 *
 * Implements the cryptographic core of X3DH: 4 Diffie-Hellman exchanges
 * concatenated and run through HKDF-SHA256 to produce a 32-byte shared
 * secret that seeds the Double Ratchet.
 *
 * Spec: https://signal.org/docs/specifications/x3dh/
 *
 * @module x3dh/shared-secret
 */

import { diffieHellman, hkdf } from '../crypto';
import type { PrivateKey, PublicKey, SharedSecret } from '../types';
import { asSharedSecret } from '../types';
import {
  X3DH_SECRET_SIZE,
  getX3DHSalt,
  getX3DHPrefix,
  getX3DHInfo,
} from '../constants';

// ═══════════════════════════════════════════════════════════════════════════
// Initiator side (Alice)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compute the X3DH shared secret as the INITIATOR (Alice).
 *
 * Performs the 4 Diffie-Hellman operations the Signal X3DH spec describes:
 *   DH1 = DH(IK_A, SPK_B)      — my identity   ↔ their signed prekey
 *   DH2 = DH(EK_A, IK_B)       — my ephemeral  ↔ their identity
 *   DH3 = DH(EK_A, SPK_B)      — my ephemeral  ↔ their signed prekey
 *   DH4 = DH(EK_A, OPK_B)      — my ephemeral  ↔ their one-time prekey (if any)
 *
 * Then concatenates and runs through HKDF-SHA256.
 *
 * @param myIdentityPrivate    My (Alice's) long-term identity private key
 * @param myEphemeralPrivate   My fresh ephemeral private key for this session
 * @param theirIdentityPublic  Their (Bob's) identity public key
 * @param theirSignedPreKeyPublic  Their signed prekey public
 * @param theirOneTimePreKeyPublic Their one-time prekey public, or null
 * @returns 32-byte shared secret (suitable as Double Ratchet root key seed)
 *
 * @example
 * ```ts
 * const sharedSecret = computeInitiatorSharedSecret(
 *   alice.privateKey,         // IK_A priv
 *   ephemeralKp.privateKey,   // EK_A priv
 *   bob.publicKey,            // IK_B pub
 *   bobSpk.publicKey,         // SPK_B pub
 *   bobOpk?.publicKey ?? null // OPK_B pub or null
 * );
 * ```
 */
export function computeInitiatorSharedSecret(
  myIdentityPrivate: PrivateKey,
  myEphemeralPrivate: PrivateKey,
  theirIdentityPublic: PublicKey,
  theirSignedPreKeyPublic: PublicKey,
  theirOneTimePreKeyPublic: PublicKey | null,
): SharedSecret {
  // ─── 4 Diffie-Hellman operations ──────────────────────────────────────
  // Spec: https://signal.org/docs/specifications/x3dh/#sending-the-initial-message
  const dh1 = diffieHellman(myIdentityPrivate, theirSignedPreKeyPublic);
  const dh2 = diffieHellman(myEphemeralPrivate, theirIdentityPublic);
  const dh3 = diffieHellman(myEphemeralPrivate, theirSignedPreKeyPublic);
  const dh4 = theirOneTimePreKeyPublic
    ? diffieHellman(myEphemeralPrivate, theirOneTimePreKeyPublic)
    : null;

  return deriveFromDHs(dh1, dh2, dh3, dh4);
}

// ═══════════════════════════════════════════════════════════════════════════
// Responder side (Bob)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compute the X3DH shared secret as the RESPONDER (Bob).
 *
 * Bob does the 4 DHs from the OTHER side. Curve25519 ECDH is symmetric, so
 * `DH(priv_A, pub_B) === DH(priv_B, pub_A)`. Bob and Alice end up with the
 * same `SharedSecret` after this.
 *
 *   DH1 = DH(SPK_B, IK_A)
 *   DH2 = DH(IK_B,  EK_A)
 *   DH3 = DH(SPK_B, EK_A)
 *   DH4 = DH(OPK_B, EK_A)  (if Alice used an OPK)
 *
 * @param myIdentityPrivate    My (Bob's) identity private key
 * @param mySignedPreKeyPrivate  My signed prekey private
 * @param myOneTimePreKeyPrivate My one-time prekey private (if Alice used one)
 * @param theirIdentityPublic  Their (Alice's) identity public key
 * @param theirEphemeralPublic Their ephemeral public key for this session
 * @returns 32-byte shared secret matching the initiator's
 */
export function computeResponderSharedSecret(
  myIdentityPrivate: PrivateKey,
  mySignedPreKeyPrivate: PrivateKey,
  myOneTimePreKeyPrivate: PrivateKey | null,
  theirIdentityPublic: PublicKey,
  theirEphemeralPublic: PublicKey,
): SharedSecret {
  // ─── 4 Diffie-Hellman operations (mirror of initiator's) ──────────────
  const dh1 = diffieHellman(mySignedPreKeyPrivate, theirIdentityPublic);
  const dh2 = diffieHellman(myIdentityPrivate, theirEphemeralPublic);
  const dh3 = diffieHellman(mySignedPreKeyPrivate, theirEphemeralPublic);
  const dh4 = myOneTimePreKeyPrivate
    ? diffieHellman(myOneTimePreKeyPrivate, theirEphemeralPublic)
    : null;

  return deriveFromDHs(dh1, dh2, dh3, dh4);
}

// ═══════════════════════════════════════════════════════════════════════════
// Common derivation step
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Internal: HKDF the 4 DH outputs into a 32-byte shared secret.
 *
 * Spec:
 *   F  = 0xFF × 32       (prefix to differentiate from Curve25519 byte strings)
 *   KM = F || DH1 || DH2 || DH3 [|| DH4]
 *   SK = HKDF-SHA256(salt=0x00 × 32, IKM=KM, info="Signalis_X3DH_v1", L=32)
 */
function deriveFromDHs(
  dh1: Buffer,
  dh2: Buffer,
  dh3: Buffer,
  dh4: Buffer | null,
): SharedSecret {
  // Note: Curve25519 ECDH always returns exactly 32 bytes — verified at the
  // signalis-core/Rust layer. We rely on that contract here.

  // Build KM = F || DH1 || DH2 || DH3 [|| DH4]
  const f = getX3DHPrefix();
  const km = dh4
    ? Buffer.concat([f, dh1, dh2, dh3, dh4], f.length + 32 * 4)
    : Buffer.concat([f, dh1, dh2, dh3], f.length + 32 * 3);

  // HKDF-SHA256 → 32 bytes
  const salt = getX3DHSalt();
  const info = getX3DHInfo();
  const sk = hkdf(salt, km, info, X3DH_SECRET_SIZE);

  return asSharedSecret(sk);
}
