/**
 * Storage Layer Interfaces
 *
 * The four canonical Signal-style storage interfaces. Any production app
 * implements these for its preferred database (SQLite, IndexedDB, Redis,
 * Postgres, etc.) and plugs them into `StoreBundle`.
 *
 * Two bundled implementations come with `@brashkie/signalis`:
 *   - `MemoryIdentityStore`, etc. — in-process Map (testing, ephemeral)
 *   - `FileIdentityStore`, etc.   — JSON files on disk (Node.js apps)
 *
 * Custom implementations are encouraged.
 *
 * @module storage/types
 */

import type { IdentityKeyPair, PublicIdentityKey } from '../identity/identity-key';
import type { OneTimePreKey } from '../prekeys/one-time-prekey';
import type { SignedPreKey } from '../prekeys/signed-prekey';
import type { Session } from '../session';
import type { ProtocolAddress } from '../address';

// ═══════════════════════════════════════════════════════════════════════════
// IdentityStore — long-term identity + trusted-peers fingerprint cache
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Stores the user's own identity keypair, registration id, and tracks
 * the trusted public-identity-keys of remote peers (for TOFU / change
 * detection à la WhatsApp's "security number changed").
 */
export interface IdentityStore {
  /**
   * Save the user's own long-term identity key pair.
   * Should be called exactly once per registration. Subsequent calls
   * with a DIFFERENT key pair are a programmer error and may be
   * rejected by the impl.
   */
  saveIdentityKeyPair(keyPair: IdentityKeyPair): Promise<void>;

  /**
   * Load the user's own identity key pair, or null if not registered.
   */
  getIdentityKeyPair(): Promise<IdentityKeyPair | null>;

  /**
   * Save the user's registration id (assigned by the server, sent in
   * X3DH InitialMessage).
   */
  saveRegistrationId(id: number): Promise<void>;

  /**
   * Load the registration id, or null if not registered.
   */
  getRegistrationId(): Promise<number | null>;

  /**
   * Save a remote peer's public identity key. On first contact this is
   * trust-on-first-use (TOFU). Subsequent calls with a DIFFERENT key
   * for the same address should not silently overwrite — see
   * `isTrustedIdentity`.
   */
  saveTrustedIdentity(
    address: ProtocolAddress,
    key: PublicIdentityKey,
  ): Promise<void>;

  /**
   * Check whether the given key matches the one previously stored for
   * the address. Returns:
   *   - `true`  if no record exists yet (first contact, accept)
   *   - `true`  if the key matches the stored one
   *   - `false` if the key DIFFERS from the stored one (security warning)
   *
   * Apps SHOULD warn the user before proceeding if this returns `false`
   * (this is how WhatsApp's "security code changed" notification works).
   */
  isTrustedIdentity(
    address: ProtocolAddress,
    key: PublicIdentityKey,
  ): Promise<boolean>;
}

// ═══════════════════════════════════════════════════════════════════════════
// PreKeyStore — one-time prekeys
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Stores the user's batch of one-time prekeys. After a peer consumes
 * one, it must be deleted (Signal one-shot semantics — never reuse).
 */
export interface PreKeyStore {
  /**
   * Save (or overwrite) a one-time prekey by id.
   */
  savePreKey(id: number, preKey: OneTimePreKey): Promise<void>;

  /**
   * Load a prekey by id, or null if not present (already used + removed,
   * or never created).
   */
  getPreKey(id: number): Promise<OneTimePreKey | null>;

  /**
   * Cheap "does it exist" check. Equivalent to
   * `(await getPreKey(id)) !== null` but may be optimized in some impls.
   */
  containsPreKey(id: number): Promise<boolean>;

  /**
   * Permanently delete a prekey. MUST be called after a successful X3DH
   * receive — reusing a prekey breaks forward secrecy.
   */
  removePreKey(id: number): Promise<void>;

  /**
   * Return all currently-stored prekey ids, sorted ascending.
   * Used for monitoring (top-up when running low) and for bundle generation.
   */
  loadAllPreKeyIds(): Promise<number[]>;
}

// ═══════════════════════════════════════════════════════════════════════════
// SignedPreKeyStore — medium-term signed prekey (rotates ~weekly)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Stores signed prekeys. Typically there is ONE active signed prekey at
 * a time, with older ones kept around briefly for in-flight messages
 * that were sent against them.
 */
export interface SignedPreKeyStore {
  /**
   * Save a signed prekey by id.
   */
  saveSignedPreKey(id: number, preKey: SignedPreKey): Promise<void>;

  /**
   * Load a signed prekey by id (any id, even non-active ones, for
   * in-flight message processing).
   */
  getSignedPreKey(id: number): Promise<SignedPreKey | null>;

  /**
   * Mark `newId` as the active signed prekey. Older ones are kept (not
   * deleted) so in-flight messages still decrypt — apps SHOULD garbage-
   * collect old ones periodically (e.g., after 30 days).
   */
  rotateActiveSignedPreKey(newId: number, newPreKey: SignedPreKey): Promise<void>;

  /**
   * Return the currently-active signed prekey, or null if none.
   * Used by bundle generation.
   */
  getActiveSignedPreKey(): Promise<SignedPreKey | null>;

  /**
   * Return all stored signed-prekey ids (for GC monitoring).
   */
  loadAllSignedPreKeyIds(): Promise<number[]>;
}

// ═══════════════════════════════════════════════════════════════════════════
// SessionStore — per-peer Double Ratchet state
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Stores per-peer `Session` objects. Keyed by `ProtocolAddress` so that
 * `(alice@example.com, device 1)` and `(alice@example.com, device 2)`
 * are tracked independently (multi-device).
 */
export interface SessionStore {
  /**
   * Save (or overwrite) the session for the given peer address.
   *
   * Implementations MUST serialize the session via `session.serialize()`
   * and persist the resulting JSON. This is sensitive material — at-rest
   * encryption is strongly recommended in production.
   */
  saveSession(address: ProtocolAddress, session: Session): Promise<void>;

  /**
   * Load the session for the peer, or null if none exists yet (first contact).
   */
  loadSession(address: ProtocolAddress): Promise<Session | null>;

  /**
   * Cheap existence check.
   */
  containsSession(address: ProtocolAddress): Promise<boolean>;

  /**
   * Permanently delete the session. After this, the next message to/from
   * the peer requires a fresh X3DH (which is also what apps do when the
   * user taps "reset secure session").
   */
  deleteSession(address: ProtocolAddress): Promise<void>;

  /**
   * Load every stored session. Used by bulk export, multi-device sync,
   * and the admin "show all my sessions" view.
   */
  loadAllSessions(): Promise<
    Array<{ address: ProtocolAddress; session: Session }>
  >;
}
