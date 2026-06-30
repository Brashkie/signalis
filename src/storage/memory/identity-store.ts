/**
 * In-Memory Identity Store
 *
 * Stores everything in plain `Map`s. Wiped on process exit.
 *
 * Use for: tests, ephemeral apps, "anonymous chat session" UIs that
 * deliberately don't persist state.
 *
 * Do NOT use for: production messaging apps (you'd lose every session
 * on app restart).
 *
 * @module storage/memory/identity-store
 */

import type { IdentityKeyPair, PublicIdentityKey } from '../../identity/identity-key';
import type { ProtocolAddress } from '../../address';
import type { IdentityStore } from '../types';

export class MemoryIdentityStore implements IdentityStore {
  private myIdentityKeyPair: IdentityKeyPair | null = null;
  private myRegistrationId: number | null = null;
  /** Map<address.toString(), fingerprint-hex> */
  private readonly trustedFingerprints = new Map<string, string>();

  // ─── Own identity ────────────────────────────────────────────────────

  public async saveIdentityKeyPair(keyPair: IdentityKeyPair): Promise<void> {
    this.myIdentityKeyPair = keyPair;
  }

  public async getIdentityKeyPair(): Promise<IdentityKeyPair | null> {
    return this.myIdentityKeyPair;
  }

  public async saveRegistrationId(id: number): Promise<void> {
    if (!Number.isInteger(id) || id < 0) {
      throw new RangeError(`registrationId must be a non-negative integer, got ${id}`);
    }
    this.myRegistrationId = id;
  }

  public async getRegistrationId(): Promise<number | null> {
    return this.myRegistrationId;
  }

  // ─── Trusted identities (TOFU cache) ────────────────────────────────

  public async saveTrustedIdentity(
    address: ProtocolAddress,
    key: PublicIdentityKey,
  ): Promise<void> {
    this.trustedFingerprints.set(address.toString(), key.fingerprint());
  }

  public async isTrustedIdentity(
    address: ProtocolAddress,
    key: PublicIdentityKey,
  ): Promise<boolean> {
    const stored = this.trustedFingerprints.get(address.toString());
    if (stored === undefined) return true; // TOFU: first contact accepted
    return stored === key.fingerprint();
  }

  // ─── Diagnostics (not part of interface) ────────────────────────────

  /** Number of trusted-identity records cached. */
  public trustedIdentitiesCount(): number {
    return this.trustedFingerprints.size;
  }

  /** Wipe everything. */
  public clear(): void {
    this.myIdentityKeyPair = null;
    this.myRegistrationId = null;
    this.trustedFingerprints.clear();
  }
}
