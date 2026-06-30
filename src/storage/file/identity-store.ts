/**
 * File-backed Identity Store.
 *
 * Persists identity material as JSON files on disk, with atomic writes.
 *
 * Layout:
 *   <rootDir>/
 *   ├── identity.json           — own keypair (PRIVATE — chmod 600)
 *   ├── registration-id.json    — registration id
 *   └── trusted/
 *       └── <address>.json      — one file per peer
 *
 * @module storage/file/identity-store
 */

import * as path from 'node:path';
import { IdentityKeyPair, PublicIdentityKey } from '../../identity/identity-key';
import { ProtocolAddress } from '../../address';
import type { IdentityStore } from '../types';
import {
  atomicWriteFile,
  readFileOrNull,
  unlinkIfExists,
} from './atomic-write';

export class FileIdentityStore implements IdentityStore {
  private readonly identityFile: string;
  private readonly registrationIdFile: string;
  private readonly trustedDir: string;

  constructor(rootDir: string) {
    if (typeof rootDir !== 'string' || rootDir.length === 0) {
      throw new TypeError('FileIdentityStore: rootDir must be a non-empty string');
    }
    this.identityFile = path.join(rootDir, 'identity.json');
    this.registrationIdFile = path.join(rootDir, 'registration-id.json');
    this.trustedDir = path.join(rootDir, 'trusted');
  }

  // ─── Own identity ────────────────────────────────────────────────────

  public async saveIdentityKeyPair(keyPair: IdentityKeyPair): Promise<void> {
    const payload = JSON.stringify({
      version: 1,
      keyPair: keyPair.serialize(),
    });
    await atomicWriteFile(this.identityFile, payload);
  }

  public async getIdentityKeyPair(): Promise<IdentityKeyPair | null> {
    const data = await readFileOrNull(this.identityFile);
    if (data === null) return null;
    const parsed = JSON.parse(data) as {
      version: number;
      keyPair: unknown;
    };
    return IdentityKeyPair.deserialize(parsed.keyPair);
  }

  public async saveRegistrationId(id: number): Promise<void> {
    if (!Number.isInteger(id) || id < 0) {
      throw new RangeError(`registrationId must be a non-negative integer, got ${id}`);
    }
    await atomicWriteFile(
      this.registrationIdFile,
      JSON.stringify({ version: 1, registrationId: id }),
    );
  }

  public async getRegistrationId(): Promise<number | null> {
    const data = await readFileOrNull(this.registrationIdFile);
    if (data === null) return null;
    const parsed = JSON.parse(data) as { registrationId: number };
    return parsed.registrationId;
  }

  // ─── Trusted identities ─────────────────────────────────────────────

  private trustedPath(address: ProtocolAddress): string {
    // toString() is filesystem-safe by ProtocolAddress validation
    return path.join(this.trustedDir, `${address.toString()}.json`);
  }

  public async saveTrustedIdentity(
    address: ProtocolAddress,
    key: PublicIdentityKey,
  ): Promise<void> {
    await atomicWriteFile(
      this.trustedPath(address),
      JSON.stringify({
        version: 1,
        address: address.toJSON(),
        publicKeyHex: key.toHex(),
        fingerprint: key.fingerprint(),
      }),
    );
  }

  public async isTrustedIdentity(
    address: ProtocolAddress,
    key: PublicIdentityKey,
  ): Promise<boolean> {
    const data = await readFileOrNull(this.trustedPath(address));
    if (data === null) return true; // TOFU
    const parsed = JSON.parse(data) as { fingerprint: string };
    return parsed.fingerprint === key.fingerprint();
  }

  // ─── Utilities ──────────────────────────────────────────────────────

  /** Delete the cached identity for `address`. (Useful for "reset peer".) */
  public async forgetTrustedIdentity(address: ProtocolAddress): Promise<void> {
    await unlinkIfExists(this.trustedPath(address));
  }
}
