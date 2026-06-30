/**
 * In-Memory SignedPreKey Store
 *
 * @module storage/memory/signed-prekey-store
 */

import type { SignedPreKey } from '../../prekeys/signed-prekey';
import type { SignedPreKeyStore } from '../types';

export class MemorySignedPreKeyStore implements SignedPreKeyStore {
  private readonly keys = new Map<number, SignedPreKey>();
  private activeId: number | null = null;

  public async saveSignedPreKey(id: number, preKey: SignedPreKey): Promise<void> {
    this.keys.set(id, preKey);
  }

  public async getSignedPreKey(id: number): Promise<SignedPreKey | null> {
    return this.keys.get(id) ?? null;
  }

  public async rotateActiveSignedPreKey(
    newId: number,
    newPreKey: SignedPreKey,
  ): Promise<void> {
    this.keys.set(newId, newPreKey);
    this.activeId = newId;
  }

  public async getActiveSignedPreKey(): Promise<SignedPreKey | null> {
    if (this.activeId === null) return null;
    return this.keys.get(this.activeId) ?? null;
  }

  public async loadAllSignedPreKeyIds(): Promise<number[]> {
    return [...this.keys.keys()].sort((a, b) => a - b);
  }

  // ─── Diagnostics ────────────────────────────────────────────────────

  public size(): number {
    return this.keys.size;
  }

  public clear(): void {
    this.keys.clear();
    this.activeId = null;
  }
}
