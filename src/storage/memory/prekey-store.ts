/**
 * In-Memory PreKey Store
 *
 * @module storage/memory/prekey-store
 */

import type { OneTimePreKey } from '../../prekeys/one-time-prekey';
import type { PreKeyStore } from '../types';

export class MemoryPreKeyStore implements PreKeyStore {
  private readonly keys = new Map<number, OneTimePreKey>();

  public async savePreKey(id: number, preKey: OneTimePreKey): Promise<void> {
    this.keys.set(id, preKey);
  }

  public async getPreKey(id: number): Promise<OneTimePreKey | null> {
    return this.keys.get(id) ?? null;
  }

  public async containsPreKey(id: number): Promise<boolean> {
    return this.keys.has(id);
  }

  public async removePreKey(id: number): Promise<void> {
    this.keys.delete(id);
  }

  public async loadAllPreKeyIds(): Promise<number[]> {
    return [...this.keys.keys()].sort((a, b) => a - b);
  }

  // ─── Diagnostics ────────────────────────────────────────────────────

  /** Current count of stored prekeys. */
  public size(): number {
    return this.keys.size;
  }

  /** Wipe all prekeys. */
  public clear(): void {
    this.keys.clear();
  }
}
