/**
 * File-backed PreKey Store.
 *
 * Layout:
 *   <rootDir>/prekeys/<id>.json
 *
 * @module storage/file/prekey-store
 */

import * as path from 'node:path';
import { OneTimePreKey } from '../../prekeys/one-time-prekey';
import type { PreKeyStore } from '../types';
import {
  atomicWriteFile,
  readFileOrNull,
  unlinkIfExists,
  listFiles,
} from './atomic-write';

export class FilePreKeyStore implements PreKeyStore {
  private readonly preKeysDir: string;

  constructor(rootDir: string) {
    if (typeof rootDir !== 'string' || rootDir.length === 0) {
      throw new TypeError('FilePreKeyStore: rootDir must be a non-empty string');
    }
    this.preKeysDir = path.join(rootDir, 'prekeys');
  }

  private filePath(id: number): string {
    if (!Number.isInteger(id) || id < 0) {
      throw new RangeError(`prekey id must be a non-negative integer, got ${id}`);
    }
    return path.join(this.preKeysDir, `${id}.json`);
  }

  public async savePreKey(id: number, preKey: OneTimePreKey): Promise<void> {
    await atomicWriteFile(
      this.filePath(id),
      JSON.stringify({
        version: 1,
        preKey: preKey.serialize(),
      }),
    );
  }

  public async getPreKey(id: number): Promise<OneTimePreKey | null> {
    const data = await readFileOrNull(this.filePath(id));
    if (data === null) return null;
    const parsed = JSON.parse(data) as { version: number; preKey: unknown };
    return OneTimePreKey.deserialize(parsed.preKey);
  }

  public async containsPreKey(id: number): Promise<boolean> {
    return (await readFileOrNull(this.filePath(id))) !== null;
  }

  public async removePreKey(id: number): Promise<void> {
    await unlinkIfExists(this.filePath(id));
  }

  public async loadAllPreKeyIds(): Promise<number[]> {
    const files = await listFiles(this.preKeysDir, (n) => n.endsWith('.json'));
    return files
      .map((name) => Number.parseInt(name.slice(0, -5), 10))
      .filter((n) => Number.isInteger(n))
      .sort((a, b) => a - b);
  }
}
