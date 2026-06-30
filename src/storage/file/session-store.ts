/**
 * File-backed Session Store.
 *
 * Layout:
 *   <rootDir>/sessions/<address>.json
 *
 * @module storage/file/session-store
 */

import * as path from 'node:path';
import { Session } from '../../session';
import { ProtocolAddress } from '../../address';
import type { SessionStore } from '../types';
import {
  atomicWriteFile,
  readFileOrNull,
  unlinkIfExists,
  listFiles,
} from './atomic-write';

export class FileSessionStore implements SessionStore {
  private readonly sessionsDir: string;

  constructor(rootDir: string) {
    if (typeof rootDir !== 'string' || rootDir.length === 0) {
      throw new TypeError('FileSessionStore: rootDir must be a non-empty string');
    }
    this.sessionsDir = path.join(rootDir, 'sessions');
  }

  private filePath(address: ProtocolAddress): string {
    return path.join(this.sessionsDir, `${address.toString()}.json`);
  }

  public async saveSession(address: ProtocolAddress, session: Session): Promise<void> {
    const snapshot = session.serialize();
    await atomicWriteFile(this.filePath(address), JSON.stringify(snapshot));
  }

  public async loadSession(address: ProtocolAddress): Promise<Session | null> {
    const data = await readFileOrNull(this.filePath(address));
    if (data === null) return null;
    return Session.deserialize(JSON.parse(data));
  }

  public async containsSession(address: ProtocolAddress): Promise<boolean> {
    return (await readFileOrNull(this.filePath(address))) !== null;
  }

  public async deleteSession(address: ProtocolAddress): Promise<void> {
    await unlinkIfExists(this.filePath(address));
  }

  public async loadAllSessions(): Promise<
    Array<{ address: ProtocolAddress; session: Session }>
  > {
    const files = await listFiles(this.sessionsDir, (n) => n.endsWith('.json'));
    const result: Array<{ address: ProtocolAddress; session: Session }> = [];
    for (const file of files) {
      const addrStr = file.slice(0, -5); // strip .json
      let address: ProtocolAddress;
      try {
        address = ProtocolAddress.parse(addrStr);
      } catch {
        // Skip malformed filenames silently
        continue;
      }
      const session = await this.loadSession(address);
      if (session !== null) {
        result.push({ address, session });
      }
    }
    return result;
  }
}
