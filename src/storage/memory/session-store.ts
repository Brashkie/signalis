/**
 * In-Memory Session Store
 *
 * @module storage/memory/session-store
 */

import { Session } from '../../session';
import { ProtocolAddress } from '../../address';
import type { SessionStore } from '../types';

export class MemorySessionStore implements SessionStore {
  /** Map<address.toString(), serialized session JSON> */
  private readonly sessions = new Map<string, string>();

  public async saveSession(address: ProtocolAddress, session: Session): Promise<void> {
    const snapshot = session.serialize();
    this.sessions.set(address.toString(), JSON.stringify(snapshot));
  }

  public async loadSession(address: ProtocolAddress): Promise<Session | null> {
    const serialized = this.sessions.get(address.toString());
    if (serialized === undefined) return null;
    return Session.deserialize(JSON.parse(serialized));
  }

  public async containsSession(address: ProtocolAddress): Promise<boolean> {
    return this.sessions.has(address.toString());
  }

  public async deleteSession(address: ProtocolAddress): Promise<void> {
    this.sessions.delete(address.toString());
  }

  public async loadAllSessions(): Promise<
    Array<{ address: ProtocolAddress; session: Session }>
  > {
    const result: Array<{ address: ProtocolAddress; session: Session }> = [];
    for (const [key, serialized] of this.sessions.entries()) {
      result.push({
        address: ProtocolAddress.parse(key),
        session: Session.deserialize(JSON.parse(serialized)),
      });
    }
    return result;
  }

  // ─── Diagnostics ────────────────────────────────────────────────────

  public size(): number {
    return this.sessions.size;
  }

  public clear(): void {
    this.sessions.clear();
  }
}
