/**
 * StoreBundle — facade combining all four storage interfaces.
 *
 * Pass one of these to high-level APIs (like `SessionBuilder`) instead
 * of passing 4 separate store references.
 *
 * @module storage/bundle
 */

import {
  MemoryIdentityStore,
  MemoryPreKeyStore,
  MemorySignedPreKeyStore,
  MemorySessionStore,
} from './memory';
import {
  FileIdentityStore,
  FilePreKeyStore,
  FileSignedPreKeyStore,
  FileSessionStore,
} from './file';
import type {
  IdentityStore,
  PreKeyStore,
  SignedPreKeyStore,
  SessionStore,
} from './types';

/**
 * Bundle of all four canonical storage interfaces.
 *
 * @example
 * ```ts
 * // Memory (testing)
 * const stores = StoreBundle.memory();
 *
 * // File-backed (production)
 * const stores = StoreBundle.file('~/.myapp/signalis');
 *
 * // Custom mix (e.g., file for identity/prekeys, memory for sessions)
 * const stores = new StoreBundle({
 *   identity: new FileIdentityStore('~/.myapp'),
 *   preKeys: new FilePreKeyStore('~/.myapp'),
 *   signedPreKeys: new FileSignedPreKeyStore('~/.myapp'),
 *   sessions: new MemorySessionStore(),
 * });
 * ```
 */
export class StoreBundle {
  public readonly identity: IdentityStore;
  public readonly preKeys: PreKeyStore;
  public readonly signedPreKeys: SignedPreKeyStore;
  public readonly sessions: SessionStore;

  constructor(stores: {
    identity: IdentityStore;
    preKeys: PreKeyStore;
    signedPreKeys: SignedPreKeyStore;
    sessions: SessionStore;
  }) {
    if (
      stores === null ||
      typeof stores !== 'object' ||
      !stores.identity ||
      !stores.preKeys ||
      !stores.signedPreKeys ||
      !stores.sessions
    ) {
      throw new TypeError(
        'StoreBundle: expected { identity, preKeys, signedPreKeys, sessions }',
      );
    }
    this.identity = stores.identity;
    this.preKeys = stores.preKeys;
    this.signedPreKeys = stores.signedPreKeys;
    this.sessions = stores.sessions;
    Object.freeze(this);
  }

  /**
   * Shorthand: build a bundle backed entirely by in-memory stores.
   * Use for tests or genuinely ephemeral sessions.
   */
  public static memory(): StoreBundle {
    return new StoreBundle({
      identity: new MemoryIdentityStore(),
      preKeys: new MemoryPreKeyStore(),
      signedPreKeys: new MemorySignedPreKeyStore(),
      sessions: new MemorySessionStore(),
    });
  }

  /**
   * Shorthand: build a bundle backed by JSON files under `rootDir`.
   * The directory is created if it doesn't exist.
   *
   * Use for Node.js apps, Electron, Termux, etc.
   */
  public static file(rootDir: string): StoreBundle {
    return new StoreBundle({
      identity: new FileIdentityStore(rootDir),
      preKeys: new FilePreKeyStore(rootDir),
      signedPreKeys: new FileSignedPreKeyStore(rootDir),
      sessions: new FileSessionStore(rootDir),
    });
  }
}
