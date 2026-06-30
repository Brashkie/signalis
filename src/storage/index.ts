/**
 * Storage Layer — interfaces + bundled implementations.
 *
 * @module storage
 */

// Interfaces
export type {
  IdentityStore,
  PreKeyStore,
  SignedPreKeyStore,
  SessionStore,
} from './types';

// Implementations (memory)
export {
  MemoryIdentityStore,
  MemoryPreKeyStore,
  MemorySignedPreKeyStore,
  MemorySessionStore,
} from './memory';

// Implementations (file)
export {
  FileIdentityStore,
  FilePreKeyStore,
  FileSignedPreKeyStore,
  FileSessionStore,
} from './file';

// Facade + high-level API
export { StoreBundle } from './bundle';
export {
  SessionBuilder,
  type WireMessage,
  type InitialMessageWithPayload,
  type RegularMessage,
} from './session-builder';
