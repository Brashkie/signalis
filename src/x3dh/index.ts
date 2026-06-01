/**
 * X3DH (Extended Triple Diffie-Hellman) Protocol
 *
 * Public API surface for the X3DH module.
 *
 * @module x3dh
 */

import { initiate, type X3DHInitiateOptions } from './initiator';
import { receive } from './responder';

// ─── Initial Message ──────────────────────────────────────────────────────
export {
  InitialMessage,
  isInitialMessage,
} from './initial-message';

// ─── Shared Secret primitives (advanced use) ─────────────────────────────
export {
  computeInitiatorSharedSecret,
  computeResponderSharedSecret,
} from './shared-secret';

// ─── High-level handshake API ────────────────────────────────────────────
export { initiate, receive, type X3DHInitiateOptions };

// ─── Types ────────────────────────────────────────────────────────────────
export type {
  InitialMessagePayload,
  X3DHInitiateResult,
  X3DHReceiveResult,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// Namespace export for ergonomic usage
//
// Usage: import { X3DH } from '@brashkie/signalis';
//        const result = X3DH.initiate(myIdentity, theirBundle, options);
//        const recvResult = X3DH.receive(myIdentity, mySpk, myOpk, msg);
// ═══════════════════════════════════════════════════════════════════════════
export const X3DH = Object.freeze({
  initiate,
  receive,
});
