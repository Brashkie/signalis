/**
 * Double Ratchet Primitives
 *
 * Low-level building blocks for the Double Ratchet algorithm.
 * High-level `Session` class is in Sprint 3 Part 2 (v0.6.0).
 *
 * @module ratchet
 */

// ─── DH Ratchet ───────────────────────────────────────────────────────────
export { deriveRootKey } from './root-key';

// ─── Symmetric Ratchet ────────────────────────────────────────────────────
export {
  advanceChainKey,
  advanceChainKeyN,
} from './chain-key';

// ─── Message Encryption ───────────────────────────────────────────────────
export {
  expandMessageKey,
  encryptWithMessageKey,
  decryptWithMessageKey,
} from './message-key';

// ─── Wire Format ──────────────────────────────────────────────────────────
export {
  MessageHeader,
  isMessageHeader,
} from './header';

// ─── Skipped Keys Cache ───────────────────────────────────────────────────
export { SkippedMessageKeys } from './skipped-keys';

// ─── Types ────────────────────────────────────────────────────────────────
export type {
  RootKeyDerivation,
  ChainKeyAdvancement,
  MessageKeyMaterial,
  MessageHeaderPayload,
  SkippedKeyId,
} from './types';
