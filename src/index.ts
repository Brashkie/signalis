/**
 * @brashkie/signalis
 *
 * Signal Protocol implementation in TypeScript.
 *
 * @version 0.7.0
 * @license Apache-2.0
 */

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════
export {
  VERSION,
  PROTOCOL_VERSION,
  // Key sizes
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  SIGNATURE_SIZE,
  HASH_SIZE,
  MAC_SIZE,
  AES_KEY_SIZE,
  AES_CBC_IV_SIZE,
  AES_NONCE_SIZE,
  AES_TAG_SIZE,
  // PreKey
  MAX_ONE_TIME_PREKEYS,
  MIN_ONE_TIME_PREKEYS,
  DEFAULT_PREKEY_BATCH,
  MAX_PREKEY_ID,
  MIN_PREKEY_ID,
  // Rotation
  SIGNED_PREKEY_ROTATION_MS,
  SIGNED_PREKEY_MAX_AGE_MS,
  // Registration
  MAX_REGISTRATION_ID,
  MIN_REGISTRATION_ID,
  DEFAULT_DEVICE_ID,
  MAX_DEVICE_ID,
  // X3DH
  X3DH_SECRET_SIZE,
  X3DH_INITIAL_MESSAGE_MAX_AGE_MS,
  getX3DHSalt,
  getX3DHPrefix,
  // Double Ratchet (NEW v0.5.0)
  ROOT_KEY_SIZE,
  CHAIN_KEY_SIZE,
  MESSAGE_KEY_MATERIAL_SIZE,
  MAC_TRUNCATE_SIZE,
  MAX_SKIPPED_MESSAGE_KEYS,
  getRatchetRootInfo,
  getMessageKeyInfo,
  // Info strings
  INFO_STRINGS,
  getX3DHInfo,
  getRatchetInfo,
  getChainInfo,
  getMessageInfo,
  getSignedPreKeyContext,
  // Validators
  isValidPreKeyId,
  isValidRegistrationId,
  isValidDeviceId,
} from './constants';

// ═══════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════
export {
  SignalisError,
  ValidationError,
  SignatureError,
  KeyError,
  PreKeyError,
  SerializationError,
  ProtocolError,
  SessionError,
  ErrorCode,
  type ErrorCodeType,
} from './errors';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════
export type {
  PublicKey,
  PrivateKey,
  Signature,
  SharedSecret,
  ChainKey,
  MessageKey,
  RootKey,
  KeyPair,
  IdentityInfo,
  SerializedKeyPair,
} from './types';

export {
  asPublicKey,
  asPrivateKey,
  asSignature,
  asSharedSecret,
  asChainKey,
  asMessageKey,
  asRootKey,
  isPublicKey,
  isPrivateKey,
  isSignature,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// Identity
// ═══════════════════════════════════════════════════════════════════════════
export {
  IdentityKeyPair,
  PublicIdentityKey,
  isIdentityKeyPair,
  isPublicIdentityKey,
} from './identity';

// ═══════════════════════════════════════════════════════════════════════════
// PreKeys
// ═══════════════════════════════════════════════════════════════════════════
export {
  OneTimePreKey,
  PublicOneTimePreKey,
  isOneTimePreKey,
  isPublicOneTimePreKey,
  type SerializedOneTimePreKey,
  SignedPreKey,
  PublicSignedPreKey,
  isSignedPreKey,
  isPublicSignedPreKey,
  type SerializedSignedPreKey,
  type PublicSignedPreKeyPayload,
  PreKeyBundle,
  isPreKeyBundle,
  type PreKeyBundlePayload,
  type PublicOneTimePreKeyPayload,
} from './prekeys';

// ═══════════════════════════════════════════════════════════════════════════
// X3DH
// ═══════════════════════════════════════════════════════════════════════════
export {
  X3DH,
  InitialMessage,
  isInitialMessage,
  computeInitiatorSharedSecret,
  computeResponderSharedSecret,
  type X3DHInitiateOptions,
  type InitialMessagePayload,
  type X3DHInitiateResult,
  type X3DHReceiveResult,
} from './x3dh';

// ═══════════════════════════════════════════════════════════════════════════
// Double Ratchet Primitives (NEW v0.5.0)
//
// Note: A high-level `Session` class will be added in Sprint 3 Part 2 (v0.6.0).
// For now, these are the building blocks. Use them directly if implementing
// custom session management, or wait for the Session class.
// ═══════════════════════════════════════════════════════════════════════════
export {
  // DH ratchet
  deriveRootKey,
  // Symmetric ratchet
  advanceChainKey,
  advanceChainKeyN,
  // Message encryption (Signal classic: AES-256-CBC + HMAC-SHA256)
  expandMessageKey,
  encryptWithMessageKey,
  decryptWithMessageKey,
  // Wire format
  MessageHeader,
  isMessageHeader,
  // Skipped keys (anti-DoS)
  SkippedMessageKeys,
  // Types
  type RootKeyDerivation,
  type ChainKeyAdvancement,
  type MessageKeyMaterial,
  type MessageHeaderPayload,
  type SkippedKeyId,
} from './ratchet';

// ═══════════════════════════════════════════════════════════════════════════
// Session (NEW v0.6.0) — high-level encrypt/decrypt API
//
// This is what most users will use directly. It wraps the v0.5.0 ratchet
// primitives into a clean encrypt(plaintext) / decrypt(packet) interface.
// ═══════════════════════════════════════════════════════════════════════════
export {
  Session,
  isSession,
  type EncryptedMessage,
  type SessionInitiateArgs,
  type SessionReceiveArgs,
  type SerializedSession,
} from './session';

// ═══════════════════════════════════════════════════════════════════════════
// ProtocolAddress (NEW v0.7.0) — peer identifier for stores
// ═══════════════════════════════════════════════════════════════════════════
// MAX_DEVICE_ID is already exported above from `./constants` — not re-exporting.
export {
  ProtocolAddress,
  isProtocolAddress,
  MAX_USER_ID_LENGTH,
} from './address';

// ═══════════════════════════════════════════════════════════════════════════
// Storage Layer (NEW v0.7.0) — interfaces + memory/file implementations
// ═══════════════════════════════════════════════════════════════════════════
export {
  // Interfaces
  type IdentityStore,
  type PreKeyStore,
  type SignedPreKeyStore,
  type SessionStore,
  // Memory impls
  MemoryIdentityStore,
  MemoryPreKeyStore,
  MemorySignedPreKeyStore,
  MemorySessionStore,
  // File impls
  FileIdentityStore,
  FilePreKeyStore,
  FileSignedPreKeyStore,
  FileSessionStore,
  // Facade + high-level
  StoreBundle,
  SessionBuilder,
  type WireMessage,
  type InitialMessageWithPayload,
  type RegularMessage,
} from './storage';

// ═══════════════════════════════════════════════════════════════════════════
// Crypto (for advanced users)
// ═══════════════════════════════════════════════════════════════════════════
export * as crypto from './crypto';
