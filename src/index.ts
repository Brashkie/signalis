/**
 * @brashkie/signalis
 *
 * Signal Protocol implementation in TypeScript.
 *
 * @version 0.4.0
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
  // X3DH (NEW v0.4.0)
  X3DH_SECRET_SIZE,
  X3DH_INITIAL_MESSAGE_MAX_AGE_MS,
  getX3DHSalt,
  getX3DHPrefix,
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
// X3DH (NEW in v0.4.0)
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
// Crypto (for advanced users)
// ═══════════════════════════════════════════════════════════════════════════
export * as crypto from './crypto';
