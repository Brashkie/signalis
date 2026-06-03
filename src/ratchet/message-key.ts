/**
 * Message Key Expansion + Encryption (Signal classic AES-256-CBC + HMAC-SHA256)
 *
 * Takes a 32-byte MessageKey seed (output of the chain ratchet) and:
 *   1. Expands it via HKDF into 80 bytes: (AES key, HMAC key, IV)
 *   2. Provides encrypt/decrypt with authenticated encryption
 *
 * Spec (Signal "classic" encryption):
 *   material = HKDF-SHA256(salt=0x00*32, ikm=MK_seed, info="Signalis_MessageKeys_v1", L=80)
 *   aesKey  = material[0..32]
 *   hmacKey = material[32..64]
 *   iv      = material[64..80]
 *
 *   ciphertext = AES-256-CBC-PKCS7(aesKey, iv, plaintext)
 *   mac        = HMAC-SHA256(hmacKey, associatedData || ciphertext)[:8]
 *
 * The MAC is the AUTHENTICATION — without verifying it first, decrypting
 * is unsafe (padding-oracle attacks).
 *
 * @module ratchet/message-key
 */

import {
  hkdf,
  hmac,
  aesCbcEncrypt,
  aesCbcDecrypt,
} from '../crypto';
import { timingSafeEqual } from 'node:crypto';
import type { MessageKey } from '../types';
import {
  HASH_SIZE,
  MESSAGE_KEY_MATERIAL_SIZE,
  MESSAGE_KEY_AES_OFFSET,
  MESSAGE_KEY_HMAC_OFFSET,
  MESSAGE_KEY_IV_OFFSET,
  AES_KEY_SIZE,
  AES_CBC_IV_SIZE,
  MAC_TRUNCATE_SIZE,
  getMessageKeyInfo,
} from '../constants';
import { ValidationError, SignatureError } from '../errors';
import type { MessageKeyMaterial } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// MessageKey expansion
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Expand a 32-byte MessageKey seed into (AES key, HMAC key, IV).
 *
 * Uses HKDF-SHA256 with:
 *   - salt = 32 zero bytes
 *   - ikm  = the message key seed
 *   - info = "Signalis_MessageKeys_v1"
 *   - L    = 80 bytes
 *
 * @param messageKey 32-byte seed (output of chain ratchet)
 * @returns expanded material (32 + 32 + 16 = 80 bytes split into 3 buffers)
 */
export function expandMessageKey(messageKey: MessageKey): MessageKeyMaterial {
  if (!Buffer.isBuffer(messageKey)) {
    throw new ValidationError(
      'expandMessageKey: messageKey must be a Buffer',
      { type: typeof messageKey },
    );
  }

  const salt = Buffer.alloc(HASH_SIZE, 0x00);
  const material = hkdf(
    salt,
    messageKey,
    getMessageKeyInfo(),
    MESSAGE_KEY_MATERIAL_SIZE,
  );

  return {
    aesKey: material.subarray(
      MESSAGE_KEY_AES_OFFSET,
      MESSAGE_KEY_AES_OFFSET + AES_KEY_SIZE,
    ),
    hmacKey: material.subarray(
      MESSAGE_KEY_HMAC_OFFSET,
      MESSAGE_KEY_HMAC_OFFSET + AES_KEY_SIZE,
    ),
    iv: material.subarray(
      MESSAGE_KEY_IV_OFFSET,
      MESSAGE_KEY_IV_OFFSET + AES_CBC_IV_SIZE,
    ),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// Encrypt
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt-then-MAC under a MessageKey.
 *
 * @param messageKey      32-byte seed
 * @param plaintext       data to encrypt
 * @param associatedData  data to authenticate but NOT encrypt (typically the header)
 *
 * @returns Object with:
 *   - `ciphertext`: AES-256-CBC-encrypted plaintext
 *   - `mac`: 8-byte HMAC-SHA256 over (associatedData || ciphertext)
 *
 * Wire format = ciphertext || mac (caller concatenates)
 */
export function encryptWithMessageKey(
  messageKey: MessageKey,
  plaintext: Buffer,
  associatedData: Buffer,
): { ciphertext: Buffer; mac: Buffer } {
  if (!Buffer.isBuffer(plaintext)) {
    throw new ValidationError('encryptWithMessageKey: plaintext must be a Buffer');
  }
  if (!Buffer.isBuffer(associatedData)) {
    throw new ValidationError('encryptWithMessageKey: associatedData must be a Buffer');
  }

  const { aesKey, hmacKey, iv } = expandMessageKey(messageKey);

  const ciphertext = aesCbcEncrypt(aesKey, iv, plaintext);

  // MAC = HMAC-SHA256(hmacKey, AD || ciphertext)
  const macInput = Buffer.concat(
    [associatedData, ciphertext],
    associatedData.length + ciphertext.length,
  );
  const fullMac = hmac(hmacKey, macInput);

  // Truncate to MAC_TRUNCATE_SIZE bytes (Signal spec)
  const mac = fullMac.subarray(0, MAC_TRUNCATE_SIZE);

  return { ciphertext, mac };
}

// ═══════════════════════════════════════════════════════════════════════════
// Decrypt (with MAC verification)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Verify-MAC-then-Decrypt under a MessageKey.
 *
 * CRITICAL: This function verifies the MAC BEFORE decrypting. If the MAC
 * does not match, it throws SignatureError and does NOT attempt to decrypt.
 * This prevents padding-oracle attacks against AES-CBC.
 *
 * @param messageKey      32-byte seed
 * @param ciphertext      AES-CBC ciphertext
 * @param mac             8-byte MAC tag (truncated HMAC-SHA256)
 * @param associatedData  data that was authenticated alongside the ciphertext
 *
 * @returns Decrypted plaintext
 *
 * @throws {SignatureError} If the MAC does not verify
 * @throws {ValidationError} On wrong input sizes
 * @throws {Error} On padding errors (only AFTER MAC verifies — should never happen)
 */
export function decryptWithMessageKey(
  messageKey: MessageKey,
  ciphertext: Buffer,
  mac: Buffer,
  associatedData: Buffer,
): Buffer {
  if (!Buffer.isBuffer(ciphertext)) {
    throw new ValidationError('decryptWithMessageKey: ciphertext must be a Buffer');
  }
  if (!Buffer.isBuffer(mac) || mac.length !== MAC_TRUNCATE_SIZE) {
    throw new ValidationError(
      `decryptWithMessageKey: mac must be ${MAC_TRUNCATE_SIZE} bytes (got ${mac?.length})`,
      { actual: mac?.length, expected: MAC_TRUNCATE_SIZE },
    );
  }
  if (!Buffer.isBuffer(associatedData)) {
    throw new ValidationError('decryptWithMessageKey: associatedData must be a Buffer');
  }

  const { aesKey, hmacKey, iv } = expandMessageKey(messageKey);

  // ─── 1. VERIFY MAC FIRST (constant-time compare) ──────────────────────
  const macInput = Buffer.concat(
    [associatedData, ciphertext],
    associatedData.length + ciphertext.length,
  );
  const expectedFullMac = hmac(hmacKey, macInput);
  const expectedMac = expectedFullMac.subarray(0, MAC_TRUNCATE_SIZE);

  if (!timingSafeEqual(mac, expectedMac)) {
    throw new SignatureError(
      'decryptWithMessageKey: MAC verification failed (ciphertext tampered or wrong key)',
      { macLength: mac.length },
    );
  }

  // ─── 2. Only now decrypt ──────────────────────────────────────────────
  return aesCbcDecrypt(aesKey, iv, ciphertext);
}
