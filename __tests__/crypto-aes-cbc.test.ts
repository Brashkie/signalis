import { describe, it, expect } from 'vitest';

import {
  crypto,
  AES_KEY_SIZE,
  AES_CBC_IV_SIZE,
  ValidationError,
} from '../src';

const { aesCbcEncrypt, aesCbcDecrypt, randomBytes } = crypto;

describe('aesCbcEncrypt / aesCbcDecrypt', () => {
  it('round-trips a short message', () => {
    const key = randomBytes(AES_KEY_SIZE);
    const iv = randomBytes(AES_CBC_IV_SIZE);
    const pt = Buffer.from('Hello world');

    const ct = aesCbcEncrypt(key, iv, pt);
    const decrypted = aesCbcDecrypt(key, iv, ct);

    expect(decrypted.toString('utf-8')).toBe('Hello world');
  });

  it('round-trips an empty plaintext', () => {
    const key = randomBytes(AES_KEY_SIZE);
    const iv = randomBytes(AES_CBC_IV_SIZE);

    const ct = aesCbcEncrypt(key, iv, Buffer.alloc(0));
    // PKCS#7 padded → ciphertext has at least one block (16 bytes)
    expect(ct.length).toBe(16);

    const decrypted = aesCbcDecrypt(key, iv, ct);
    expect(decrypted.length).toBe(0);
  });

  it('round-trips a message exactly 1 block', () => {
    const key = randomBytes(AES_KEY_SIZE);
    const iv = randomBytes(AES_CBC_IV_SIZE);
    const pt = Buffer.alloc(16, 0xab);

    const ct = aesCbcEncrypt(key, iv, pt);
    // 16-byte input → 32 bytes after padding (one full pad block)
    expect(ct.length).toBe(32);

    const decrypted = aesCbcDecrypt(key, iv, ct);
    expect(decrypted.equals(pt)).toBe(true);
  });

  it('round-trips a large message (10 KB)', () => {
    const key = randomBytes(AES_KEY_SIZE);
    const iv = randomBytes(AES_CBC_IV_SIZE);
    const pt = randomBytes(10_000);

    const ct = aesCbcEncrypt(key, iv, pt);
    const decrypted = aesCbcDecrypt(key, iv, ct);

    expect(decrypted.equals(pt)).toBe(true);
  });

  it('different IVs produce different ciphertexts (same key, same plaintext)', () => {
    const key = randomBytes(AES_KEY_SIZE);
    const iv1 = randomBytes(AES_CBC_IV_SIZE);
    const iv2 = randomBytes(AES_CBC_IV_SIZE);
    const pt = Buffer.from('same plaintext');

    const ct1 = aesCbcEncrypt(key, iv1, pt);
    const ct2 = aesCbcEncrypt(key, iv2, pt);

    expect(ct1.equals(ct2)).toBe(false);
  });

  // ─── Validation ──────────────────────────────────────────────────────

  it('encrypt rejects wrong key size', () => {
    expect(() =>
      aesCbcEncrypt(Buffer.alloc(16), randomBytes(AES_CBC_IV_SIZE), Buffer.from('x')),
    ).toThrow(ValidationError);
  });

  it('encrypt rejects wrong IV size', () => {
    expect(() =>
      aesCbcEncrypt(randomBytes(AES_KEY_SIZE), Buffer.alloc(8), Buffer.from('x')),
    ).toThrow(ValidationError);
  });

  it('decrypt rejects wrong key size', () => {
    expect(() =>
      aesCbcDecrypt(Buffer.alloc(16), randomBytes(AES_CBC_IV_SIZE), Buffer.alloc(16)),
    ).toThrow(ValidationError);
  });

  it('decrypt rejects wrong IV size', () => {
    expect(() =>
      aesCbcDecrypt(randomBytes(AES_KEY_SIZE), Buffer.alloc(8), Buffer.alloc(16)),
    ).toThrow(ValidationError);
  });

  it('decrypt with wrong key throws padding error', () => {
    const key1 = randomBytes(AES_KEY_SIZE);
    const key2 = randomBytes(AES_KEY_SIZE);
    const iv = randomBytes(AES_CBC_IV_SIZE);
    const pt = Buffer.from('secret data');

    const ct = aesCbcEncrypt(key1, iv, pt);
    // Wrong key → usually fails with padding error in OpenSSL
    expect(() => aesCbcDecrypt(key2, iv, ct)).toThrow();
  });
});
