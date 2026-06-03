import { describe, it, expect } from 'vitest';

import {
  advanceChainKey,
  advanceChainKeyN,
  expandMessageKey,
  encryptWithMessageKey,
  decryptWithMessageKey,
  CHAIN_KEY_SIZE,
  AES_KEY_SIZE,
  AES_CBC_IV_SIZE,
  MAC_TRUNCATE_SIZE,
  ValidationError,
  SignatureError,
  crypto,
} from '../src';
import { asChainKey, asMessageKey } from '../src/types';

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

function freshChainKey() {
  return asChainKey(crypto.randomBytes(CHAIN_KEY_SIZE));
}

// ═══════════════════════════════════════════════════════════════════════════
// advanceChainKey
// ═══════════════════════════════════════════════════════════════════════════

describe('advanceChainKey (symmetric ratchet)', () => {
  it('produces NextChainKey + MessageKey of correct sizes', () => {
    const ck = freshChainKey();
    const adv = advanceChainKey(ck, 0);

    expect(adv.nextChainKey.length).toBe(CHAIN_KEY_SIZE);
    expect(adv.messageKey.length).toBe(32); // raw HMAC output before HKDF expansion
    expect(adv.counter).toBe(0);
  });

  it('two advances from same CK produce same NextCK + MK', () => {
    const ck = freshChainKey();
    const a = advanceChainKey(ck, 0);
    const b = advanceChainKey(ck, 0);

    expect(a.nextChainKey.equals(b.nextChainKey)).toBe(true);
    expect(a.messageKey.equals(b.messageKey)).toBe(true);
  });

  it('successive advances produce DIFFERENT NextCKs (chain advances)', () => {
    const ck0 = freshChainKey();
    const step1 = advanceChainKey(ck0, 0);
    const step2 = advanceChainKey(step1.nextChainKey, 1);
    const step3 = advanceChainKey(step2.nextChainKey, 2);

    expect(step1.nextChainKey.equals(step2.nextChainKey)).toBe(false);
    expect(step2.nextChainKey.equals(step3.nextChainKey)).toBe(false);
  });

  it('each MessageKey is unique across the chain', () => {
    let ck = freshChainKey();
    const mks: Buffer[] = [];

    for (let n = 0; n < 5; n++) {
      const adv = advanceChainKey(ck, n);
      mks.push(adv.messageKey);
      ck = adv.nextChainKey;
    }

    // All 5 message keys are unique
    const hexSet = new Set(mks.map((b) => b.toString('hex')));
    expect(hexSet.size).toBe(5);
  });

  it('MessageKey and NextChainKey are different (HMAC inputs 0x01 vs 0x02)', () => {
    const ck = freshChainKey();
    const adv = advanceChainKey(ck, 0);

    expect(adv.messageKey.equals(adv.nextChainKey)).toBe(false);
  });

  it('counter is reported correctly', () => {
    const ck = freshChainKey();
    expect(advanceChainKey(ck, 0).counter).toBe(0);
    expect(advanceChainKey(ck, 5).counter).toBe(5);
    expect(advanceChainKey(ck, 100).counter).toBe(100);
  });

  // ─── Validation ───────────────────────────────────────────────────────

  it('rejects wrong-size chainKey', () => {
    expect(() => advanceChainKey(asChainKey(Buffer.alloc(10)), 0)).toThrow(
      ValidationError,
    );
  });

  it('rejects negative counter', () => {
    expect(() => advanceChainKey(freshChainKey(), -1)).toThrow(ValidationError);
  });

  it('rejects non-integer counter', () => {
    expect(() => advanceChainKey(freshChainKey(), 1.5)).toThrow(ValidationError);
  });

  it('rejects non-Buffer chainKey', () => {
    expect(() => advanceChainKey('string' as never, 0)).toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// advanceChainKeyN
// ═══════════════════════════════════════════════════════════════════════════

describe('advanceChainKeyN (skip forward)', () => {
  it('returns empty skipped array when target === start', () => {
    const ck = freshChainKey();
    const result = advanceChainKeyN(ck, 0, 0);

    expect(result.skippedKeys).toHaveLength(0);
    expect(result.nextChainKey.equals(ck)).toBe(true);
  });

  it('skipping 3 steps produces 3 MessageKeys', () => {
    const ck = freshChainKey();
    const result = advanceChainKeyN(ck, 0, 3);

    expect(result.skippedKeys).toHaveLength(3);
    expect(result.skippedKeys[0]!.counter).toBe(0);
    expect(result.skippedKeys[1]!.counter).toBe(1);
    expect(result.skippedKeys[2]!.counter).toBe(2);
  });

  it('matches the result of N sequential advanceChainKey calls', () => {
    const ck0 = freshChainKey();

    // Manual loop
    let manualCk = ck0;
    const manualMks: Buffer[] = [];
    for (let n = 0; n < 5; n++) {
      const adv = advanceChainKey(manualCk, n);
      manualMks.push(adv.messageKey);
      manualCk = adv.nextChainKey;
    }

    // advanceChainKeyN
    const bulk = advanceChainKeyN(ck0, 0, 5);

    expect(bulk.skippedKeys).toHaveLength(5);
    bulk.skippedKeys.forEach((adv, i) => {
      expect(adv.messageKey.equals(manualMks[i]!)).toBe(true);
    });
    expect(bulk.nextChainKey.equals(manualCk)).toBe(true);
  });

  it('rejects target < start', () => {
    expect(() => advanceChainKeyN(freshChainKey(), 5, 3)).toThrow(ValidationError);
  });

  it('rejects non-integer counters', () => {
    expect(() => advanceChainKeyN(freshChainKey(), 0.5, 5)).toThrow(ValidationError);
    expect(() => advanceChainKeyN(freshChainKey(), 0, 5.5)).toThrow(ValidationError);
  });

  it('rejects negative starting counter', () => {
    expect(() => advanceChainKeyN(freshChainKey(), -1, 5)).toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// expandMessageKey
// ═══════════════════════════════════════════════════════════════════════════

describe('expandMessageKey (HKDF expansion)', () => {
  it('produces aesKey (32), hmacKey (32), iv (16)', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const expanded = expandMessageKey(mk);

    expect(expanded.aesKey.length).toBe(AES_KEY_SIZE);
    expect(expanded.hmacKey.length).toBe(AES_KEY_SIZE);
    expect(expanded.iv.length).toBe(AES_CBC_IV_SIZE);
  });

  it('three parts are distinct', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const e = expandMessageKey(mk);

    expect(e.aesKey.equals(e.hmacKey)).toBe(false);
    expect(e.aesKey.subarray(0, AES_CBC_IV_SIZE).equals(e.iv)).toBe(false);
  });

  it('deterministic: same input → same output', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const e1 = expandMessageKey(mk);
    const e2 = expandMessageKey(mk);

    expect(e1.aesKey.equals(e2.aesKey)).toBe(true);
    expect(e1.hmacKey.equals(e2.hmacKey)).toBe(true);
    expect(e1.iv.equals(e2.iv)).toBe(true);
  });

  it('different MK seeds → different expansion', () => {
    const mk1 = asMessageKey(crypto.randomBytes(32));
    const mk2 = asMessageKey(crypto.randomBytes(32));

    const e1 = expandMessageKey(mk1);
    const e2 = expandMessageKey(mk2);

    expect(e1.aesKey.equals(e2.aesKey)).toBe(false);
  });

  it('rejects non-Buffer input', () => {
    expect(() => expandMessageKey('string' as never)).toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// encrypt / decrypt round trip
// ═══════════════════════════════════════════════════════════════════════════

describe('encryptWithMessageKey + decryptWithMessageKey', () => {
  it('round-trips a short message', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const plaintext = Buffer.from('Hello Bob!');
    const ad = Buffer.from('header data');

    const { ciphertext, mac } = encryptWithMessageKey(mk, plaintext, ad);
    expect(mac.length).toBe(MAC_TRUNCATE_SIZE);

    const decrypted = decryptWithMessageKey(mk, ciphertext, mac, ad);
    expect(decrypted.toString('utf-8')).toBe('Hello Bob!');
  });

  it('round-trips a long message (multiple AES blocks)', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const plaintext = Buffer.alloc(5000, 0xab); // 5000 bytes, far past block size
    const ad = Buffer.from('header');

    const { ciphertext, mac } = encryptWithMessageKey(mk, plaintext, ad);
    const decrypted = decryptWithMessageKey(mk, ciphertext, mac, ad);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('round-trips empty plaintext', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const ad = Buffer.from('header');

    const { ciphertext, mac } = encryptWithMessageKey(mk, Buffer.alloc(0), ad);
    const decrypted = decryptWithMessageKey(mk, ciphertext, mac, ad);

    expect(decrypted.length).toBe(0);
  });

  it('round-trips with empty associated data', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const pt = Buffer.from('data');

    const { ciphertext, mac } = encryptWithMessageKey(mk, pt, Buffer.alloc(0));
    const decrypted = decryptWithMessageKey(mk, ciphertext, mac, Buffer.alloc(0));

    expect(decrypted.toString()).toBe('data');
  });

  // ─── Security: MAC failures ───────────────────────────────────────────

  it('rejects tampered ciphertext', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const pt = Buffer.from('Hello');
    const ad = Buffer.from('header');

    const { ciphertext, mac } = encryptWithMessageKey(mk, pt, ad);

    // Flip a bit
    const tampered = Buffer.from(ciphertext);
    tampered[0] ^= 0xff;

    expect(() => decryptWithMessageKey(mk, tampered, mac, ad)).toThrow(SignatureError);
  });

  it('rejects tampered MAC', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const pt = Buffer.from('Hello');
    const ad = Buffer.from('header');

    const { ciphertext, mac } = encryptWithMessageKey(mk, pt, ad);

    const tamperedMac = Buffer.from(mac);
    tamperedMac[0] ^= 0xff;

    expect(() => decryptWithMessageKey(mk, ciphertext, tamperedMac, ad)).toThrow(
      SignatureError,
    );
  });

  it('rejects tampered associated data', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    const pt = Buffer.from('Hello');
    const ad = Buffer.from('header');

    const { ciphertext, mac } = encryptWithMessageKey(mk, pt, ad);

    const tamperedAd = Buffer.from('HEADER'); // different AD
    expect(() => decryptWithMessageKey(mk, ciphertext, mac, tamperedAd)).toThrow(
      SignatureError,
    );
  });

  it('rejects wrong MessageKey', () => {
    const mk1 = asMessageKey(crypto.randomBytes(32));
    const mk2 = asMessageKey(crypto.randomBytes(32));
    const pt = Buffer.from('Hello');
    const ad = Buffer.from('header');

    const { ciphertext, mac } = encryptWithMessageKey(mk1, pt, ad);
    expect(() => decryptWithMessageKey(mk2, ciphertext, mac, ad)).toThrow(
      SignatureError,
    );
  });

  // ─── Validation ───────────────────────────────────────────────────────

  it('encrypt rejects non-Buffer plaintext', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    expect(() =>
      encryptWithMessageKey(mk, 'string' as never, Buffer.alloc(0)),
    ).toThrow(ValidationError);
  });

  it('encrypt rejects non-Buffer associatedData', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    expect(() =>
      encryptWithMessageKey(mk, Buffer.alloc(0), 'string' as never),
    ).toThrow(ValidationError);
  });

  it('decrypt rejects non-Buffer ciphertext', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    expect(() =>
      decryptWithMessageKey(mk, 'string' as never, Buffer.alloc(MAC_TRUNCATE_SIZE), Buffer.alloc(0)),
    ).toThrow(ValidationError);
  });

  it('decrypt rejects wrong MAC size', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    expect(() =>
      decryptWithMessageKey(mk, Buffer.alloc(16), Buffer.alloc(4), Buffer.alloc(0)),
    ).toThrow(ValidationError);
  });

  it('decrypt rejects non-Buffer associatedData', () => {
    const mk = asMessageKey(crypto.randomBytes(32));
    expect(() =>
      decryptWithMessageKey(mk, Buffer.alloc(16), Buffer.alloc(MAC_TRUNCATE_SIZE), 'string' as never),
    ).toThrow(ValidationError);
  });
});
