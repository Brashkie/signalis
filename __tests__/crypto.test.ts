import { describe, it, expect } from 'vitest';
import {
  randomBytes,
  generateKeyPair,
  diffieHellman,
  signXEd25519,
  signXEd25519WithRandom,
  verifyXEd25519,
  verifyXEd25519Bool,
  generateEd25519KeyPair,
  ed25519FromSeed,
  signEd25519,
  verifyEd25519,
  verifyEd25519Bool,
  hkdf,
  hkdfMultiple,
  hmac,
  hmacVerify,
  sha256,
  sha256Multiple,
  aesGcmEncrypt,
  aesGcmDecrypt,
  aesGcmEncryptWithAad,
  aesGcmDecryptWithAad,
} from '../src/crypto';
import { ValidationError, SignatureError } from '../src/errors';
import { asSignature } from '../src/types';

describe('Crypto Wrappers', () => {
  describe('randomBytes', () => {
    it('generates correct size', () => {
      expect(randomBytes(0).length).toBe(0);
      expect(randomBytes(16).length).toBe(16);
      expect(randomBytes(32).length).toBe(32);
      expect(randomBytes(1024).length).toBe(1024);
    });

    it('throws on negative size', () => {
      expect(() => randomBytes(-1)).toThrow(ValidationError);
    });

    it('throws on non-integer', () => {
      expect(() => randomBytes(1.5)).toThrow(ValidationError);
    });

    it('produces different output each call', () => {
      const a = randomBytes(32);
      const b = randomBytes(32);
      expect(a.equals(b)).toBe(false);
    });
  });

  describe('generateKeyPair', () => {
    it('creates valid keypair', () => {
      const kp = generateKeyPair();
      expect(kp.publicKey.length).toBe(32);
      expect(kp.privateKey.length).toBe(32);
    });

    it('different each call', () => {
      const a = generateKeyPair();
      const b = generateKeyPair();
      expect(a.publicKey.equals(b.publicKey)).toBe(false);
    });
  });

  describe('diffieHellman', () => {
    it('computes shared secret', () => {
      const a = generateKeyPair();
      const b = generateKeyPair();
      const ab = diffieHellman(a.privateKey, b.publicKey);
      const ba = diffieHellman(b.privateKey, a.publicKey);
      expect(ab.equals(ba)).toBe(true);
      expect(ab.length).toBe(32);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // XEd25519 — Signal-style signatures with Curve25519 keys (NEW v0.2.0)
  // ═══════════════════════════════════════════════════════════════════════

  describe('XEd25519', () => {
    it('produces 64-byte signature', () => {
      const kp = generateKeyPair();
      const sig = signXEd25519(kp.privateKey, Buffer.from('test'));
      expect(sig.length).toBe(64);
    });

    it('verifies a valid signature', () => {
      const kp = generateKeyPair();
      const msg = Buffer.from('Hello XEd25519');
      const sig = signXEd25519(kp.privateKey, msg);
      // Should not throw
      verifyXEd25519(kp.publicKey, msg, sig);
    });

    it('rejects tampered message', () => {
      const kp = generateKeyPair();
      const sig = signXEd25519(kp.privateKey, Buffer.from('original'));
      expect(() =>
        verifyXEd25519(kp.publicKey, Buffer.from('tampered'), sig),
      ).toThrow(SignatureError);
    });

    it('rejects wrong public key', () => {
      const a = generateKeyPair();
      const b = generateKeyPair();
      const sig = signXEd25519(a.privateKey, Buffer.from('msg'));
      expect(() =>
        verifyXEd25519(b.publicKey, Buffer.from('msg'), sig),
      ).toThrow(SignatureError);
    });

    it('signatures are non-deterministic', () => {
      const kp = generateKeyPair();
      const msg = Buffer.from('test');
      const sig1 = signXEd25519(kp.privateKey, msg);
      const sig2 = signXEd25519(kp.privateKey, msg);
      expect(sig1.equals(sig2)).toBe(false);

      // But both verify
      verifyXEd25519(kp.publicKey, msg, sig1);
      verifyXEd25519(kp.publicKey, msg, sig2);
    });

    it('verifyXEd25519Bool returns true for valid', () => {
      const kp = generateKeyPair();
      const msg = Buffer.from('test');
      const sig = signXEd25519(kp.privateKey, msg);
      expect(verifyXEd25519Bool(kp.publicKey, msg, sig)).toBe(true);
    });

    it('verifyXEd25519Bool returns false for invalid', () => {
      const kp = generateKeyPair();
      const fakeSig = Buffer.alloc(64);
      expect(
        verifyXEd25519Bool(kp.publicKey, Buffer.from('msg'), fakeSig),
      ).toBe(false);
    });

    it('signWithRandom is deterministic', () => {
      const kp = generateKeyPair();
      const msg = Buffer.from('test');
      const random = Buffer.alloc(64, 0x99);
      const sig1 = signXEd25519WithRandom(kp.privateKey, msg, random);
      const sig2 = signXEd25519WithRandom(kp.privateKey, msg, random);
      expect(sig1.equals(sig2)).toBe(true);

      // And it verifies
      verifyXEd25519(kp.publicKey, msg, sig1);
    });

    it('signWithRandom with different randoms gives different sigs', () => {
      const kp = generateKeyPair();
      const msg = Buffer.from('test');
      const r1 = Buffer.alloc(64, 0x11);
      const r2 = Buffer.alloc(64, 0x22);
      const sig1 = signXEd25519WithRandom(kp.privateKey, msg, r1);
      const sig2 = signXEd25519WithRandom(kp.privateKey, msg, r2);
      expect(sig1.equals(sig2)).toBe(false);
    });

    it('Signal-style: SAME key for ECDH and signing', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      // ECDH works
      const aShared = diffieHellman(alice.privateKey, bob.publicKey);
      const bShared = diffieHellman(bob.privateKey, alice.publicKey);
      expect(aShared.equals(bShared)).toBe(true);

      // SAME alice key signs
      const sig = signXEd25519(alice.privateKey, Buffer.from('I am alice'));
      verifyXEd25519(alice.publicKey, Buffer.from('I am alice'), sig);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Ed25519 — standard signatures (NEW v0.2.0)
  // ═══════════════════════════════════════════════════════════════════════

  describe('Ed25519', () => {
    it('generates 32-byte keys', () => {
      const kp = generateEd25519KeyPair();
      expect(kp.privateKey.length).toBe(32);
      expect(kp.publicKey.length).toBe(32);
    });

    it('signature is deterministic (RFC 8032)', () => {
      const kp = generateEd25519KeyPair();
      const msg = Buffer.from('test');
      const sig1 = signEd25519(kp.privateKey, msg);
      const sig2 = signEd25519(kp.privateKey, msg);
      expect(sig1.equals(sig2)).toBe(true);
    });

    it('keyPairFromSeed is deterministic', () => {
      const seed = Buffer.alloc(32, 0x42);
      const a = ed25519FromSeed(seed);
      const b = ed25519FromSeed(seed);
      expect(a.privateKey.equals(b.privateKey)).toBe(true);
      expect(a.publicKey.equals(b.publicKey)).toBe(true);
    });

    it('verify accepts valid signature', () => {
      const kp = generateEd25519KeyPair();
      const msg = Buffer.from('Ed25519 test');
      const sig = signEd25519(kp.privateKey, msg);
      verifyEd25519(kp.publicKey, msg, sig);
    });

    it('verify throws SignatureError on tamper', () => {
      const kp = generateEd25519KeyPair();
      const sig = signEd25519(kp.privateKey, Buffer.from('original'));
      expect(() =>
        verifyEd25519(kp.publicKey, Buffer.from('tampered'), sig),
      ).toThrow(SignatureError);
    });

    it('verifyEd25519Bool', () => {
      const kp = generateEd25519KeyPair();
      const msg = Buffer.from('m');
      const sig = signEd25519(kp.privateKey, msg);
      expect(verifyEd25519Bool(kp.publicKey, msg, sig)).toBe(true);
      expect(verifyEd25519Bool(kp.publicKey, Buffer.from('x'), sig)).toBe(false);
    });

    it('RFC 8032 vector 1 (empty message)', () => {
      const seed = Buffer.from(
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
        'hex',
      );
      const expectedPub = Buffer.from(
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        'hex',
      );
      const expectedSig = Buffer.from(
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        'hex',
      );

      const kp = ed25519FromSeed(seed);
      expect(kp.publicKey.equals(expectedPub)).toBe(true);

      const sig = signEd25519(seed, Buffer.alloc(0));
      expect(sig.equals(expectedSig)).toBe(true);

      verifyEd25519(expectedPub, Buffer.alloc(0), expectedSig);
    });
  });

  describe('HKDF', () => {
    it('derives correct size', () => {
      const key = hkdf(Buffer.from('s'), Buffer.from('i'), Buffer.from('x'), 64);
      expect(key.length).toBe(64);
    });

    it('is deterministic', () => {
      const a = hkdf(Buffer.from('s'), Buffer.from('i'), Buffer.from('x'), 32);
      const b = hkdf(Buffer.from('s'), Buffer.from('i'), Buffer.from('x'), 32);
      expect(a.equals(b)).toBe(true);
    });

    it('hkdfMultiple derives multiple', () => {
      const keys = hkdfMultiple(
        Buffer.from('s'),
        Buffer.from('i'),
        Buffer.from('x'),
        [32, 16, 8],
      );
      expect(keys).toHaveLength(3);
      expect(keys[0]!.length).toBe(32);
      expect(keys[1]!.length).toBe(16);
      expect(keys[2]!.length).toBe(8);
    });
  });

  describe('HMAC', () => {
    it('computes 32-byte tag', () => {
      const tag = hmac(Buffer.alloc(32), Buffer.from('msg'));
      expect(tag.length).toBe(32);
    });

    it('verifies correctly', () => {
      const key = randomBytes(32);
      const data = Buffer.from('test');
      const tag = hmac(key, data);
      expect(hmacVerify(key, data, tag)).toBe(true);
    });

    it('rejects bad tag', () => {
      const key = randomBytes(32);
      const data = Buffer.from('test');
      const badTag = Buffer.alloc(32);
      expect(hmacVerify(key, data, badTag)).toBe(false);
    });
  });

  describe('SHA-256', () => {
    it('hashes to 32 bytes', () => {
      const h = sha256(Buffer.from('test'));
      expect(h.length).toBe(32);
    });

    it('NIST empty vector', () => {
      const h = sha256(Buffer.alloc(0));
      expect(h.toString('hex')).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });

    it('NIST "abc" vector', () => {
      const h = sha256(Buffer.from('abc'));
      expect(h.toString('hex')).toBe(
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    it('sha256Multiple concatenates and hashes', () => {
      const a = sha256(Buffer.concat([Buffer.from('hello'), Buffer.from('world')]));
      const b = sha256Multiple(Buffer.from('hello'), Buffer.from('world'));
      expect(a.equals(b)).toBe(true);
    });
  });

  describe('AES-GCM', () => {
    it('round-trip encrypt/decrypt', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const plaintext = Buffer.from('hello world');
      const ct = aesGcmEncrypt(key, nonce, plaintext);
      const pt = aesGcmDecrypt(key, nonce, ct);
      expect(pt.equals(plaintext)).toBe(true);
    });

    it('detects tampering', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const ct = aesGcmEncrypt(key, nonce, Buffer.from('msg'));
      ct[0]! ^= 0xff;
      expect(() => aesGcmDecrypt(key, nonce, ct)).toThrow();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // AES-GCM with AAD (NEW v0.2.0)
  // ═══════════════════════════════════════════════════════════════════════

  describe('AES-GCM with AAD', () => {
    it('round-trip with AAD', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const pt = Buffer.from('secret body');
      const aad = Buffer.from('public header');

      const ct = aesGcmEncryptWithAad(key, nonce, pt, aad);
      const dec = aesGcmDecryptWithAad(key, nonce, ct, aad);
      expect(dec.equals(pt)).toBe(true);
    });

    it('AAD mismatch fails decryption', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const ct = aesGcmEncryptWithAad(
        key,
        nonce,
        Buffer.from('msg'),
        Buffer.from('correct-aad'),
      );
      expect(() =>
        aesGcmDecryptWithAad(key, nonce, ct, Buffer.from('wrong-aad')),
      ).toThrow();
    });

    it('empty AAD equals no AAD', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const pt = Buffer.from('msg');
      const ct1 = aesGcmEncrypt(key, nonce, pt);
      const ct2 = aesGcmEncryptWithAad(key, nonce, pt, Buffer.alloc(0));
      expect(ct1.equals(ct2)).toBe(true);
    });

    it('tampered AAD fails decryption', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const aad = Buffer.from('header_data');
      const ct = aesGcmEncryptWithAad(key, nonce, Buffer.from('msg'), aad);

      const tampered = Buffer.from(aad);
      tampered[0]! ^= 0xff;
      expect(() => aesGcmDecryptWithAad(key, nonce, ct, tampered)).toThrow();
    });

    it('use case: Signal-style header binding', () => {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const body = Buffer.from('Hello Bob!');
      const header = Buffer.from(JSON.stringify({ msg_id: 1, from: 'alice' }));

      const ct = aesGcmEncryptWithAad(key, nonce, body, header);
      const dec = aesGcmDecryptWithAad(key, nonce, ct, header);
      expect(dec.equals(body)).toBe(true);
    });
  });

  // Mark asSignature as used to prevent unused-import errors
  describe('helpers', () => {
    it('asSignature is exported', () => {
      const sig = Buffer.alloc(64);
      expect(asSignature(sig).length).toBe(64);
    });
  });
});
