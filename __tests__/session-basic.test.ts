/**
 * Session basic tests — single message round-trip + lifecycle.
 */

import { describe, it, expect } from 'vitest';

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
  Session,
  isSession,
  ValidationError,
  SerializationError,
  SignatureError,
} from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// Helper: complete X3DH → Session setup for both parties
// ═══════════════════════════════════════════════════════════════════════════

function setupSessions() {
  // ─── Bob registers ────────────────────────────────────────────────
  const bob = IdentityKeyPair.generate();
  const bobSpk = SignedPreKey.generate(bob, 1);
  const bobOpk = OneTimePreKey.generate(100);
  const bobBundle = PreKeyBundle.build({
    registrationId: 4242,
    identityKey: bob.toPublic(),
    signedPreKey: bobSpk.toPublic(),
    oneTimePreKey: bobOpk.toPublic(),
  });

  // ─── Alice initiates ──────────────────────────────────────────────
  const alice = IdentityKeyPair.generate();
  const handshake = X3DH.initiate(alice, bobBundle, {
    myRegistrationId: 1234,
  });

  const aliceSession = Session.initiateFromX3DH({
    sharedSecret: handshake.sharedSecret,
    theirIdentityKey: bob.toPublic(),
    theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
  });

  // ─── Bob receives ─────────────────────────────────────────────────
  const bobResult = X3DH.receive(bob, bobSpk, bobOpk, handshake.initialMessage);

  const bobSession = Session.receiveFromX3DH({
    sharedSecret: bobResult.sharedSecret,
    myIdentityKey: bob.toPublic(),
    mySignedPreKeyPrivate: bobSpk.privateKey,
    mySignedPreKeyPublic: bobSpk.publicKey,
    theirIdentityKey: alice.toPublic(),
  });

  return { alice, bob, aliceSession, bobSession };
}

// ═══════════════════════════════════════════════════════════════════════════
// Single message round-trip
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — basic single message', () => {
  it('Alice encrypts, Bob decrypts (one message)', () => {
    const { aliceSession, bobSession } = setupSessions();

    const plaintext = Buffer.from('Hola Bob, soy Alice');
    const packet = aliceSession.encrypt(plaintext);
    const decoded = bobSession.decrypt(packet);

    expect(decoded.toString('utf-8')).toBe('Hola Bob, soy Alice');
  });

  it('counters advance after each encrypt/decrypt', () => {
    const { aliceSession, bobSession } = setupSessions();

    expect(aliceSession.sendingCounterValue()).toBe(0);
    expect(bobSession.receivingCounterValue()).toBe(0);

    const packet = aliceSession.encrypt(Buffer.from('x'));
    expect(aliceSession.sendingCounterValue()).toBe(1);

    bobSession.decrypt(packet);
    expect(bobSession.receivingCounterValue()).toBe(1);
  });

  it('round-trips empty plaintext', () => {
    const { aliceSession, bobSession } = setupSessions();
    const packet = aliceSession.encrypt(Buffer.alloc(0));
    const decoded = bobSession.decrypt(packet);
    expect(decoded.length).toBe(0);
  });

  it('round-trips large plaintext (10 KB)', () => {
    const { aliceSession, bobSession } = setupSessions();
    const pt = Buffer.alloc(10_000, 0xab);
    const packet = aliceSession.encrypt(pt);
    const decoded = bobSession.decrypt(packet);
    expect(decoded.equals(pt)).toBe(true);
  });

  it('packet has expected wire format', () => {
    const { aliceSession } = setupSessions();
    const packet = aliceSession.encrypt(Buffer.from('hi'));

    expect(typeof packet.header).toBe('string');
    expect(typeof packet.ciphertext).toBe('string');
    expect(typeof packet.mac).toBe('string');

    // Header is hex of 40 bytes = 80 chars
    expect(packet.header.length).toBe(80);
    // MAC is 8 bytes = 16 hex chars
    expect(packet.mac.length).toBe(16);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Multiple messages (chain ratchet advancing)
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — multiple messages in order', () => {
  it('Alice sends 10 messages, Bob decrypts all', () => {
    const { aliceSession, bobSession } = setupSessions();

    for (let i = 0; i < 10; i++) {
      const pt = Buffer.from(`Message ${i}`);
      const packet = aliceSession.encrypt(pt);
      const decoded = bobSession.decrypt(packet);
      expect(decoded.toString()).toBe(`Message ${i}`);
    }

    expect(aliceSession.sendingCounterValue()).toBe(10);
    expect(bobSession.receivingCounterValue()).toBe(10);
  });

  it('each message uses a different key (no key reuse)', () => {
    const { aliceSession, bobSession } = setupSessions();
    const packets = [];
    for (let i = 0; i < 5; i++) {
      packets.push(aliceSession.encrypt(Buffer.from('same')));
    }
    // All ciphertexts are different (different keys, different IVs)
    const cts = new Set(packets.map((p) => p.ciphertext));
    expect(cts.size).toBe(5);
    // Decrypt verifies they all work
    for (const p of packets) {
      expect(bobSession.decrypt(p).toString()).toBe('same');
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════════════════════════════

describe('Session.initiateFromX3DH validation', () => {
  it('rejects wrong sharedSecret size', () => {
    const bob = IdentityKeyPair.generate();
    expect(() =>
      Session.initiateFromX3DH({
        sharedSecret: Buffer.alloc(10),
        theirIdentityKey: bob.toPublic(),
        theirSignedPreKeyPublic: Buffer.alloc(32),
      }),
    ).toThrow(ValidationError);
  });

  it('rejects non-PublicIdentityKey', () => {
    expect(() =>
      Session.initiateFromX3DH({
        sharedSecret: Buffer.alloc(32),
        theirIdentityKey: {} as never,
        theirSignedPreKeyPublic: Buffer.alloc(32),
      }),
    ).toThrow(ValidationError);
  });

  it('rejects wrong theirSignedPreKeyPublic size', () => {
    const bob = IdentityKeyPair.generate();
    expect(() =>
      Session.initiateFromX3DH({
        sharedSecret: Buffer.alloc(32),
        theirIdentityKey: bob.toPublic(),
        theirSignedPreKeyPublic: Buffer.alloc(10),
      }),
    ).toThrow(ValidationError);
  });
});

describe('Session.receiveFromX3DH validation', () => {
  it('rejects wrong sharedSecret size', () => {
    const me = IdentityKeyPair.generate();
    const them = IdentityKeyPair.generate();
    expect(() =>
      Session.receiveFromX3DH({
        sharedSecret: Buffer.alloc(10),
        myIdentityKey: me.toPublic(),
        mySignedPreKeyPrivate: Buffer.alloc(32),
        mySignedPreKeyPublic: Buffer.alloc(32),
        theirIdentityKey: them.toPublic(),
      }),
    ).toThrow(ValidationError);
  });

  it('rejects wrong mySignedPreKeyPrivate size', () => {
    const me = IdentityKeyPair.generate();
    const them = IdentityKeyPair.generate();
    expect(() =>
      Session.receiveFromX3DH({
        sharedSecret: Buffer.alloc(32),
        myIdentityKey: me.toPublic(),
        mySignedPreKeyPrivate: Buffer.alloc(10),
        mySignedPreKeyPublic: Buffer.alloc(32),
        theirIdentityKey: them.toPublic(),
      }),
    ).toThrow(ValidationError);
  });

  it('rejects wrong mySignedPreKeyPublic size', () => {
    const me = IdentityKeyPair.generate();
    const them = IdentityKeyPair.generate();
    expect(() =>
      Session.receiveFromX3DH({
        sharedSecret: Buffer.alloc(32),
        myIdentityKey: me.toPublic(),
        mySignedPreKeyPrivate: Buffer.alloc(32),
        mySignedPreKeyPublic: Buffer.alloc(10),
        theirIdentityKey: them.toPublic(),
      }),
    ).toThrow(ValidationError);
  });

  it('rejects non-PublicIdentityKey for myIdentityKey', () => {
    const them = IdentityKeyPair.generate();
    expect(() =>
      Session.receiveFromX3DH({
        sharedSecret: Buffer.alloc(32),
        myIdentityKey: {} as never,
        mySignedPreKeyPrivate: Buffer.alloc(32),
        mySignedPreKeyPublic: Buffer.alloc(32),
        theirIdentityKey: them.toPublic(),
      }),
    ).toThrow(ValidationError);
  });

  it('rejects non-PublicIdentityKey for theirIdentityKey', () => {
    const me = IdentityKeyPair.generate();
    expect(() =>
      Session.receiveFromX3DH({
        sharedSecret: Buffer.alloc(32),
        myIdentityKey: me.toPublic(),
        mySignedPreKeyPrivate: Buffer.alloc(32),
        mySignedPreKeyPublic: Buffer.alloc(32),
        theirIdentityKey: {} as never,
      }),
    ).toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// encrypt/decrypt validation
// ═══════════════════════════════════════════════════════════════════════════

describe('Session encrypt/decrypt input validation', () => {
  it('encrypt rejects non-Buffer plaintext', () => {
    const { aliceSession } = setupSessions();
    expect(() => aliceSession.encrypt('string' as never)).toThrow(ValidationError);
  });

  it('decrypt rejects null packet', () => {
    const { bobSession } = setupSessions();
    expect(() => bobSession.decrypt(null as never)).toThrow(SerializationError);
  });

  it('decrypt rejects packet with non-string fields', () => {
    const { bobSession } = setupSessions();
    expect(() =>
      bobSession.decrypt({ header: 123, ciphertext: 'a', mac: 'b' } as never),
    ).toThrow(SerializationError);
  });

  it('decrypt rejects packet with wrong MAC size', () => {
    const { aliceSession, bobSession } = setupSessions();
    const packet = aliceSession.encrypt(Buffer.from('x'));
    expect(() =>
      bobSession.decrypt({ ...packet, mac: '00' }),
    ).toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Tamper detection
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — tamper detection', () => {
  it('rejects tampered ciphertext', () => {
    const { aliceSession, bobSession } = setupSessions();
    const packet = aliceSession.encrypt(Buffer.from('secret'));

    // Flip a hex char in ciphertext
    const tamperedCt = packet.ciphertext.replace(/^./, (c) =>
      c === 'a' ? 'b' : 'a',
    );

    expect(() =>
      bobSession.decrypt({ ...packet, ciphertext: tamperedCt }),
    ).toThrow(SignatureError);
  });

  it('rejects tampered MAC', () => {
    const { aliceSession, bobSession } = setupSessions();
    const packet = aliceSession.encrypt(Buffer.from('secret'));

    const tamperedMac = packet.mac.replace(/^./, (c) =>
      c === 'a' ? 'b' : 'a',
    );

    expect(() =>
      bobSession.decrypt({ ...packet, mac: tamperedMac }),
    ).toThrow(SignatureError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Type guard + accessors
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — utilities', () => {
  it('isSession returns true for Session', () => {
    const { aliceSession } = setupSessions();
    expect(isSession(aliceSession)).toBe(true);
  });

  it('isSession returns false for non-Session', () => {
    expect(isSession({})).toBe(false);
    expect(isSession(null)).toBe(false);
    expect(isSession(undefined)).toBe(false);
    expect(isSession('string')).toBe(false);
  });

  it('toString is safe and informative', () => {
    const { aliceSession, bob } = setupSessions();
    const str = aliceSession.toString();
    expect(str).toMatch(/Session\(peer=.{16}, sent=0, recv=0, skipped=0\)/);
    expect(str).toContain(bob.shortFingerprint());
  });

  it('toJSON does not leak private state', () => {
    const { aliceSession } = setupSessions();
    const json = aliceSession.toJSON();
    expect(json.type).toBe('Session');
    expect(json).toHaveProperty('peer');
    expect(json).toHaveProperty('sent');
    expect(json).toHaveProperty('recv');
    expect(json).toHaveProperty('skipped');
    // No private key material
    expect(JSON.stringify(json)).not.toContain('rootKey');
    expect(JSON.stringify(json)).not.toContain('chainKey');
  });

  it('skippedKeysCount() works', () => {
    const { aliceSession } = setupSessions();
    expect(aliceSession.skippedKeysCount()).toBe(0);
  });
});
