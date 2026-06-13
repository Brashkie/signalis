/**
 * Session DH ratchet tests — Bob replies, both sides rotate keys.
 */

import { describe, it, expect } from 'vitest';

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
  Session,
} from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// Helper
// ═══════════════════════════════════════════════════════════════════════════

function setupSessions() {
  const bob = IdentityKeyPair.generate();
  const bobSpk = SignedPreKey.generate(bob, 1);
  const bobOpk = OneTimePreKey.generate(100);
  const bobBundle = PreKeyBundle.build({
    registrationId: 4242,
    identityKey: bob.toPublic(),
    signedPreKey: bobSpk.toPublic(),
    oneTimePreKey: bobOpk.toPublic(),
  });

  const alice = IdentityKeyPair.generate();
  const handshake = X3DH.initiate(alice, bobBundle, { myRegistrationId: 1234 });

  const aliceSession = Session.initiateFromX3DH({
    sharedSecret: handshake.sharedSecret,
    theirIdentityKey: bob.toPublic(),
    theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
  });

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
// Bidirectional flow
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — bidirectional flow with DH ratchet rotation', () => {
  it('Alice sends, Bob replies, Alice receives', () => {
    const { aliceSession, bobSession } = setupSessions();

    // Alice → Bob
    const p1 = aliceSession.encrypt(Buffer.from('Hola Bob'));
    expect(bobSession.decrypt(p1).toString()).toBe('Hola Bob');

    // Bob → Alice (DH rotation happens here)
    const p2 = bobSession.encrypt(Buffer.from('Hola Alice'));
    expect(aliceSession.decrypt(p2).toString()).toBe('Hola Alice');
  });

  it('full ping-pong conversation', () => {
    const { aliceSession, bobSession } = setupSessions();

    // 5 round trips
    for (let i = 0; i < 5; i++) {
      const fromA = aliceSession.encrypt(Buffer.from(`Alice #${i}`));
      expect(bobSession.decrypt(fromA).toString()).toBe(`Alice #${i}`);

      const fromB = bobSession.encrypt(Buffer.from(`Bob #${i}`));
      expect(aliceSession.decrypt(fromB).toString()).toBe(`Bob #${i}`);
    }
  });

  it('multiple messages in a row from one side, then reply', () => {
    const { aliceSession, bobSession } = setupSessions();

    // Alice sends 3 in a row
    const a0 = aliceSession.encrypt(Buffer.from('A0'));
    const a1 = aliceSession.encrypt(Buffer.from('A1'));
    const a2 = aliceSession.encrypt(Buffer.from('A2'));

    expect(bobSession.decrypt(a0).toString()).toBe('A0');
    expect(bobSession.decrypt(a1).toString()).toBe('A1');
    expect(bobSession.decrypt(a2).toString()).toBe('A2');

    // Bob replies (triggers DH ratchet)
    const b0 = bobSession.encrypt(Buffer.from('B0'));
    expect(aliceSession.decrypt(b0).toString()).toBe('B0');

    // Alice sends more (her DH ratchet rotates too on next encrypt)
    const a3 = aliceSession.encrypt(Buffer.from('A3'));
    expect(bobSession.decrypt(a3).toString()).toBe('A3');
  });

  it('three full rotations in a row', () => {
    const { aliceSession, bobSession } = setupSessions();

    // Round 1
    const a1 = aliceSession.encrypt(Buffer.from('A1'));
    bobSession.decrypt(a1);
    const b1 = bobSession.encrypt(Buffer.from('B1'));
    aliceSession.decrypt(b1);

    // Round 2
    const a2 = aliceSession.encrypt(Buffer.from('A2'));
    bobSession.decrypt(a2);
    const b2 = bobSession.encrypt(Buffer.from('B2'));
    aliceSession.decrypt(b2);

    // Round 3
    const a3 = aliceSession.encrypt(Buffer.from('A3'));
    expect(bobSession.decrypt(a3).toString()).toBe('A3');
    const b3 = bobSession.encrypt(Buffer.from('B3'));
    expect(aliceSession.decrypt(b3).toString()).toBe('B3');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Bob cannot encrypt before receiving anything
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — responder constraints', () => {
  it('Bob cannot encrypt() before receiving any message from Alice', () => {
    const { bobSession } = setupSessions();

    // Bob hasn't received yet → his lastReceivedDhPublic is null → encrypt fails
    expect(() => bobSession.encrypt(Buffer.from('premature'))).toThrow();
  });

  it('Bob CAN encrypt() after receiving Alice\'s first message', () => {
    const { aliceSession, bobSession } = setupSessions();

    const p = aliceSession.encrypt(Buffer.from('Hola Bob'));
    bobSession.decrypt(p);

    // Now Bob has Alice's DH key, so he can encrypt and rotate
    const reply = bobSession.encrypt(Buffer.from('Hola Alice'));
    expect(reply.header).toBeTruthy();
    expect(aliceSession.decrypt(reply).toString()).toBe('Hola Alice');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// previousSendingCounter (pn) tracking
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — counter tracking', () => {
  it('sendingCounter resets after DH rotation', () => {
    const { aliceSession, bobSession } = setupSessions();

    aliceSession.encrypt(Buffer.from('a0'));
    aliceSession.encrypt(Buffer.from('a1'));
    aliceSession.encrypt(Buffer.from('a2'));
    expect(aliceSession.sendingCounterValue()).toBe(3);

    // Receive a message from Bob → Alice will rotate on her next encrypt
    // First, Bob has to receive at least one message from Alice
    const a = aliceSession.encrypt(Buffer.from('a3'));
    bobSession.decrypt(a);
    const fromB = bobSession.encrypt(Buffer.from('bob reply'));
    aliceSession.decrypt(fromB);

    // Alice's next encrypt rotates → counter resets to 0 then increments
    aliceSession.encrypt(Buffer.from('after rotation'));
    expect(aliceSession.sendingCounterValue()).toBe(1);
  });
});
