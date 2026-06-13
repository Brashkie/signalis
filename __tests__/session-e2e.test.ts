/**
 * Session E2E — full flow from X3DH through 20+ messages.
 *
 * This is the equivalent of v0.5.0's ratchet-e2e.test.ts but using the
 * high-level Session API. Same coverage, ~1/10 the code.
 */

import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
  Session,
  isSession,
} from '../src';

describe('Session E2E — full X3DH → Session conversation', () => {
  it('Alice and Bob have a 20-message conversation with multiple rotations', () => {
    // ─── Setup ────────────────────────────────────────────────────────
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
    const handshake = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 1234,
    });
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

    // ─── 20-message conversation (alternating + bursts) ───────────────
    const log: string[] = [];

    // Burst 1: Alice sends 3
    for (let i = 0; i < 3; i++) {
      const msg = `alice-burst1-${i}`;
      const p = aliceSession.encrypt(Buffer.from(msg));
      expect(bobSession.decrypt(p).toString()).toBe(msg);
      log.push(msg);
    }

    // Burst 2: Bob replies with 2 (DH rotation)
    for (let i = 0; i < 2; i++) {
      const msg = `bob-burst2-${i}`;
      const p = bobSession.encrypt(Buffer.from(msg));
      expect(aliceSession.decrypt(p).toString()).toBe(msg);
      log.push(msg);
    }

    // Burst 3: Alice 5 more
    for (let i = 0; i < 5; i++) {
      const msg = `alice-burst3-${i}`;
      const p = aliceSession.encrypt(Buffer.from(msg));
      expect(bobSession.decrypt(p).toString()).toBe(msg);
      log.push(msg);
    }

    // Burst 4: ping-pong 10 messages
    for (let i = 0; i < 5; i++) {
      const a = aliceSession.encrypt(Buffer.from(`pp-A-${i}`));
      expect(bobSession.decrypt(a).toString()).toBe(`pp-A-${i}`);
      const b = bobSession.encrypt(Buffer.from(`pp-B-${i}`));
      expect(aliceSession.decrypt(b).toString()).toBe(`pp-B-${i}`);
      log.push(`pp-A-${i}`, `pp-B-${i}`);
    }

    expect(log.length).toBe(20);
  });

  it('survives application restart mid-conversation', () => {
    // ─── Setup ────────────────────────────────────────────────────────
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
    const handshake = X3DH.initiate(alice, bobBundle, {
      myRegistrationId: 1234,
    });
    let aliceSession = Session.initiateFromX3DH({
      sharedSecret: handshake.sharedSecret,
      theirIdentityKey: bob.toPublic(),
      theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
    });
    const bobResult = X3DH.receive(bob, bobSpk, bobOpk, handshake.initialMessage);
    let bobSession = Session.receiveFromX3DH({
      sharedSecret: bobResult.sharedSecret,
      myIdentityKey: bob.toPublic(),
      mySignedPreKeyPrivate: bobSpk.privateKey,
      mySignedPreKeyPublic: bobSpk.publicKey,
      theirIdentityKey: alice.toPublic(),
    });

    // ─── Conversation begins ─────────────────────────────────────────
    bobSession.decrypt(aliceSession.encrypt(Buffer.from('msg 1')));
    aliceSession.decrypt(bobSession.encrypt(Buffer.from('msg 2')));
    bobSession.decrypt(aliceSession.encrypt(Buffer.from('msg 3')));

    // ─── APP CRASH — serialize both sides ────────────────────────────
    const aliceState = JSON.stringify(aliceSession.serialize());
    const bobState = JSON.stringify(bobSession.serialize());

    // ─── 5 minutes later — restore ───────────────────────────────────
    aliceSession = Session.deserialize(JSON.parse(aliceState));
    bobSession = Session.deserialize(JSON.parse(bobState));

    // ─── Continue right where they left off ──────────────────────────
    expect(
      bobSession.decrypt(aliceSession.encrypt(Buffer.from('after restart'))).toString(),
    ).toBe('after restart');
    expect(
      aliceSession.decrypt(bobSession.encrypt(Buffer.from('also after'))).toString(),
    ).toBe('also after');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// inspect coverage
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — inspect coverage', () => {
  it('util.inspect returns safe representation', () => {
    const bob = IdentityKeyPair.generate();
    const bobSpk = SignedPreKey.generate(bob, 1);
    const bobBundle = PreKeyBundle.build({
      registrationId: 1,
      identityKey: bob.toPublic(),
      signedPreKey: bobSpk.toPublic(),
    });
    const alice = IdentityKeyPair.generate();
    const h = X3DH.initiate(alice, bobBundle, { myRegistrationId: 2 });
    const s = Session.initiateFromX3DH({
      sharedSecret: h.sharedSecret,
      theirIdentityKey: bob.toPublic(),
      theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
    });

    const i = inspect(s);
    expect(i).toMatch(/Session\(peer=/);

    expect(isSession(s)).toBe(true);
  });
});
