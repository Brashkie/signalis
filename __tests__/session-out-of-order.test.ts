/**
 * Session out-of-order + serialize tests.
 */

import { describe, it, expect } from 'vitest';

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
  Session,
  SessionError,
  SerializationError,
} from '../src';

function setupSessions(maxSkippedKeys?: number) {
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
    maxSkippedKeys,
  });

  const bobResult = X3DH.receive(bob, bobSpk, bobOpk, handshake.initialMessage);

  const bobSession = Session.receiveFromX3DH({
    sharedSecret: bobResult.sharedSecret,
    myIdentityKey: bob.toPublic(),
    mySignedPreKeyPrivate: bobSpk.privateKey,
    mySignedPreKeyPublic: bobSpk.publicKey,
    theirIdentityKey: alice.toPublic(),
    maxSkippedKeys,
  });

  return { alice, bob, aliceSession, bobSession };
}

// ═══════════════════════════════════════════════════════════════════════════
// Out-of-order delivery
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — out-of-order delivery', () => {
  it('Bob receives msg #0 and #2 (#1 in flight), then #1 arrives', () => {
    const { aliceSession, bobSession } = setupSessions();

    const p0 = aliceSession.encrypt(Buffer.from('msg 0'));
    const p1 = aliceSession.encrypt(Buffer.from('msg 1'));
    const p2 = aliceSession.encrypt(Buffer.from('msg 2'));

    // Receive 0 normally
    expect(bobSession.decrypt(p0).toString()).toBe('msg 0');

    // Skip to #2 — Bob caches key for #1
    expect(bobSession.decrypt(p2).toString()).toBe('msg 2');
    expect(bobSession.skippedKeysCount()).toBe(1); // msg 1's key cached

    // #1 finally arrives → looked up from cache
    expect(bobSession.decrypt(p1).toString()).toBe('msg 1');
    expect(bobSession.skippedKeysCount()).toBe(0); // cache drained
  });

  it('Bob receives 5 messages out of order', () => {
    const { aliceSession, bobSession } = setupSessions();

    const packets = [];
    for (let i = 0; i < 5; i++) {
      packets.push(aliceSession.encrypt(Buffer.from(`m${i}`)));
    }

    // Bob receives in order: 0, 4, 2, 1, 3
    expect(bobSession.decrypt(packets[0]!).toString()).toBe('m0');
    expect(bobSession.decrypt(packets[4]!).toString()).toBe('m4'); // skip 1,2,3
    expect(bobSession.skippedKeysCount()).toBe(3);

    expect(bobSession.decrypt(packets[2]!).toString()).toBe('m2');
    expect(bobSession.decrypt(packets[1]!).toString()).toBe('m1');
    expect(bobSession.decrypt(packets[3]!).toString()).toBe('m3');
    expect(bobSession.skippedKeysCount()).toBe(0);
  });

  it('skipped keys survive across DH rotation', () => {
    const { aliceSession, bobSession } = setupSessions();

    // Alice sends 3
    const a0 = aliceSession.encrypt(Buffer.from('a0'));
    const a1 = aliceSession.encrypt(Buffer.from('a1'));
    const a2 = aliceSession.encrypt(Buffer.from('a2'));

    // Bob receives only #0
    bobSession.decrypt(a0);

    // Bob replies → his DH rotates
    const b0 = bobSession.encrypt(Buffer.from('b0'));
    aliceSession.decrypt(b0);

    // Alice sends in her new chain
    const a3 = aliceSession.encrypt(Buffer.from('a3'));

    // Bob receives a3 first → triggers DH rotation on his side,
    // pn=3 tells him to cache the 2 remaining keys from old chain (a1, a2)
    expect(bobSession.decrypt(a3).toString()).toBe('a3');
    expect(bobSession.skippedKeysCount()).toBe(2);

    // a1 and a2 finally arrive — should still decrypt from cache
    expect(bobSession.decrypt(a1).toString()).toBe('a1');
    expect(bobSession.decrypt(a2).toString()).toBe('a2');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Replay rejection
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — replay detection', () => {
  it('replaying a successfully-decrypted message is rejected', () => {
    const { aliceSession, bobSession } = setupSessions();

    const p = aliceSession.encrypt(Buffer.from('once'));
    expect(bobSession.decrypt(p).toString()).toBe('once');

    // Replay → counter is "in the past" with no cached key
    expect(() => bobSession.decrypt(p)).toThrow(SessionError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Anti-DoS cap
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — anti-DoS skipped-keys cap', () => {
  it('rejects messages that would force too many skipped derivations', () => {
    const { aliceSession, bobSession } = setupSessions(/* maxSkippedKeys */ 5);

    // Alice sends 10 messages, but Bob only sees the 10th
    let lastPacket;
    for (let i = 0; i < 10; i++) {
      lastPacket = aliceSession.encrypt(Buffer.from(`m${i}`));
    }

    // Bob tries to decrypt msg #9 → has to derive 9 skipped keys, cap is 5
    expect(() => bobSession.decrypt(lastPacket!)).toThrow();
  });

  it('respects custom maxSkippedKeys', () => {
    const { aliceSession, bobSession } = setupSessions(100);
    // 100 is enough headroom — sending 5 skipped should work
    for (let i = 0; i < 5; i++) aliceSession.encrypt(Buffer.from(`m${i}`));
    const p5 = aliceSession.encrypt(Buffer.from('m5'));
    expect(bobSession.decrypt(p5).toString()).toBe('m5');
    expect(bobSession.skippedKeysCount()).toBe(5);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Serialize / Deserialize
// ═══════════════════════════════════════════════════════════════════════════

describe('Session — serialize / deserialize', () => {
  it('basic round-trip: serialize Alice, restore, continue conversation', () => {
    const { aliceSession, bobSession } = setupSessions();

    // Send a message before serializing
    const p0 = aliceSession.encrypt(Buffer.from('before'));
    bobSession.decrypt(p0);

    // Serialize Alice's state
    const aliceSnapshot = aliceSession.serialize();
    const aliceJson = JSON.stringify(aliceSnapshot);

    // Simulate app restart: restore
    const aliceRestored = Session.deserialize(JSON.parse(aliceJson));

    // Continue sending
    const p1 = aliceRestored.encrypt(Buffer.from('after restore'));
    expect(bobSession.decrypt(p1).toString()).toBe('after restore');
  });

  it('round-trip preserves skipped keys cache', () => {
    const { aliceSession, bobSession } = setupSessions();

    // Build up skipped keys
    const p0 = aliceSession.encrypt(Buffer.from('m0'));
    const p1 = aliceSession.encrypt(Buffer.from('m1'));
    const p2 = aliceSession.encrypt(Buffer.from('m2'));

    bobSession.decrypt(p0);
    bobSession.decrypt(p2); // skip 1 → cached
    expect(bobSession.skippedKeysCount()).toBe(1);

    // Serialize Bob with the cached skipped key
    const bobSnapshot = bobSession.serialize();
    const bobRestored = Session.deserialize(
      JSON.parse(JSON.stringify(bobSnapshot)),
    );
    expect(bobRestored.skippedKeysCount()).toBe(1);

    // Now the missing message arrives → restored session decrypts from cache
    expect(bobRestored.decrypt(p1).toString()).toBe('m1');
    expect(bobRestored.skippedKeysCount()).toBe(0);
  });

  it('serialized format is JSON-safe', () => {
    const { aliceSession } = setupSessions();
    aliceSession.encrypt(Buffer.from('x'));

    const snapshot = aliceSession.serialize();
    const roundTrip = JSON.parse(JSON.stringify(snapshot));

    expect(roundTrip.version).toBe(1);
    expect(typeof roundTrip.rootKey).toBe('string');
    expect(typeof roundTrip.sendingCounter).toBe('number');
  });

  it('rejects null/non-object on deserialize', () => {
    expect(() => Session.deserialize(null as never)).toThrow(SerializationError);
    expect(() => Session.deserialize('string' as never)).toThrow(SerializationError);
  });

  it('rejects wrong version', () => {
    const { aliceSession } = setupSessions();
    const snap = aliceSession.serialize();
    expect(() =>
      Session.deserialize({ ...snap, version: 99 as 1 }),
    ).toThrow(SerializationError);
  });

  it('rejects non-hex fields', () => {
    const { aliceSession } = setupSessions();
    const snap = aliceSession.serialize();
    expect(() =>
      Session.deserialize({ ...snap, rootKey: 'ZZZ' }),
    ).toThrow(SerializationError);
  });

  it('rejects non-string rootKey', () => {
    const { aliceSession } = setupSessions();
    const snap = aliceSession.serialize();
    expect(() =>
      Session.deserialize({ ...snap, rootKey: 42 as never }),
    ).toThrow(SerializationError);
  });

  it('restored session has correct peer fingerprint', () => {
    const { aliceSession, bob } = setupSessions();
    const restored = Session.deserialize(
      JSON.parse(JSON.stringify(aliceSession.serialize())),
    );
    expect(restored.theirIdentityKey.fingerprint()).toBe(
      bob.toPublic().fingerprint(),
    );
  });

  it('null sendingChainKey/receivingChainKey preserved correctly', () => {
    const { bobSession } = setupSessions();
    // Bob hasn't sent anything yet → sendingChainKey is null
    const snap = bobSession.serialize();
    expect(snap.sendingChainKey).toBe(null);
    expect(snap.receivingChainKey).toBe(null);

    const restored = Session.deserialize(JSON.parse(JSON.stringify(snap)));
    // Restored Bob still cannot encrypt before receiving
    expect(() => restored.encrypt(Buffer.from('x'))).toThrow();
  });
});
