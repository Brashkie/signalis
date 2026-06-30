/**
 * SessionBuilder tests — high-level encrypt/decrypt orchestration.
 */

import { describe, it, expect } from 'vitest';

import {
  IdentityKeyPair,
  OneTimePreKey,
  SignedPreKey,
  PreKeyBundle,
  ProtocolAddress,
  StoreBundle,
  SessionBuilder,
  SessionError,
  ValidationError,
} from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// Helpers — set up Alice and Bob with their stores + identities
// ═══════════════════════════════════════════════════════════════════════════

async function makeUser(opts: { userId: string; registrationId: number }) {
  const stores = StoreBundle.memory();
  const identity = IdentityKeyPair.generate();
  const signedPreKey = SignedPreKey.generate(identity, 1);
  const oneTimePreKey = OneTimePreKey.generate(100);

  await stores.identity.saveIdentityKeyPair(identity);
  await stores.identity.saveRegistrationId(opts.registrationId);
  await stores.signedPreKeys.rotateActiveSignedPreKey(1, signedPreKey);
  await stores.preKeys.savePreKey(100, oneTimePreKey);

  const builder = new SessionBuilder(stores);

  const bundle = PreKeyBundle.build({
    registrationId: opts.registrationId,
    identityKey: identity.toPublic(),
    signedPreKey: signedPreKey.toPublic(),
    oneTimePreKey: oneTimePreKey.toPublic(),
  });

  return { stores, identity, builder, bundle };
}

// ═══════════════════════════════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════════════════════════════

describe('SessionBuilder — validation', () => {
  it('rejects missing stores', () => {
    expect(() => new SessionBuilder(undefined as never)).toThrow(ValidationError);
  });

  it('encrypt rejects non-Buffer plaintext', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    await expect(
      alice.builder.encrypt(
        new ProtocolAddress('bob', 1),
        'string' as never,
        bob.bundle,
      ),
    ).rejects.toThrow(ValidationError);
  });

  it('decrypt rejects null message', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    await expect(
      alice.builder.decrypt(new ProtocolAddress('bob', 1), null as never),
    ).rejects.toThrow(ValidationError);
  });

  it('decrypt rejects bad type', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    await expect(
      alice.builder.decrypt(
        new ProtocolAddress('bob', 1),
        { type: 'invalid' } as never,
      ),
    ).rejects.toThrow(ValidationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// First-time encrypt (X3DH initiated)
// ═══════════════════════════════════════════════════════════════════════════

describe('SessionBuilder — first-time encrypt', () => {
  it('returns a prekey message on first send', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });

    const msg = await alice.builder.encrypt(
      new ProtocolAddress('bob', 1),
      Buffer.from('Hola Bob'),
      bob.bundle,
    );
    expect(msg.type).toBe('prekey');
    if (msg.type === 'prekey') {
      // initialMessage is an InitialMessagePayload object (not a hex string)
      expect(typeof msg.initialMessage).toBe('object');
      expect(typeof msg.initialMessage.identityKey).toBe('string');
      expect(msg.initialMessage.identityKey.length).toBeGreaterThan(0);
      expect(typeof msg.initialMessage.ephemeralKey).toBe('string');
      expect(typeof msg.initialMessage.signedPreKeyId).toBe('number');
      expect(msg.packet.ciphertext.length).toBeGreaterThan(0);
    }
  });

  it('rejects encrypt without bundle when no session exists', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    await expect(
      alice.builder.encrypt(new ProtocolAddress('bob', 1), Buffer.from('x')),
    ).rejects.toThrow(SessionError);
  });

  it('rejects encrypt when own identity not registered', async () => {
    const stores = StoreBundle.memory();
    const builder = new SessionBuilder(stores);
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    await expect(
      builder.encrypt(new ProtocolAddress('bob', 1), Buffer.from('x'), bob.bundle),
    ).rejects.toThrow(/identity not registered/);
  });

  it('rejects encrypt when own registrationId not set', async () => {
    const stores = StoreBundle.memory();
    const id = IdentityKeyPair.generate();
    await stores.identity.saveIdentityKeyPair(id);
    // forgot saveRegistrationId
    const builder = new SessionBuilder(stores);
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    await expect(
      builder.encrypt(new ProtocolAddress('bob', 1), Buffer.from('x'), bob.bundle),
    ).rejects.toThrow(/registrationId not set/);
  });

  it('stores trusted identity for the recipient on first contact', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    const bobAddr = new ProtocolAddress('bob', 1);
    await alice.builder.encrypt(bobAddr, Buffer.from('hi'), bob.bundle);

    // Same key still trusted
    expect(
      await alice.stores.identity.isTrustedIdentity(bobAddr, bob.identity.toPublic()),
    ).toBe(true);
  });

  it('detects changed bundle identity (MITM)', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    const bobAddr = new ProtocolAddress('bob', 1);

    // First contact: ok
    await alice.builder.encrypt(bobAddr, Buffer.from('first'), bob.bundle);

    // Attacker bundle with the same address
    const attacker = await makeUser({ userId: 'attacker', registrationId: 999 });
    const attackerBundle = PreKeyBundle.build({
      registrationId: 999,
      identityKey: attacker.identity.toPublic(),
      signedPreKey: (await attacker.stores.signedPreKeys.getActiveSignedPreKey())!.toPublic(),
    });
    // Delete Alice's session to force re-X3DH
    await alice.stores.sessions.deleteSession(bobAddr);

    await expect(
      alice.builder.encrypt(bobAddr, Buffer.from('second'), attackerBundle),
    ).rejects.toThrow(/identity for .* has changed/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Bidirectional E2E
// ═══════════════════════════════════════════════════════════════════════════

describe('SessionBuilder — bidirectional E2E', () => {
  it('Alice → Bob → Alice (full round trip)', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    const bobAddr = new ProtocolAddress('bob', 1);
    const aliceAddr = new ProtocolAddress('alice', 1);

    // Alice → Bob
    const m1 = await alice.builder.encrypt(bobAddr, Buffer.from('Hola Bob'), bob.bundle);
    const dec1 = await bob.builder.decrypt(aliceAddr, m1);
    expect(dec1.toString()).toBe('Hola Bob');

    // Bob → Alice (DH ratchet rotation)
    const m2 = await bob.builder.encrypt(aliceAddr, Buffer.from('Hola Alice'));
    const dec2 = await alice.builder.decrypt(bobAddr, m2);
    expect(dec2.toString()).toBe('Hola Alice');

    // Alice → Bob again
    const m3 = await alice.builder.encrypt(bobAddr, Buffer.from('how are you'));
    const dec3 = await bob.builder.decrypt(aliceAddr, m3);
    expect(dec3.toString()).toBe('how are you');
  });

  it('subsequent messages are whisper type', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    const bobAddr = new ProtocolAddress('bob', 1);

    // First message: prekey type
    const m1 = await alice.builder.encrypt(bobAddr, Buffer.from('1'), bob.bundle);
    expect(m1.type).toBe('prekey');

    // Bob receives, creates session on his side
    await bob.builder.decrypt(new ProtocolAddress('alice', 1), m1);

    // Second message: no bundle needed
    const m2 = await alice.builder.encrypt(bobAddr, Buffer.from('2'));
    expect(m2.type).toBe('whisper');
  });

  it('20-message conversation', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    const bobAddr = new ProtocolAddress('bob', 1);
    const aliceAddr = new ProtocolAddress('alice', 1);

    // First message with bundle
    const first = await alice.builder.encrypt(
      bobAddr,
      Buffer.from('msg 0'),
      bob.bundle,
    );
    expect((await bob.builder.decrypt(aliceAddr, first)).toString()).toBe('msg 0');

    // 10 ping-pong rounds
    for (let i = 1; i <= 10; i++) {
      const aMsg = await bob.builder.encrypt(aliceAddr, Buffer.from(`bob-${i}`));
      expect((await alice.builder.decrypt(bobAddr, aMsg)).toString()).toBe(
        `bob-${i}`,
      );

      const bMsg = await alice.builder.encrypt(bobAddr, Buffer.from(`alice-${i}`));
      expect((await bob.builder.decrypt(aliceAddr, bMsg)).toString()).toBe(
        `alice-${i}`,
      );
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// One-time prekey lifecycle
// ═══════════════════════════════════════════════════════════════════════════

describe('SessionBuilder — one-time prekey consumed', () => {
  it("Bob's one-time prekey is deleted after first decrypt", async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });

    expect(await bob.stores.preKeys.containsPreKey(100)).toBe(true);

    const m = await alice.builder.encrypt(
      new ProtocolAddress('bob', 1),
      Buffer.from('hi'),
      bob.bundle,
    );
    await bob.builder.decrypt(new ProtocolAddress('alice', 1), m);

    // Bob's prekey 100 was consumed → gone
    expect(await bob.stores.preKeys.containsPreKey(100)).toBe(false);
  });

  it('replay of prekey message rejected (prekey already used)', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });

    const m = await alice.builder.encrypt(
      new ProtocolAddress('bob', 1),
      Buffer.from('hi'),
      bob.bundle,
    );
    await bob.builder.decrypt(new ProtocolAddress('alice', 1), m);

    // Replay the EXACT same prekey message → should fail
    await expect(
      bob.builder.decrypt(new ProtocolAddress('alice', 1), m),
    ).rejects.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Receive side error paths
// ═══════════════════════════════════════════════════════════════════════════

describe('SessionBuilder — decrypt errors', () => {
  it('whisper message without existing session → error', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    const bobAddr = new ProtocolAddress('bob', 1);

    // Alice sends Bob a message; Bob sets up the session
    const first = await alice.builder.encrypt(
      bobAddr,
      Buffer.from('first'),
      bob.bundle,
    );
    await bob.builder.decrypt(new ProtocolAddress('alice', 1), first);

    // Bob's session for Alice exists; Alice never received Bob's session reset
    // Simulate: Alice deletes her session (e.g., reinstall)
    await alice.stores.sessions.deleteSession(bobAddr);

    // Bob sends a whisper to Alice — Alice no longer has a session
    const bobReply = await bob.builder.encrypt(
      new ProtocolAddress('alice', 1),
      Buffer.from('bob says hi'),
    );

    await expect(alice.builder.decrypt(bobAddr, bobReply)).rejects.toThrow(/no session/);
  });

  it('resetSession deletes the session', async () => {
    const alice = await makeUser({ userId: 'alice', registrationId: 1 });
    const bob = await makeUser({ userId: 'bob', registrationId: 2 });
    const bobAddr = new ProtocolAddress('bob', 1);

    await alice.builder.encrypt(bobAddr, Buffer.from('hi'), bob.bundle);
    expect(await alice.stores.sessions.containsSession(bobAddr)).toBe(true);

    await alice.builder.resetSession(bobAddr);
    expect(await alice.stores.sessions.containsSession(bobAddr)).toBe(false);
  });
});
