/**
 * Memory stores tests.
 *
 * These tests also serve as the "interface contract" — every other impl
 * (file, custom SQLite, etc.) should pass an equivalent suite.
 */

import { describe, it, expect, beforeEach } from 'vitest';

import {
  IdentityKeyPair,
  OneTimePreKey,
  SignedPreKey,
  ProtocolAddress,
  Session,
  X3DH,
  PreKeyBundle,
  MemoryIdentityStore,
  MemoryPreKeyStore,
  MemorySignedPreKeyStore,
  MemorySessionStore,
} from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// MemoryIdentityStore
// ═══════════════════════════════════════════════════════════════════════════

describe('MemoryIdentityStore', () => {
  let store: MemoryIdentityStore;
  beforeEach(() => {
    store = new MemoryIdentityStore();
  });

  describe('own identity', () => {
    it('returns null before save', async () => {
      expect(await store.getIdentityKeyPair()).toBeNull();
      expect(await store.getRegistrationId()).toBeNull();
    });

    it('saves and loads identity keypair', async () => {
      const kp = IdentityKeyPair.generate();
      await store.saveIdentityKeyPair(kp);
      const loaded = await store.getIdentityKeyPair();
      expect(loaded).not.toBeNull();
      expect(loaded!.publicKey.equals(kp.publicKey)).toBe(true);
    });

    it('saves and loads registration id', async () => {
      await store.saveRegistrationId(12345);
      expect(await store.getRegistrationId()).toBe(12345);
    });

    it('rejects negative registration id', async () => {
      await expect(store.saveRegistrationId(-1)).rejects.toThrow(RangeError);
    });

    it('rejects non-integer registration id', async () => {
      await expect(store.saveRegistrationId(1.5)).rejects.toThrow(RangeError);
    });

    it('overwrites on second save', async () => {
      const kp1 = IdentityKeyPair.generate();
      const kp2 = IdentityKeyPair.generate();
      await store.saveIdentityKeyPair(kp1);
      await store.saveIdentityKeyPair(kp2);
      const loaded = await store.getIdentityKeyPair();
      expect(loaded!.publicKey.equals(kp2.publicKey)).toBe(true);
    });
  });

  describe('trusted identities', () => {
    it('TOFU: first contact returns true', async () => {
      const bob = IdentityKeyPair.generate();
      const addr = new ProtocolAddress('bob', 1);
      expect(await store.isTrustedIdentity(addr, bob.toPublic())).toBe(true);
    });

    it('matching key returns true', async () => {
      const bob = IdentityKeyPair.generate();
      const addr = new ProtocolAddress('bob', 1);
      await store.saveTrustedIdentity(addr, bob.toPublic());
      expect(await store.isTrustedIdentity(addr, bob.toPublic())).toBe(true);
    });

    it('changed key returns false', async () => {
      const bob1 = IdentityKeyPair.generate();
      const bob2 = IdentityKeyPair.generate();
      const addr = new ProtocolAddress('bob', 1);
      await store.saveTrustedIdentity(addr, bob1.toPublic());
      expect(await store.isTrustedIdentity(addr, bob2.toPublic())).toBe(false);
    });

    it('different address: independent', async () => {
      const bob = IdentityKeyPair.generate();
      const carol = IdentityKeyPair.generate();
      const bobAddr = new ProtocolAddress('bob', 1);
      const carolAddr = new ProtocolAddress('carol', 1);
      await store.saveTrustedIdentity(bobAddr, bob.toPublic());
      expect(await store.isTrustedIdentity(carolAddr, carol.toPublic())).toBe(true);
    });

    it('multi-device: same userId different deviceId tracked separately', async () => {
      const bobPhone = IdentityKeyPair.generate();
      const bobLaptop = IdentityKeyPair.generate();
      const phoneAddr = new ProtocolAddress('bob', 1);
      const laptopAddr = new ProtocolAddress('bob', 2);
      await store.saveTrustedIdentity(phoneAddr, bobPhone.toPublic());
      await store.saveTrustedIdentity(laptopAddr, bobLaptop.toPublic());
      expect(await store.isTrustedIdentity(phoneAddr, bobPhone.toPublic())).toBe(true);
      expect(await store.isTrustedIdentity(laptopAddr, bobLaptop.toPublic())).toBe(true);
      expect(await store.isTrustedIdentity(phoneAddr, bobLaptop.toPublic())).toBe(false);
    });
  });

  describe('utility', () => {
    it('clear wipes everything', async () => {
      const kp = IdentityKeyPair.generate();
      await store.saveIdentityKeyPair(kp);
      await store.saveRegistrationId(42);
      await store.saveTrustedIdentity(new ProtocolAddress('x', 0), kp.toPublic());
      store.clear();
      expect(await store.getIdentityKeyPair()).toBeNull();
      expect(await store.getRegistrationId()).toBeNull();
      expect(store.trustedIdentitiesCount()).toBe(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// MemoryPreKeyStore
// ═══════════════════════════════════════════════════════════════════════════

describe('MemoryPreKeyStore', () => {
  let store: MemoryPreKeyStore;
  beforeEach(() => {
    store = new MemoryPreKeyStore();
  });

  it('returns null for unknown id', async () => {
    expect(await store.getPreKey(999)).toBeNull();
  });

  it('saves and loads a prekey', async () => {
    const pk = OneTimePreKey.generate(1);
    await store.savePreKey(1, pk);
    const loaded = await store.getPreKey(1);
    expect(loaded).not.toBeNull();
    expect(loaded!.id).toBe(1);
  });

  it('containsPreKey works', async () => {
    const pk = OneTimePreKey.generate(7);
    await store.savePreKey(7, pk);
    expect(await store.containsPreKey(7)).toBe(true);
    expect(await store.containsPreKey(8)).toBe(false);
  });

  it('removePreKey removes', async () => {
    const pk = OneTimePreKey.generate(1);
    await store.savePreKey(1, pk);
    await store.removePreKey(1);
    expect(await store.getPreKey(1)).toBeNull();
  });

  it('remove non-existent: no-op', async () => {
    await expect(store.removePreKey(999)).resolves.toBeUndefined();
  });

  it('loadAllPreKeyIds returns sorted', async () => {
    await store.savePreKey(5, OneTimePreKey.generate(5));
    await store.savePreKey(1, OneTimePreKey.generate(1));
    await store.savePreKey(3, OneTimePreKey.generate(3));
    expect(await store.loadAllPreKeyIds()).toEqual([1, 3, 5]);
  });

  it('size and clear', async () => {
    await store.savePreKey(1, OneTimePreKey.generate(1));
    await store.savePreKey(2, OneTimePreKey.generate(2));
    expect(store.size()).toBe(2);
    store.clear();
    expect(store.size()).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// MemorySignedPreKeyStore
// ═══════════════════════════════════════════════════════════════════════════

describe('MemorySignedPreKeyStore', () => {
  let store: MemorySignedPreKeyStore;
  let identity: IdentityKeyPair;
  beforeEach(() => {
    store = new MemorySignedPreKeyStore();
    identity = IdentityKeyPair.generate();
  });

  it('returns null for unknown id and no active', async () => {
    expect(await store.getSignedPreKey(0)).toBeNull();
    expect(await store.getActiveSignedPreKey()).toBeNull();
  });

  it('saves + loads signed prekey', async () => {
    const spk = SignedPreKey.generate(identity, 1);
    await store.saveSignedPreKey(1, spk);
    const loaded = await store.getSignedPreKey(1);
    expect(loaded).not.toBeNull();
    expect(loaded!.id).toBe(1);
  });

  it('rotateActive sets the active pointer', async () => {
    const spk = SignedPreKey.generate(identity, 1);
    await store.rotateActiveSignedPreKey(1, spk);
    const active = await store.getActiveSignedPreKey();
    expect(active).not.toBeNull();
    expect(active!.id).toBe(1);
  });

  it('rotation keeps old keys around', async () => {
    const spk1 = SignedPreKey.generate(identity, 1);
    const spk2 = SignedPreKey.generate(identity, 2);
    await store.rotateActiveSignedPreKey(1, spk1);
    await store.rotateActiveSignedPreKey(2, spk2);
    expect((await store.getActiveSignedPreKey())!.id).toBe(2);
    expect(await store.getSignedPreKey(1)).not.toBeNull(); // old still there
  });

  it('loadAllSignedPreKeyIds returns sorted', async () => {
    const spk1 = SignedPreKey.generate(identity, 1);
    const spk3 = SignedPreKey.generate(identity, 3);
    const spk2 = SignedPreKey.generate(identity, 2);
    await store.saveSignedPreKey(1, spk1);
    await store.saveSignedPreKey(3, spk3);
    await store.saveSignedPreKey(2, spk2);
    expect(await store.loadAllSignedPreKeyIds()).toEqual([1, 2, 3]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// MemorySessionStore
// ═══════════════════════════════════════════════════════════════════════════

describe('MemorySessionStore', () => {
  let store: MemorySessionStore;
  beforeEach(() => {
    store = new MemorySessionStore();
  });

  function makeSession(): Session {
    const bob = IdentityKeyPair.generate();
    const bobSpk = SignedPreKey.generate(bob, 1);
    const bobBundle = PreKeyBundle.build({
      registrationId: 1,
      identityKey: bob.toPublic(),
      signedPreKey: bobSpk.toPublic(),
    });
    const alice = IdentityKeyPair.generate();
    const h = X3DH.initiate(alice, bobBundle, { myRegistrationId: 2 });
    return Session.initiateFromX3DH({
      sharedSecret: h.sharedSecret,
      theirIdentityKey: bob.toPublic(),
      theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
    });
  }

  it('returns null for unknown address', async () => {
    expect(await store.loadSession(new ProtocolAddress('bob', 1))).toBeNull();
  });

  it('containsSession is false initially', async () => {
    expect(await store.containsSession(new ProtocolAddress('bob', 1))).toBe(false);
  });

  it('saves + loads a session', async () => {
    const addr = new ProtocolAddress('bob', 1);
    const session = makeSession();
    await store.saveSession(addr, session);

    const loaded = await store.loadSession(addr);
    expect(loaded).not.toBeNull();
    expect(await store.containsSession(addr)).toBe(true);
  });

  it('deleteSession removes', async () => {
    const addr = new ProtocolAddress('bob', 1);
    await store.saveSession(addr, makeSession());
    await store.deleteSession(addr);
    expect(await store.loadSession(addr)).toBeNull();
  });

  it('delete non-existent: no-op', async () => {
    await expect(
      store.deleteSession(new ProtocolAddress('ghost', 1)),
    ).resolves.toBeUndefined();
  });

  it('different addresses are independent', async () => {
    const a1 = new ProtocolAddress('alice', 1);
    const a2 = new ProtocolAddress('alice', 2);
    await store.saveSession(a1, makeSession());
    expect(await store.containsSession(a1)).toBe(true);
    expect(await store.containsSession(a2)).toBe(false);
  });

  it('loadAllSessions returns every record', async () => {
    const addr1 = new ProtocolAddress('alice', 1);
    const addr2 = new ProtocolAddress('bob', 1);
    await store.saveSession(addr1, makeSession());
    await store.saveSession(addr2, makeSession());
    const all = await store.loadAllSessions();
    expect(all.length).toBe(2);
    expect(all.map((e) => e.address.toString()).sort()).toEqual([
      'alice.1',
      'bob.1',
    ]);
  });

  it('saved session is functional after load', async () => {
    const addr = new ProtocolAddress('bob', 1);
    const original = makeSession();
    const packet = original.encrypt(Buffer.from('hello'));
    expect(original.sendingCounterValue()).toBe(1);

    await store.saveSession(addr, original);
    const loaded = await store.loadSession(addr);
    expect(loaded!.sendingCounterValue()).toBe(1);

    // continuar enviando con la session cargada
    const packet2 = loaded!.encrypt(Buffer.from('hello 2'));
    expect(packet2.header).not.toBe(packet.header); // counter avanzó
  });
});
