/**
 * File stores tests — atomic writes, persistence, recovery.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

import {
  IdentityKeyPair,
  OneTimePreKey,
  SignedPreKey,
  PreKeyBundle,
  X3DH,
  Session,
  ProtocolAddress,
  FileIdentityStore,
  FilePreKeyStore,
  FileSignedPreKeyStore,
  FileSessionStore,
} from '../src';

// ═══════════════════════════════════════════════════════════════════════════
// Test directory helpers
// ═══════════════════════════════════════════════════════════════════════════

async function freshTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), 'signalis-file-store-'));
}

async function cleanup(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

// ═══════════════════════════════════════════════════════════════════════════
// FileIdentityStore
// ═══════════════════════════════════════════════════════════════════════════

describe('FileIdentityStore', () => {
  let dir: string;
  let store: FileIdentityStore;

  beforeEach(async () => {
    dir = await freshTempDir();
    store = new FileIdentityStore(dir);
  });
  afterEach(async () => {
    await cleanup(dir);
  });

  it('rejects empty rootDir', () => {
    expect(() => new FileIdentityStore('')).toThrow(TypeError);
  });

  it('rejects non-string rootDir', () => {
    expect(() => new FileIdentityStore(42 as never)).toThrow(TypeError);
  });

  it('returns null when nothing saved yet', async () => {
    expect(await store.getIdentityKeyPair()).toBeNull();
    expect(await store.getRegistrationId()).toBeNull();
  });

  it('persists and reloads identity keypair', async () => {
    const kp = IdentityKeyPair.generate();
    await store.saveIdentityKeyPair(kp);

    // Fresh store reading the same dir → must see it
    const store2 = new FileIdentityStore(dir);
    const loaded = await store2.getIdentityKeyPair();
    expect(loaded).not.toBeNull();
    expect(loaded!.publicKey.equals(kp.publicKey)).toBe(true);
    expect(loaded!.privateKey.equals(kp.privateKey)).toBe(true);
  });

  it('persists and reloads registration id', async () => {
    await store.saveRegistrationId(12345);
    const store2 = new FileIdentityStore(dir);
    expect(await store2.getRegistrationId()).toBe(12345);
  });

  it('TOFU on first contact', async () => {
    const bob = IdentityKeyPair.generate();
    const addr = new ProtocolAddress('bob', 1);
    expect(await store.isTrustedIdentity(addr, bob.toPublic())).toBe(true);
  });

  it('detects changed identity key', async () => {
    const bob1 = IdentityKeyPair.generate();
    const bob2 = IdentityKeyPair.generate();
    const addr = new ProtocolAddress('bob', 1);
    await store.saveTrustedIdentity(addr, bob1.toPublic());
    expect(await store.isTrustedIdentity(addr, bob2.toPublic())).toBe(false);
  });

  it('forgetTrustedIdentity clears it', async () => {
    const bob = IdentityKeyPair.generate();
    const addr = new ProtocolAddress('bob', 1);
    await store.saveTrustedIdentity(addr, bob.toPublic());
    await store.forgetTrustedIdentity(addr);
    // After forget, ANY key is trusted (TOFU again)
    const someoneElse = IdentityKeyPair.generate();
    expect(await store.isTrustedIdentity(addr, someoneElse.toPublic())).toBe(true);
  });

  it('rejects negative registration id', async () => {
    await expect(store.saveRegistrationId(-1)).rejects.toThrow(RangeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// FilePreKeyStore
// ═══════════════════════════════════════════════════════════════════════════

describe('FilePreKeyStore', () => {
  let dir: string;
  let store: FilePreKeyStore;

  beforeEach(async () => {
    dir = await freshTempDir();
    store = new FilePreKeyStore(dir);
  });
  afterEach(async () => {
    await cleanup(dir);
  });

  it('persists prekey', async () => {
    const pk = OneTimePreKey.generate(7);
    await store.savePreKey(7, pk);
    const store2 = new FilePreKeyStore(dir);
    const loaded = await store2.getPreKey(7);
    expect(loaded).not.toBeNull();
    expect(loaded!.id).toBe(7);
  });

  it('returns null for missing', async () => {
    expect(await store.getPreKey(999)).toBeNull();
  });

  it('contains works', async () => {
    await store.savePreKey(1, OneTimePreKey.generate(1));
    expect(await store.containsPreKey(1)).toBe(true);
    expect(await store.containsPreKey(2)).toBe(false);
  });

  it('removePreKey deletes file', async () => {
    await store.savePreKey(1, OneTimePreKey.generate(1));
    await store.removePreKey(1);
    expect(await store.getPreKey(1)).toBeNull();
  });

  it('rejects negative id', async () => {
    await expect(
      store.savePreKey(-1, OneTimePreKey.generate(1)),
    ).rejects.toThrow(RangeError);
  });

  it('loadAllPreKeyIds returns sorted, ignores non-numeric files', async () => {
    await store.savePreKey(3, OneTimePreKey.generate(3));
    await store.savePreKey(1, OneTimePreKey.generate(1));
    // Inject a junk file
    await fs.writeFile(path.join(dir, 'prekeys', 'NOT_A_NUMBER.json'), '{}');
    const ids = await store.loadAllPreKeyIds();
    expect(ids).toEqual([1, 3]);
  });

  it('loadAllPreKeyIds: empty when no dir', async () => {
    const emptyDir = await freshTempDir();
    const s = new FilePreKeyStore(emptyDir);
    expect(await s.loadAllPreKeyIds()).toEqual([]);
    await cleanup(emptyDir);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// FileSignedPreKeyStore
// ═══════════════════════════════════════════════════════════════════════════

describe('FileSignedPreKeyStore', () => {
  let dir: string;
  let store: FileSignedPreKeyStore;
  let identity: IdentityKeyPair;

  beforeEach(async () => {
    dir = await freshTempDir();
    store = new FileSignedPreKeyStore(dir);
    identity = IdentityKeyPair.generate();
  });
  afterEach(async () => {
    await cleanup(dir);
  });

  it('persists + rotates active', async () => {
    const spk1 = SignedPreKey.generate(identity, 1);
    const spk2 = SignedPreKey.generate(identity, 2);
    await store.rotateActiveSignedPreKey(1, spk1);
    await store.rotateActiveSignedPreKey(2, spk2);

    const store2 = new FileSignedPreKeyStore(dir);
    const active = await store2.getActiveSignedPreKey();
    expect(active!.id).toBe(2);
    // Old one still there
    expect(await store2.getSignedPreKey(1)).not.toBeNull();
  });

  it('loadAllSignedPreKeyIds excludes active.json', async () => {
    await store.rotateActiveSignedPreKey(1, SignedPreKey.generate(identity, 1));
    await store.saveSignedPreKey(2, SignedPreKey.generate(identity, 2));
    expect(await store.loadAllSignedPreKeyIds()).toEqual([1, 2]);
  });

  it('rejects negative id', async () => {
    await expect(
      store.saveSignedPreKey(-1, SignedPreKey.generate(identity, 1)),
    ).rejects.toThrow(RangeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// FileSessionStore
// ═══════════════════════════════════════════════════════════════════════════

describe('FileSessionStore', () => {
  let dir: string;
  let store: FileSessionStore;

  beforeEach(async () => {
    dir = await freshTempDir();
    store = new FileSessionStore(dir);
  });
  afterEach(async () => {
    await cleanup(dir);
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

  it('persists session', async () => {
    const addr = new ProtocolAddress('bob', 1);
    const s = makeSession();
    s.encrypt(Buffer.from('msg'));
    await store.saveSession(addr, s);

    const store2 = new FileSessionStore(dir);
    const loaded = await store2.loadSession(addr);
    expect(loaded).not.toBeNull();
    expect(loaded!.sendingCounterValue()).toBe(1);
  });

  it('deleteSession removes the file', async () => {
    const addr = new ProtocolAddress('bob', 1);
    await store.saveSession(addr, makeSession());
    await store.deleteSession(addr);
    expect(await store.containsSession(addr)).toBe(false);
  });

  it('loadAllSessions returns all', async () => {
    await store.saveSession(new ProtocolAddress('a', 1), makeSession());
    await store.saveSession(new ProtocolAddress('b', 1), makeSession());
    const all = await store.loadAllSessions();
    expect(all.length).toBe(2);
  });

  it('loadAllSessions skips malformed filenames', async () => {
    await store.saveSession(new ProtocolAddress('good', 1), makeSession());
    // Inject malformed file
    await fs.writeFile(path.join(dir, 'sessions', 'no-deviceid.json'), '{}');
    const all = await store.loadAllSessions();
    expect(all.length).toBe(1);
    expect(all[0]!.address.userId).toBe('good');
  });

  it('rejects empty rootDir', () => {
    expect(() => new FileSessionStore('')).toThrow(TypeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Atomic write properties
// ═══════════════════════════════════════════════════════════════════════════

describe('Atomic write properties', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await freshTempDir();
  });
  afterEach(async () => {
    await cleanup(dir);
  });

  it('overwriting many times leaves no .tmp files behind', async () => {
    const store = new FilePreKeyStore(dir);
    for (let i = 0; i < 20; i++) {
      await store.savePreKey(1, OneTimePreKey.generate(1));
    }
    const entries = await fs.readdir(path.join(dir, 'prekeys'));
    const tmpFiles = entries.filter((n) => n.includes('.tmp.'));
    expect(tmpFiles).toEqual([]);
  });

  it('concurrent writes converge to last-write-wins (no corruption)', async () => {
    const store = new FilePreKeyStore(dir);
    // Issue 10 concurrent saves; last one to land in `rename` wins
    const promises = [];
    for (let i = 0; i < 10; i++) {
      promises.push(store.savePreKey(1, OneTimePreKey.generate(1)));
    }
    await Promise.all(promises);

    // Should be readable (no corruption); content valid
    const loaded = await store.getPreKey(1);
    expect(loaded).not.toBeNull();
    expect(loaded!.id).toBe(1);
  });
});
