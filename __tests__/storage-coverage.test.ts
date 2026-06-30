/**
 * Storage coverage closer — tests for the remaining uncovered lines:
 *   - Diagnostics methods (size, clear) on memory stores
 *   - Constructor validation on file stores
 *   - Decrypt error paths in SessionBuilder
 *   - Atomic-write error paths (retry exhausted, cleanup on failure, etc.)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

import {
  IdentityKeyPair,
  OneTimePreKey,
  SignedPreKey,
  PreKeyBundle,
  ProtocolAddress,
  StoreBundle,
  SessionBuilder,
  MemorySessionStore,
  MemorySignedPreKeyStore,
  FilePreKeyStore,
  FileSignedPreKeyStore,
  FileIdentityStore,
  SessionError,
} from '../src';
import {
  atomicWriteFile,
  readFileOrNull,
  unlinkIfExists,
  listFiles,
} from '../src/storage/file/atomic-write';

// ═══════════════════════════════════════════════════════════════════════════
// Memory stores — diagnostics
// ═══════════════════════════════════════════════════════════════════════════

describe('MemorySessionStore — diagnostics', () => {
  it('size() returns current session count', async () => {
    const store = new MemorySessionStore();
    expect(store.size()).toBe(0);

    // Add 2 sessions by directly mutating internal state via saveSession
    const bob = IdentityKeyPair.generate();
    const bobSpk = SignedPreKey.generate(bob, 1);
    const bobBundle = PreKeyBundle.build({
      registrationId: 1,
      identityKey: bob.toPublic(),
      signedPreKey: bobSpk.toPublic(),
    });
    const alice = IdentityKeyPair.generate();
    const { X3DH, Session } = await import('../src');
    const h = X3DH.initiate(alice, bobBundle, { myRegistrationId: 2 });
    const session = Session.initiateFromX3DH({
      sharedSecret: h.sharedSecret,
      theirIdentityKey: bob.toPublic(),
      theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
    });

    await store.saveSession(new ProtocolAddress('a', 1), session);
    expect(store.size()).toBe(1);
    await store.saveSession(new ProtocolAddress('b', 1), session);
    expect(store.size()).toBe(2);
  });

  it('clear() wipes all sessions', async () => {
    const store = new MemorySessionStore();
    const bob = IdentityKeyPair.generate();
    const bobSpk = SignedPreKey.generate(bob, 1);
    const bobBundle = PreKeyBundle.build({
      registrationId: 1,
      identityKey: bob.toPublic(),
      signedPreKey: bobSpk.toPublic(),
    });
    const alice = IdentityKeyPair.generate();
    const { X3DH, Session } = await import('../src');
    const h = X3DH.initiate(alice, bobBundle, { myRegistrationId: 2 });
    const session = Session.initiateFromX3DH({
      sharedSecret: h.sharedSecret,
      theirIdentityKey: bob.toPublic(),
      theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
    });

    await store.saveSession(new ProtocolAddress('a', 1), session);
    expect(store.size()).toBe(1);
    store.clear();
    expect(store.size()).toBe(0);
  });
});

describe('MemorySignedPreKeyStore — diagnostics', () => {
  it('size() returns current count', async () => {
    const store = new MemorySignedPreKeyStore();
    const identity = IdentityKeyPair.generate();
    expect(store.size()).toBe(0);
    await store.saveSignedPreKey(1, SignedPreKey.generate(identity, 1));
    expect(store.size()).toBe(1);
    await store.saveSignedPreKey(2, SignedPreKey.generate(identity, 2));
    expect(store.size()).toBe(2);
  });

  it('clear() wipes keys and resets active pointer', async () => {
    const store = new MemorySignedPreKeyStore();
    const identity = IdentityKeyPair.generate();
    await store.rotateActiveSignedPreKey(1, SignedPreKey.generate(identity, 1));
    expect(store.size()).toBe(1);
    expect(await store.getActiveSignedPreKey()).not.toBeNull();

    store.clear();
    expect(store.size()).toBe(0);
    expect(await store.getActiveSignedPreKey()).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// File stores — rootDir validation
// ═══════════════════════════════════════════════════════════════════════════

describe('File stores — rootDir validation', () => {
  it('FilePreKeyStore rejects empty rootDir', () => {
    expect(() => new FilePreKeyStore('')).toThrow(TypeError);
  });

  it('FilePreKeyStore rejects non-string rootDir', () => {
    expect(() => new FilePreKeyStore(42 as never)).toThrow(TypeError);
  });

  it('FileSignedPreKeyStore rejects empty rootDir', () => {
    expect(() => new FileSignedPreKeyStore('')).toThrow(TypeError);
  });

  it('FileSignedPreKeyStore rejects non-string rootDir', () => {
    expect(() => new FileSignedPreKeyStore(42 as never)).toThrow(TypeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SessionBuilder — decrypt error paths
// ═══════════════════════════════════════════════════════════════════════════

describe('SessionBuilder — decrypt error paths (coverage)', () => {
  async function makeUser(userId: string, registrationId: number) {
    const stores = StoreBundle.memory();
    const identity = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(identity, 1);
    const opk = OneTimePreKey.generate(100);

    await stores.identity.saveIdentityKeyPair(identity);
    await stores.identity.saveRegistrationId(registrationId);
    await stores.signedPreKeys.rotateActiveSignedPreKey(1, spk);
    await stores.preKeys.savePreKey(100, opk);

    const bundle = PreKeyBundle.build({
      registrationId,
      identityKey: identity.toPublic(),
      signedPreKey: spk.toPublic(),
      oneTimePreKey: opk.toPublic(),
    });

    return { stores, identity, builder: new SessionBuilder(stores), bundle };
  }

  it('decrypt rejects prekey msg when own identity not registered', async () => {
    const alice = await makeUser('alice', 1);
    const bob = await makeUser('bob', 2);
    const m = await alice.builder.encrypt(
      new ProtocolAddress('bob', 1),
      Buffer.from('hi'),
      bob.bundle,
    );

    // Wipe Bob's identity so decrypt fails
    const emptyStores = StoreBundle.memory();
    const emptyBuilder = new SessionBuilder(emptyStores);
    await expect(
      emptyBuilder.decrypt(new ProtocolAddress('alice', 1), m),
    ).rejects.toThrow(/identity not registered/);
  });

  it('decrypt rejects when signedPreKey id not found', async () => {
    const alice = await makeUser('alice', 1);
    const bob = await makeUser('bob', 2);
    const m = await alice.builder.encrypt(
      new ProtocolAddress('bob', 1),
      Buffer.from('hi'),
      bob.bundle,
    );

    // Bob rotated his signed prekey — id 1 no longer available
    const bobIdentity = (await bob.stores.identity.getIdentityKeyPair())!;
    const newSpk = SignedPreKey.generate(bobIdentity, 999);
    await bob.stores.signedPreKeys.rotateActiveSignedPreKey(999, newSpk);
    // Manually delete signed prekey id 1 to simulate forgetting old SPKs
    // (No deleteSignedPreKey method — work around by replacing the store)
    const newSpkStore = new MemorySignedPreKeyStore();
    await newSpkStore.rotateActiveSignedPreKey(999, newSpk);
    const builder2 = new SessionBuilder({
      ...bob.stores,
      signedPreKeys: newSpkStore,
    } as never);

    await expect(
      builder2.decrypt(new ProtocolAddress('alice', 1), m),
    ).rejects.toThrow(/signed prekey id=\d+ not found/);
  });

  it('decrypt rejects when one-time prekey was already consumed (replay)', async () => {
    const alice = await makeUser('alice', 1);
    const bob = await makeUser('bob', 2);
    const m = await alice.builder.encrypt(
      new ProtocolAddress('bob', 1),
      Buffer.from('hi'),
      bob.bundle,
    );

    // Manually delete Bob's prekey 100 BEFORE decrypt to simulate replay
    await bob.stores.preKeys.removePreKey(100);

    await expect(
      bob.builder.decrypt(new ProtocolAddress('alice', 1), m),
    ).rejects.toThrow(/one-time prekey id=\d+ not found/);
  });

  it('decrypt rejects when sender identity changed (MITM on receive side)', async () => {
    const alice = await makeUser('alice', 1);
    const bob = await makeUser('bob', 2);

    // Bob pre-trusts a DIFFERENT alice identity
    const fakeAlice = IdentityKeyPair.generate();
    await bob.stores.identity.saveTrustedIdentity(
      new ProtocolAddress('alice', 1),
      fakeAlice.toPublic(),
    );

    // Real alice sends a message — bob should detect the mismatch
    const m = await alice.builder.encrypt(
      new ProtocolAddress('bob', 1),
      Buffer.from('hi'),
      bob.bundle,
    );

    await expect(
      bob.builder.decrypt(new ProtocolAddress('alice', 1), m),
    ).rejects.toThrow(/identity for .* has changed/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// atomic-write — error paths
// ═══════════════════════════════════════════════════════════════════════════

describe('atomic-write — error paths (coverage)', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'signalis-atomic-cov-'));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('readFileOrNull returns null on ENOENT', async () => {
    const result = await readFileOrNull(path.join(dir, 'nonexistent.txt'));
    expect(result).toBeNull();
  });

  it('readFileOrNull rethrows non-ENOENT errors', async () => {
    // Make the path a directory — readFile on a directory throws EISDIR
    await fs.mkdir(path.join(dir, 'is-a-dir'));
    await expect(readFileOrNull(path.join(dir, 'is-a-dir'))).rejects.toThrow();
  });

  it('unlinkIfExists no-ops on missing file', async () => {
    await expect(
      unlinkIfExists(path.join(dir, 'nonexistent.txt')),
    ).resolves.toBeUndefined();
  });

  it('unlinkIfExists rethrows non-ENOENT errors', async () => {
    // Try to unlink a non-empty directory — rethrows EISDIR/EPERM
    await fs.mkdir(path.join(dir, 'a-dir'));
    await fs.writeFile(path.join(dir, 'a-dir', 'file.txt'), 'x');
    await expect(unlinkIfExists(path.join(dir, 'a-dir'))).rejects.toThrow();
  });

  it('listFiles returns [] on missing directory', async () => {
    const result = await listFiles(path.join(dir, 'nonexistent-dir'));
    expect(result).toEqual([]);
  });

  it('listFiles rethrows non-ENOENT errors', async () => {
    // Pass a file as if it were a directory — readdir throws ENOTDIR
    await fs.writeFile(path.join(dir, 'not-a-dir'), 'x');
    await expect(listFiles(path.join(dir, 'not-a-dir'))).rejects.toThrow();
  });

  it('atomicWriteFile cleans up tmp file on write failure', async () => {
    // Spy on rename to make it throw a non-retryable error
    const renameSpy = vi.spyOn(fs, 'rename').mockRejectedValueOnce(
      Object.assign(new Error('mock fatal error'), { code: 'EXDEV' }),
    );

    const target = path.join(dir, 'target.txt');
    await expect(atomicWriteFile(target, 'data')).rejects.toThrow();

    // No .tmp leftovers
    const entries = await fs.readdir(dir);
    const tmpFiles = entries.filter((n) => n.includes('.tmp.'));
    expect(tmpFiles).toEqual([]);

    renameSpy.mockRestore();
  });

  it('atomicWriteFile retries on EPERM and eventually succeeds', async () => {
    // Make rename fail twice with EPERM, succeed third time
    let calls = 0;
    const realRename = fs.rename.bind(fs);
    const renameSpy = vi
      .spyOn(fs, 'rename')
      .mockImplementation(async (from: import('node:fs').PathLike, to: import('node:fs').PathLike) => {
        calls++;
        if (calls <= 2) {
          throw Object.assign(new Error('mock EPERM'), { code: 'EPERM' });
        }
        return realRename(from, to);
      });

    const target = path.join(dir, 'retried.txt');
    await atomicWriteFile(target, 'eventually-ok');

    expect(calls).toBe(3); // 2 failures + 1 success
    const content = await fs.readFile(target, 'utf-8');
    expect(content).toBe('eventually-ok');

    renameSpy.mockRestore();
  });

  it('atomicWriteFile gives up after MAX_ATTEMPTS retries on persistent EPERM', async () => {
    const renameSpy = vi
      .spyOn(fs, 'rename')
      .mockRejectedValue(
        Object.assign(new Error('persistent EPERM'), { code: 'EPERM' }),
      );

    const target = path.join(dir, 'never-succeeds.txt');
    await expect(atomicWriteFile(target, 'data')).rejects.toThrow(/EPERM/);

    // 5 attempts (MAX_ATTEMPTS)
    expect(renameSpy).toHaveBeenCalledTimes(5);

    renameSpy.mockRestore();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Final coverage: clean branches that were missed
// ═══════════════════════════════════════════════════════════════════════════

describe('SessionBuilder — bundle without OPK (coverage)', () => {
  it('encrypt + decrypt works with a bundle that has no one-time prekey', async () => {
    // Bob registers WITHOUT a one-time prekey (only identity + signed prekey)
    const bobStores = StoreBundle.memory();
    const bobIdentity = IdentityKeyPair.generate();
    const bobSpk = SignedPreKey.generate(bobIdentity, 1);
    await bobStores.identity.saveIdentityKeyPair(bobIdentity);
    await bobStores.identity.saveRegistrationId(2);
    await bobStores.signedPreKeys.rotateActiveSignedPreKey(1, bobSpk);
    // ↑ No savePreKey() — Bob has no OPK

    // Bundle WITHOUT oneTimePreKey field
    const bobBundle = PreKeyBundle.build({
      registrationId: 2,
      identityKey: bobIdentity.toPublic(),
      signedPreKey: bobSpk.toPublic(),
      // oneTimePreKey omitted on purpose
    });
    const bobBuilder = new SessionBuilder(bobStores);

    // Alice registers normally
    const aliceStores = StoreBundle.memory();
    const aliceIdentity = IdentityKeyPair.generate();
    await aliceStores.identity.saveIdentityKeyPair(aliceIdentity);
    await aliceStores.identity.saveRegistrationId(1);
    const aliceBuilder = new SessionBuilder(aliceStores);

    // Alice → Bob (no OPK in the wire format)
    const msg = await aliceBuilder.encrypt(
      new ProtocolAddress('bob', 1),
      Buffer.from('hi without OPK'),
      bobBundle,
    );
    expect(msg.type).toBe('prekey');
    if (msg.type === 'prekey') {
      // Confirm the wire payload has no oneTimePreKeyId
      expect(msg.initialMessage.oneTimePreKeyId).toBeUndefined();
    }

    // Bob receives — should work without trying to consume any OPK
    const plaintext = await bobBuilder.decrypt(
      new ProtocolAddress('alice', 1),
      msg,
    );
    expect(plaintext.toString()).toBe('hi without OPK');
  });
});

describe('FileSignedPreKeyStore — null branches (coverage)', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'signalis-fspk-null-'));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('getSignedPreKey returns null for missing id', async () => {
    const store = new FileSignedPreKeyStore(dir);
    expect(await store.getSignedPreKey(999)).toBeNull();
  });

  it('getActiveSignedPreKey returns null before any rotation', async () => {
    const store = new FileSignedPreKeyStore(dir);
    expect(await store.getActiveSignedPreKey()).toBeNull();
  });
});

describe('MemorySignedPreKeyStore — orphan active pointer (coverage)', () => {
  it('getActiveSignedPreKey returns null when active key was deleted', async () => {
    const store = new MemorySignedPreKeyStore();
    const identity = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(identity, 1);

    // Rotate so activeId is set
    await store.rotateActiveSignedPreKey(1, spk);
    expect((await store.getActiveSignedPreKey())!.id).toBe(1);

    // Manually wipe just the keys map (simulates GC bug or external mutation)
    // by calling internal clear() which resets activeId to null too — so we
    // simulate the orphan case by mutating internal map directly.
    // Easier: use the public API to trigger the `?? null` branch via direct
    // map access. We'll achieve it by setting a SECOND rotation then clearing
    // the keys but not the pointer.
    //
    // Since `clear()` resets both, we use an alternative:
    // (store as any).keys.delete(1) — keeps activeId=1 but key is gone.
    // This is the legitimate orphan-pointer edge case.
    (store as unknown as { keys: Map<number, unknown> }).keys.delete(1);

    // activeId is still 1, but keys.get(1) returns undefined → ?? null kicks in
    expect(await store.getActiveSignedPreKey()).toBeNull();
  });
});
