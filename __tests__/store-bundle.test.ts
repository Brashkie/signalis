/**
 * StoreBundle tests
 */

import { describe, it, expect, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

import {
  StoreBundle,
  MemoryIdentityStore,
  MemoryPreKeyStore,
  MemorySignedPreKeyStore,
  MemorySessionStore,
  FileIdentityStore,
  FilePreKeyStore,
  FileSignedPreKeyStore,
  FileSessionStore,
  IdentityKeyPair,
  OneTimePreKey,
  SignedPreKey,
} from '../src';

describe('StoreBundle — construction', () => {
  it('builds with explicit stores', () => {
    const b = new StoreBundle({
      identity: new MemoryIdentityStore(),
      preKeys: new MemoryPreKeyStore(),
      signedPreKeys: new MemorySignedPreKeyStore(),
      sessions: new MemorySessionStore(),
    });
    expect(b.identity).toBeInstanceOf(MemoryIdentityStore);
    expect(b.preKeys).toBeInstanceOf(MemoryPreKeyStore);
    expect(b.signedPreKeys).toBeInstanceOf(MemorySignedPreKeyStore);
    expect(b.sessions).toBeInstanceOf(MemorySessionStore);
  });

  it('is immutable (frozen)', () => {
    const b = StoreBundle.memory();
    expect(Object.isFrozen(b)).toBe(true);
  });

  it('rejects null arg', () => {
    expect(() => new StoreBundle(null as never)).toThrow(TypeError);
  });

  it('rejects missing fields', () => {
    expect(
      () =>
        new StoreBundle({
          identity: new MemoryIdentityStore(),
          preKeys: new MemoryPreKeyStore(),
          signedPreKeys: new MemorySignedPreKeyStore(),
          // missing sessions
        } as never),
    ).toThrow(TypeError);
  });
});

describe('StoreBundle.memory', () => {
  it('uses memory impls', () => {
    const b = StoreBundle.memory();
    expect(b.identity).toBeInstanceOf(MemoryIdentityStore);
    expect(b.preKeys).toBeInstanceOf(MemoryPreKeyStore);
    expect(b.signedPreKeys).toBeInstanceOf(MemorySignedPreKeyStore);
    expect(b.sessions).toBeInstanceOf(MemorySessionStore);
  });

  it('end-to-end memory store usage', async () => {
    const b = StoreBundle.memory();
    const identity = IdentityKeyPair.generate();
    await b.identity.saveIdentityKeyPair(identity);
    await b.preKeys.savePreKey(1, OneTimePreKey.generate(1));
    await b.signedPreKeys.rotateActiveSignedPreKey(
      1,
      SignedPreKey.generate(identity, 1),
    );

    expect((await b.identity.getIdentityKeyPair())!.publicKey.equals(identity.publicKey))
      .toBe(true);
    expect(await b.preKeys.containsPreKey(1)).toBe(true);
    expect((await b.signedPreKeys.getActiveSignedPreKey())!.id).toBe(1);
  });
});

describe('StoreBundle.file', () => {
  let dir: string;

  afterEach(async () => {
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  it('uses file impls', async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'signalis-bundle-'));
    const b = StoreBundle.file(dir);
    expect(b.identity).toBeInstanceOf(FileIdentityStore);
    expect(b.preKeys).toBeInstanceOf(FilePreKeyStore);
    expect(b.signedPreKeys).toBeInstanceOf(FileSignedPreKeyStore);
    expect(b.sessions).toBeInstanceOf(FileSessionStore);
  });

  it('end-to-end file persistence', async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'signalis-bundle-'));
    const b1 = StoreBundle.file(dir);
    const id = IdentityKeyPair.generate();
    await b1.identity.saveIdentityKeyPair(id);
    await b1.identity.saveRegistrationId(123);

    // Re-open: should see the same data
    const b2 = StoreBundle.file(dir);
    const loaded = await b2.identity.getIdentityKeyPair();
    expect(loaded!.publicKey.equals(id.publicKey)).toBe(true);
    expect(await b2.identity.getRegistrationId()).toBe(123);
  });
});

describe('StoreBundle — mixing impls', () => {
  it('mix: file identity + memory sessions', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'signalis-mix-'));
    try {
      const b = new StoreBundle({
        identity: new FileIdentityStore(dir),
        preKeys: new FilePreKeyStore(dir),
        signedPreKeys: new FileSignedPreKeyStore(dir),
        sessions: new MemorySessionStore(),
      });
      const kp = IdentityKeyPair.generate();
      await b.identity.saveIdentityKeyPair(kp);
      expect((await b.identity.getIdentityKeyPair())!.publicKey.equals(kp.publicKey)).toBe(true);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
