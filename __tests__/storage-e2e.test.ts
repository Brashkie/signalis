/**
 * Storage E2E — full conversation + app restart simulation.
 */

import { describe, it, expect, afterEach } from 'vitest';
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
} from '../src';

async function freshDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), 'signalis-e2e-'));
}

describe('Storage E2E — full app lifecycle', () => {
  let aliceDir: string;
  let bobDir: string;

  afterEach(async () => {
    if (aliceDir) await fs.rm(aliceDir, { recursive: true, force: true });
    if (bobDir) await fs.rm(bobDir, { recursive: true, force: true });
  });

  async function setupUser(rootDir: string, opts: { regId: number }) {
    const stores = StoreBundle.file(rootDir);
    const identity = IdentityKeyPair.generate();
    const spk = SignedPreKey.generate(identity, 1);
    const opk = OneTimePreKey.generate(100);

    await stores.identity.saveIdentityKeyPair(identity);
    await stores.identity.saveRegistrationId(opts.regId);
    await stores.signedPreKeys.rotateActiveSignedPreKey(1, spk);
    await stores.preKeys.savePreKey(100, opk);

    const bundle = PreKeyBundle.build({
      registrationId: opts.regId,
      identityKey: identity.toPublic(),
      signedPreKey: spk.toPublic(),
      oneTimePreKey: opk.toPublic(),
    });

    return {
      stores,
      builder: new SessionBuilder(stores),
      identity,
      bundle,
      rootDir,
    };
  }

  it('full E2E: register, send, receive, reply, save state, restart, continue', async () => {
    aliceDir = await freshDir();
    bobDir = await freshDir();

    // ─── Bootstrap both ────────────────────────────────────────────
    let alice = await setupUser(aliceDir, { regId: 1001 });
    let bob = await setupUser(bobDir, { regId: 1002 });

    const bobAddr = new ProtocolAddress('bob', 1);
    const aliceAddr = new ProtocolAddress('alice', 1);

    // ─── Alice → Bob (first message, X3DH bootstrap) ───────────────
    const m1 = await alice.builder.encrypt(
      bobAddr,
      Buffer.from('Hola Bob, soy Alice'),
      bob.bundle,
    );
    expect((await bob.builder.decrypt(aliceAddr, m1)).toString()).toBe(
      'Hola Bob, soy Alice',
    );

    // ─── Bob → Alice ───────────────────────────────────────────────
    const m2 = await bob.builder.encrypt(
      aliceAddr,
      Buffer.from('Hola Alice, te recibí'),
    );
    expect((await alice.builder.decrypt(bobAddr, m2)).toString()).toBe(
      'Hola Alice, te recibí',
    );

    // ─── 5 more rounds ─────────────────────────────────────────────
    for (let i = 0; i < 5; i++) {
      const a = await alice.builder.encrypt(bobAddr, Buffer.from(`A${i}`));
      expect((await bob.builder.decrypt(aliceAddr, a)).toString()).toBe(`A${i}`);
      const b = await bob.builder.encrypt(aliceAddr, Buffer.from(`B${i}`));
      expect((await alice.builder.decrypt(bobAddr, b)).toString()).toBe(`B${i}`);
    }

    // ─── 💥 SIMULATE APP RESTART — both sides ──────────────────────
    // Build fresh StoreBundle + SessionBuilder from disk
    alice = {
      ...alice,
      stores: StoreBundle.file(aliceDir),
      builder: new SessionBuilder(StoreBundle.file(aliceDir)),
    };
    bob = {
      ...bob,
      stores: StoreBundle.file(bobDir),
      builder: new SessionBuilder(StoreBundle.file(bobDir)),
    };

    // ─── Continue conversation seamlessly ──────────────────────────
    const m3 = await alice.builder.encrypt(
      bobAddr,
      Buffer.from('after restart'),
    );
    expect((await bob.builder.decrypt(aliceAddr, m3)).toString()).toBe(
      'after restart',
    );

    const m4 = await bob.builder.encrypt(
      aliceAddr,
      Buffer.from('I am still here'),
    );
    expect((await alice.builder.decrypt(bobAddr, m4)).toString()).toBe(
      'I am still here',
    );
  });

  it('Alice has 2 conversations with different peers, both persist', async () => {
    aliceDir = await freshDir();
    const carolDir = await freshDir();
    bobDir = await freshDir();

    try {
      const alice = await setupUser(aliceDir, { regId: 1 });
      const bob = await setupUser(bobDir, { regId: 2 });
      const carol = await setupUser(carolDir, { regId: 3 });

      // Alice → Bob
      const m1 = await alice.builder.encrypt(
        new ProtocolAddress('bob', 1),
        Buffer.from('hi bob'),
        bob.bundle,
      );
      await bob.builder.decrypt(new ProtocolAddress('alice', 1), m1);

      // Alice → Carol (different bundle, independent session)
      const m2 = await alice.builder.encrypt(
        new ProtocolAddress('carol', 1),
        Buffer.from('hi carol'),
        carol.bundle,
      );
      await carol.builder.decrypt(new ProtocolAddress('alice', 1), m2);

      // Alice should have 2 sessions stored
      const all = await alice.stores.sessions.loadAllSessions();
      expect(all.length).toBe(2);
      const userIds = all.map((s) => s.address.userId).sort();
      expect(userIds).toEqual(['bob', 'carol']);
    } finally {
      await fs.rm(carolDir, { recursive: true, force: true });
    }
  });
});
