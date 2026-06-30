/**
 * Example 08 — Storage Layer (The Real Deal)
 * ════════════════════════════════════════════════════════════════════════
 *
 * v0.7.0 adds the storage layer + SessionBuilder. This makes signalis
 * usable as the crypto foundation for a real messaging app (not just a
 * crypto-spec library).
 *
 * This example shows a full app lifecycle:
 *   1. Alice and Bob register (generate identities, prekeys, signed prekeys)
 *   2. They exchange messages
 *   3. Both apps "restart" (simulated by re-opening stores from disk)
 *   4. Conversation continues seamlessly
 *
 * Run with:
 *   npx tsx examples/08-storage-layer.ts
 *
 * Format: TypeScript ESM
 */

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
} from '@brashkie/signalis';

// ════════════════════════════════════════════════════════════════════════
// Setup — create temp dirs for Alice and Bob's "app data"
// ════════════════════════════════════════════════════════════════════════

const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'signalis-demo-'));
const aliceDir = path.join(tmpDir, 'alice');
const bobDir = path.join(tmpDir, 'bob');

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('1. Alice and Bob register (one-time setup per device)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

async function register(rootDir: string, registrationId: number) {
  const stores = StoreBundle.file(rootDir);
  const identity = IdentityKeyPair.generate();
  const spk = SignedPreKey.generate(identity, 1);
  const opk = OneTimePreKey.generate(100);

  // Persist everything to disk
  await stores.identity.saveIdentityKeyPair(identity);
  await stores.identity.saveRegistrationId(registrationId);
  await stores.signedPreKeys.rotateActiveSignedPreKey(1, spk);
  await stores.preKeys.savePreKey(100, opk);

  // The bundle Alice would publish to a server for Bob to fetch
  const bundle = PreKeyBundle.build({
    registrationId,
    identityKey: identity.toPublic(),
    signedPreKey: spk.toPublic(),
    oneTimePreKey: opk.toPublic(),
  });

  return {
    rootDir,
    stores,
    builder: new SessionBuilder(stores),
    identity,
    bundle,
  };
}

let alice = await register(aliceDir, 1001);
let bob = await register(bobDir, 1002);

console.log('  Alice (id=1001) registered at', aliceDir);
console.log('  Bob (id=1002) registered at', bobDir);
console.log('  Alice fingerprint:', alice.identity.toPublic().fingerprint());
console.log('  Bob fingerprint:  ', bob.identity.toPublic().fingerprint());

const bobAddr = new ProtocolAddress('bob', 1);
const aliceAddr = new ProtocolAddress('alice', 1);

// ════════════════════════════════════════════════════════════════════════
// 2. Alice sends Bob a message — first time (X3DH bootstrap)
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('2. Alice fetches Bob\'s bundle and sends a first message');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const m1 = await alice.builder.encrypt(
  bobAddr,
  Buffer.from('Hola Bob, soy Alice'),
  bob.bundle,
);

console.log('  Sent message type:', m1.type, '(prekey = X3DH bootstrap included)');
console.log('  Wire size: ~', JSON.stringify(m1).length, 'bytes');

const dec1 = await bob.builder.decrypt(aliceAddr, m1);
console.log('  Bob decrypts:', dec1.toString());

// ════════════════════════════════════════════════════════════════════════
// 3. Bob replies — no bundle needed, session exists on both sides
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('3. Bob replies (session already exists, no bundle needed)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const m2 = await bob.builder.encrypt(
  aliceAddr,
  Buffer.from('Hola Alice, te recibí'),
);

console.log('  Sent message type:', m2.type, '(whisper = ratchet only, smaller)');
console.log('  Wire size: ~', JSON.stringify(m2).length, 'bytes');

console.log('  Alice decrypts:', (await alice.builder.decrypt(bobAddr, m2)).toString());

// ════════════════════════════════════════════════════════════════════════
// 4. Multi-message conversation
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('4. Ping-pong: 5 messages each way (sessions auto-saved to disk)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

for (let i = 0; i < 5; i++) {
  const a = await alice.builder.encrypt(bobAddr, Buffer.from(`Alice msg ${i}`));
  console.log(`  Alice → Bob: "${(await bob.builder.decrypt(aliceAddr, a)).toString()}"`);

  const b = await bob.builder.encrypt(aliceAddr, Buffer.from(`Bob msg ${i}`));
  console.log(`  Bob → Alice: "${(await alice.builder.decrypt(bobAddr, b)).toString()}"`);
}

// ════════════════════════════════════════════════════════════════════════
// 5. 💥 SIMULATE APP RESTART
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('5. App restart! Both apps reopen, build fresh stores from disk');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Clear in-memory state, reload from disk
const aliceStores = StoreBundle.file(aliceDir);
const bobStores = StoreBundle.file(bobDir);
alice = { ...alice, stores: aliceStores, builder: new SessionBuilder(aliceStores) };
bob = { ...bob, stores: bobStores, builder: new SessionBuilder(bobStores) };

console.log('  Alice and Bob restarted their apps');
console.log('  Loaded identity:', (await alice.stores.identity.getIdentityKeyPair())!.toPublic().fingerprint());
console.log('  Active sessions:', (await alice.stores.sessions.loadAllSessions()).length);

// Continue conversation seamlessly
const m3 = await alice.builder.encrypt(bobAddr, Buffer.from('after restart!'));
console.log('  Alice → Bob:', (await bob.builder.decrypt(aliceAddr, m3)).toString());

// ════════════════════════════════════════════════════════════════════════
// 6. Diagnostic: see what's on disk
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('6. What\'s on disk in Alice\'s app dir?');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

async function listTree(dir: string, prefix = ''): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    console.log(`  ${prefix}${entry.isDirectory() ? '📁' : '📄'} ${entry.name}`);
    if (entry.isDirectory()) {
      await listTree(full, prefix + '  ');
    }
  }
}
await listTree(aliceDir);

// ════════════════════════════════════════════════════════════════════════
// Cleanup
// ════════════════════════════════════════════════════════════════════════

await fs.rm(tmpDir, { recursive: true, force: true });

console.log('\n🎉 Demo complete!\n');
console.log('Try comparing this to example 05 (`05-full-flow.ts`):');
console.log('  - example 05: manual X3DH + Session + persistence boilerplate');
console.log('  - example 08: 3-line "encrypt + decrypt" API\n');
