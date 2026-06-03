/**
 * Example 06 — Persistence Pattern
 * ════════════════════════════════════════════════════════════════════════
 *
 * Real apps need to persist crypto state across restarts. This example
 * shows the patterns you'll use with ANY storage backend (file, SQLite,
 * Postgres, IndexedDB, encrypted keychain).
 *
 * What you need to persist:
 *   1. Long-term identity (CRITICAL: ENCRYPTED AT REST)
 *   2. Current signed prekey + history (rotate weekly)
 *   3. Unused one-time prekeys
 *   4. (v0.6.0+) Session state per peer
 *
 * What you should NEVER do:
 *   • Log private keys
 *   • Send private keys over the network
 *   • Store private keys in plaintext storage
 *   • Reuse a one-time prekey ID after it's been consumed
 *
 * Run with:
 *   npx tsx examples/06-persistence-pattern.ts
 *
 * Format: TypeScript ESM
 */

import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  type SerializedKeyPair,
  type SerializedSignedPreKey,
  type SerializedOneTimePreKey,
} from '@brashkie/signalis';

// ════════════════════════════════════════════════════════════════════════
// Storage abstractions (replace with your real backend)
// ════════════════════════════════════════════════════════════════════════
//
// In production, ENCRYPT BEFORE WRITING. Examples:
//   • macOS:   keychain-access via `keytar` npm package
//   • Linux:   `libsecret` (`keytar` works here too)
//   • Windows: Windows Credential Manager via `keytar`
//   • Server:  AWS KMS, Vault, GCP KMS
//   • Mobile:  iOS Keychain / Android KeyStore
//   • Browser: NEVER store identity keys in plain localStorage
//
// For this example, we use a tmp directory with NO encryption.
// THIS IS NOT SAFE FOR PRODUCTION.

const STORAGE_DIR = join(tmpdir(), 'signalis-example-' + Date.now());

async function ensureStorageDir() {
  await fs.mkdir(STORAGE_DIR, { recursive: true });
}

async function writeSecret(name: string, data: unknown) {
  await fs.writeFile(
    join(STORAGE_DIR, `${name}.json`),
    JSON.stringify(data, null, 2),
    { mode: 0o600 }, // owner read/write only — bare minimum
  );
}

async function readSecret<T>(name: string): Promise<T | null> {
  try {
    const raw = await fs.readFile(join(STORAGE_DIR, `${name}.json`), 'utf-8');
    return JSON.parse(raw) as T;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw e;
  }
}

// ════════════════════════════════════════════════════════════════════════
// SCENARIO 1 — First-time setup (registration)
// ════════════════════════════════════════════════════════════════════════

async function firstTimeSetup(registrationId: number) {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('SCENARIO 1: First-time setup');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // 1. Generate the long-term identity
  const identity = IdentityKeyPair.generate();
  console.log('Identity fingerprint:', identity.shortFingerprint());

  // 2. Generate the first signed prekey
  const spk = SignedPreKey.generate(identity, /* id */ 1);
  console.log('SignedPreKey id:     ', spk.id);

  // 3. Generate a batch of one-time prekeys
  const otpks = OneTimePreKey.generateBatch(/* startId */ 1, /* count */ 100);
  console.log('OneTimePreKeys:      ', otpks.length);

  // 4. Persist everything (encrypted in real apps!)
  await writeSecret('identity', identity.serialize());
  await writeSecret('signed-prekey', spk.serialize());
  await writeSecret('one-time-prekeys', otpks.map((k) => k.serialize()));
  await writeSecret('next-spk-id', { id: 2 });
  await writeSecret('next-otpk-id', { id: 101 });
  console.log('\n✅ All keys saved to', STORAGE_DIR);

  // 5. Build the bundle to publish to the server
  //    (the server stores the PUBLIC bundle; private parts stay local)
  const bundle = PreKeyBundle.build({
    registrationId,
    identityKey: identity.toPublic(),
    signedPreKey: spk.toPublic(),
    oneTimePreKey: otpks[0].toPublic(),
  });
  console.log('Bundle address to publish:', bundle.address());

  return bundle.toPayload(); // → send this to the server
}

// ════════════════════════════════════════════════════════════════════════
// SCENARIO 2 — App restart, restore everything
// ════════════════════════════════════════════════════════════════════════

async function appStartup() {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('SCENARIO 2: App restart — load identity + prekeys');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // 1. Load identity
  const identityData = await readSecret<SerializedKeyPair>('identity');
  if (!identityData) throw new Error('No identity — call firstTimeSetup');
  const identity = IdentityKeyPair.deserialize(identityData);
  console.log('Loaded identity:    ', identity.shortFingerprint());

  // 2. Load signed prekey
  const spkData = await readSecret<SerializedSignedPreKey>('signed-prekey');
  if (!spkData) throw new Error('No signed prekey');
  const spk = SignedPreKey.deserialize(spkData);
  console.log('Loaded SPK id:      ', spk.id);
  console.log('SPK age (hours):    ', (spk.ageMs() / 3600000).toFixed(2));
  console.log('SPK needs rotation?:', spk.needsRotation());

  // 3. Load one-time prekeys
  const otpksData = await readSecret<SerializedOneTimePreKey[]>('one-time-prekeys');
  if (!otpksData) throw new Error('No one-time prekeys');
  const otpks = otpksData.map((d) => OneTimePreKey.deserialize(d));
  console.log('Loaded OTPKs:       ', otpks.length);

  return { identity, spk, otpks };
}

// ════════════════════════════════════════════════════════════════════════
// SCENARIO 3 — Weekly maintenance task
// ════════════════════════════════════════════════════════════════════════

async function weeklyMaintenance() {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('SCENARIO 3: Weekly maintenance task');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const { identity, spk, otpks } = await appStartup();

  // ─── Task 1: Rotate SignedPreKey if needed ──────────────────────────
  if (spk.needsRotation()) {
    const next = (await readSecret<{ id: number }>('next-spk-id'))!.id;
    const newSpk = SignedPreKey.generate(identity, next);
    await writeSecret('signed-prekey', newSpk.serialize());
    await writeSecret('next-spk-id', { id: next + 1 });
    console.log(`✅ Rotated SignedPreKey from id ${spk.id} → id ${next}`);
    console.log(`→ POST /api/keys/signed-prekey with newSpk.toPayload()`);
  } else {
    console.log(`✅ SignedPreKey (id ${spk.id}) is still fresh (no rotation)`);
  }

  // ─── Task 2: Replenish OneTimePreKeys if low ────────────────────────
  const MIN_OTPKS = 10;
  if (otpks.length < MIN_OTPKS) {
    const nextId = (await readSecret<{ id: number }>('next-otpk-id'))!.id;
    const newBatch = OneTimePreKey.generateBatch(nextId, 90);
    const updated = [...otpks, ...newBatch];
    await writeSecret('one-time-prekeys', updated.map((k) => k.serialize()));
    await writeSecret('next-otpk-id', { id: nextId + 90 });
    console.log(`✅ Refilled OTPKs: ${otpks.length} → ${updated.length}`);
    console.log(`→ POST /api/keys/one-time with newBatch.map(k => k.toPayload())`);
  } else {
    console.log(`✅ OTPK pool healthy (${otpks.length} ≥ ${MIN_OTPKS})`);
  }
}

// ════════════════════════════════════════════════════════════════════════
// SCENARIO 4 — Bob receives a message; mark the OTPK as consumed
// ════════════════════════════════════════════════════════════════════════

async function consumeOneTimePreKey(consumedId: number) {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`SCENARIO 4: Bob consumed OTPK id ${consumedId}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const all = (await readSecret<SerializedOneTimePreKey[]>('one-time-prekeys'))!;
  const beforeCount = all.length;
  const remaining = all.filter((k) => k.id !== consumedId);
  const afterCount = remaining.length;

  if (afterCount === beforeCount) {
    console.log(`⚠️  OTPK id ${consumedId} was NOT in our store (already consumed?)`);
    return;
  }

  await writeSecret('one-time-prekeys', remaining);
  console.log(`✅ Deleted OTPK id ${consumedId} (${beforeCount} → ${afterCount})`);
  console.log('   (forward secrecy: this key can never be used again)');
}

// ════════════════════════════════════════════════════════════════════════
// Run the full flow
// ════════════════════════════════════════════════════════════════════════

async function main() {
  await ensureStorageDir();

  // First-time setup
  const _publishedBundle = await firstTimeSetup(4242);

  // ... time passes, app restarts ...

  // Startup
  await appStartup();

  // Weekly cron
  await weeklyMaintenance();

  // Someone messaged Bob — consume OTPK id 1
  await consumeOneTimePreKey(1);
  await consumeOneTimePreKey(2);
  await consumeOneTimePreKey(3);

  // Reload to verify deletions persisted
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Verify: reload and count');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  const final = await appStartup();
  console.log('Final OTPK count:', final.otpks.length, '(was 100, consumed 3)');

  // Cleanup
  await fs.rm(STORAGE_DIR, { recursive: true });
  console.log('\n🎉 Example complete!\n');
}

main().catch(console.error);
