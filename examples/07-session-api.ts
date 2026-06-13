/**
 * Example 07 — Session Class (The Real API)
 * ════════════════════════════════════════════════════════════════════════
 *
 * v0.6.0 introduces the Session class — the high-level API most users
 * will actually touch. Everything from Sprints 1-3 collapses into 5 lines.
 *
 * Compare this to example 05 (full-flow) — same functionality, 1/10 the code.
 *
 * Run with:
 *   npx tsx examples/07-session-api.ts
 *
 * Format: TypeScript ESM
 */

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
  Session,
} from '@brashkie/signalis';

// ════════════════════════════════════════════════════════════════════════
// Setup (same as before — Bob publishes a bundle)
// ════════════════════════════════════════════════════════════════════════

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

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('1. Alice initiates a Session with Bob');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// X3DH gives us the sharedSecret
const handshake = X3DH.initiate(alice, bobBundle, {
  myRegistrationId: 1234,
});

// Session wraps everything
const aliceSession = Session.initiateFromX3DH({
  sharedSecret: handshake.sharedSecret,
  theirIdentityKey: bob.toPublic(),
  theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
});

console.log('Alice session:', aliceSession.toString());

// ════════════════════════════════════════════════════════════════════════
// Alice encrypts — ONE LINE
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('2. Alice encrypts (one line)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const packet1 = aliceSession.encrypt(Buffer.from('Hola Bob!'));

console.log('Encrypted packet (over the wire):');
console.log(JSON.stringify({
  initialMessage: handshake.initialMessage,
  ...packet1,
}, null, 2).slice(0, 500) + '...');

// ════════════════════════════════════════════════════════════════════════
// Bob receives + decrypts
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('3. Bob receives Alice\'s message');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Bob runs X3DH first (one-time setup for the session)
const bobResult = X3DH.receive(bob, bobSpk, bobOpk, handshake.initialMessage);

const bobSession = Session.receiveFromX3DH({
  sharedSecret: bobResult.sharedSecret,
  myIdentityKey: bob.toPublic(),
  mySignedPreKeyPrivate: bobSpk.privateKey,
  mySignedPreKeyPublic: bobSpk.publicKey,
  theirIdentityKey: alice.toPublic(),
});

// Decrypt — ONE LINE
const decoded = bobSession.decrypt(packet1);
console.log('Bob decrypted:', decoded.toString('utf-8'));

// ════════════════════════════════════════════════════════════════════════
// Continued conversation — the ratchet just works
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('4. They exchange more messages (DH ratchet rotates automatically)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const exchange = async () => {
  // Alice sends 2 more
  for (let i = 1; i <= 2; i++) {
    const p = aliceSession.encrypt(Buffer.from(`alice msg #${i}`));
    console.log(`Alice → Bob: "${bobSession.decrypt(p).toString()}"`);
  }

  // Bob replies (DH ratchet rotation happens here, automatically)
  for (let i = 0; i < 2; i++) {
    const p = bobSession.encrypt(Buffer.from(`bob msg #${i}`));
    console.log(`Bob → Alice: "${aliceSession.decrypt(p).toString()}"`);
  }

  // Alice replies (her DH rotates now too, automatically)
  const p = aliceSession.encrypt(Buffer.from('back to alice'));
  console.log(`Alice → Bob: "${bobSession.decrypt(p).toString()}"`);
};
await exchange();

// ════════════════════════════════════════════════════════════════════════
// Out-of-order delivery — handled automatically
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('5. Out-of-order: Bob sends 3 quickly, network reorders them');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const b0 = bobSession.encrypt(Buffer.from('bob-A'));
const b1 = bobSession.encrypt(Buffer.from('bob-B'));
const b2 = bobSession.encrypt(Buffer.from('bob-C'));

// Network delivers in order 2, 0, 1
console.log('Network delivered 2nd packet first:');
console.log('  Alice decrypts bob-C first:', aliceSession.decrypt(b2).toString());
console.log('  Skipped keys cached:       ', aliceSession.skippedKeysCount());

console.log('Then bob-A arrives:');
console.log('  Alice decrypts:            ', aliceSession.decrypt(b0).toString());

console.log('Finally bob-B arrives:');
console.log('  Alice decrypts:            ', aliceSession.decrypt(b1).toString());
console.log('  Skipped keys remaining:    ', aliceSession.skippedKeysCount());

// ════════════════════════════════════════════════════════════════════════
// Persistence — survive app restart
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('6. App restart simulation: serialize → restore → continue');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Persist
const aliceState = JSON.stringify(aliceSession.serialize());
console.log('Serialized state size:', aliceState.length, 'bytes');
console.log('(In real app: encrypt this and store in keychain/KMS)');

// 💀 App crashes 💀 ... time passes ... app restarts

// Restore
const aliceRestored = Session.deserialize(JSON.parse(aliceState));
console.log('Restored:', aliceRestored.toString());

// Continue right where we left off
const reply = aliceRestored.encrypt(Buffer.from('also after restart'));
console.log('Bob decrypts:', bobSession.decrypt(reply).toString());

// ════════════════════════════════════════════════════════════════════════
// Tamper detection
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('7. Tampering attempt — MAC catches it');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const safePacket = aliceRestored.encrypt(Buffer.from('original'));

// Tamper with the ciphertext
const tampered = {
  ...safePacket,
  ciphertext: safePacket.ciphertext.replace(/^./, 'f'),
};

try {
  bobSession.decrypt(tampered);
  console.log('⚠️ Should NEVER reach here');
} catch (e) {
  console.log('Tampered packet REJECTED ✅');
  console.log('  →', (e as Error).message);
}

console.log('\n🎉 Example complete!\n');
console.log('Compare this 200-line example to example 05 (`05-full-flow.ts`)');
console.log('which does the same thing using primitives in ~245 lines.');
console.log('The Session class is the same protocol; just easier to use.\n');
