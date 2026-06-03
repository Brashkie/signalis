/**
 * Example 03 — X3DH Handshake (Async Key Agreement)
 * ════════════════════════════════════════════════════════════════════════
 *
 * The "magic moment" of Signal Protocol: Alice and Bob derive the SAME
 * 32-byte secret WITHOUT ever being online at the same time.
 *
 * How? Alice fetches Bob's pre-published Bundle from a server, runs 4
 * Diffie-Hellman exchanges, mixes the outputs through HKDF-SHA256, and
 * produces a sharedSecret + initialMessage. Bob later receives the
 * initialMessage and replays the same 4 DHs from his side, deriving the
 * SAME sharedSecret.
 *
 * Run with:
 *   node examples/03-x3dh-handshake.mjs
 *
 * What this demonstrates:
 *   • Full X3DH flow: Bob publishes, Alice initiates, Bob receives
 *   • Wire format roundtrip (JSON over the network)
 *   • Why the one-time prekey matters (forward secrecy)
 *   • What Bob should do after consuming an OTPK
 *
 * Format: JavaScript ESM (.mjs)
 */

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
} from '@brashkie/signalis';

// ════════════════════════════════════════════════════════════════════════
// SETUP: Bob is offline, has published his Bundle to a server
// ════════════════════════════════════════════════════════════════════════

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('SETUP — Bob has been offline for hours');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Bob did this when he registered (probably weeks ago):
const bob = IdentityKeyPair.generate();
const bobSpk = SignedPreKey.generate(bob, 1);
const bobOtpks = OneTimePreKey.generateBatch(1, 100);
// 💤 Bob is sleeping now

// His Bundle is sitting on the server:
const serverBundle = PreKeyBundle.build({
  registrationId: 4242,
  identityKey: bob.toPublic(),
  signedPreKey: bobSpk.toPublic(),
  oneTimePreKey: bobOtpks[42].toPublic(), // server picks one for Alice
}).toPayload();

console.log('Server has Bob\'s Bundle queued for him');
console.log('  Registration ID:', 4242);
console.log('  Bob status:     OFFLINE 💤');

// ════════════════════════════════════════════════════════════════════════
// ALICE'S SIDE — fetches bundle, runs X3DH
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('ALICE — wants to send Bob a message NOW');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const alice = IdentityKeyPair.generate();

// Step 1: Alice fetches Bob's Bundle (and verifies it)
const bobBundle = PreKeyBundle.fromPayload(serverBundle);
console.log('1. Alice fetched Bob\'s bundle, signature verified ✅');

// Step 2: Alice runs X3DH (4 DHs + HKDF under the hood)
const handshake = X3DH.initiate(alice, bobBundle, {
  myRegistrationId: 1234,
  myDeviceId: 1,
});

console.log('2. Alice ran X3DH:');
console.log('   sharedSecret:', handshake.sharedSecret.toString('hex').slice(0, 32) + '...');
console.log('   ephemeral pub:', handshake.ephemeralPublicKey.toString('hex').slice(0, 32) + '...');

// Step 3: Alice now uses sharedSecret to seed the Double Ratchet (in
// v0.6.0 the Session class will wrap this). She prepares the message
// payload to send to Bob:
const messageToBob = {
  initialMessage: handshake.initialMessage,
  // ↑ Bob needs this to derive the same sharedSecret on his side
  encryptedPayload: '(encrypted ciphertext goes here — Sprint 3 Part 2)',
};

console.log('3. Alice will send to Bob: initialMessage + her ciphertext');
console.log('   InitialMessage fields:', Object.keys(handshake.initialMessage));

// ════════════════════════════════════════════════════════════════════════
// BOB'S SIDE — comes back online, processes the message
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('BOB — comes online hours later, gets Alice\'s message');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Bob receives the message over the network (JSON deserialization)
const networkPayload = JSON.parse(JSON.stringify(messageToBob));

// Step 4: Bob looks up his private prekeys by ID from his local storage
//        (here we just use the in-memory ones we created above)
const myMatchingSpk = bobSpk;                                  // id 1
const myMatchingOtpk = bobOtpks.find(
  (k) => k.id === networkPayload.initialMessage.oneTimePreKeyId,
);

console.log('1. Bob looks up his prekeys from local storage:');
console.log('   SPK id:  ', networkPayload.initialMessage.signedPreKeyId);
console.log('   OTPK id: ', networkPayload.initialMessage.oneTimePreKeyId);

// Step 5: Bob runs X3DH on his side
const bobResult = X3DH.receive(
  bob,
  myMatchingSpk,
  myMatchingOtpk,
  networkPayload.initialMessage,
);

console.log('\n2. Bob ran X3DH:');
console.log('   sharedSecret:', bobResult.sharedSecret.toString('hex').slice(0, 32) + '...');
console.log('   OTPK consumed:', bobResult.oneTimePreKeyId);

// ════════════════════════════════════════════════════════════════════════
// 🎉 THE MAGIC MOMENT
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('🎉 THE MAGIC MOMENT');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const same = handshake.sharedSecret.equals(bobResult.sharedSecret);
console.log('Alice and Bob have the SAME secret?', same, '←', same ? '✅' : '❌');

if (same) {
  console.log('\nThey now share 32 bytes of secret entropy.');
  console.log('Bob never replied, never was online while Alice initiated.');
  console.log('This is how WhatsApp / Signal send the first message offline.');
}

// ════════════════════════════════════════════════════════════════════════
// 🛡️ FORWARD SECRECY — Bob deletes the consumed OTPK
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('🛡️  CRITICAL: Bob deletes the consumed OneTimePreKey');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

if (bobResult.oneTimePreKeyId !== null) {
  // In a real app, delete from your database:
  //   await db.oneTimePreKeys.delete({ id: bobResult.oneTimePreKeyId });
  console.log(`→ DELETE FROM one_time_prekeys WHERE id = ${bobResult.oneTimePreKeyId}`);
  console.log('  (forward secrecy: if Bob is compromised later, this');
  console.log('   session\'s secret cannot be reconstructed)');
}

console.log('\n🎉 Example complete!\n');
console.log('Next: see example 04 for the Double Ratchet primitives,');
console.log('      and example 05 for the FULL flow X3DH → Ratchet.');
