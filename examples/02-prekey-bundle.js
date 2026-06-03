/**
 * Example 02 — PreKey Bundle Setup & Verification
 * ════════════════════════════════════════════════════════════════════════
 *
 * Before two people can encrypt messages to each other, they need to
 * exchange some keys ahead of time. The "PreKey Bundle" is the format
 * Bob uses to publish his keys to a server so Alice can fetch them later
 * (even when Bob is offline).
 *
 * Run with:
 *   node examples/02-prekey-bundle.js
 *
 * What this demonstrates:
 *   • Bob generates: identity + signed prekey + one-time prekeys
 *   • Bob publishes a PreKey Bundle to the server (JSON payload)
 *   • Alice fetches the bundle
 *   • Alice AUTOMATICALLY verifies the signed prekey signature
 *   • Tamper-detection: a corrupted bundle is rejected
 *
 * Format: CommonJS JavaScript (require)
 */

const {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  SignatureError,
} = require('@brashkie/signalis');

// ════════════════════════════════════════════════════════════════════════
// 1. Bob's side: generate everything needed for a session
// ════════════════════════════════════════════════════════════════════════

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('1. Bob registers — generates identity + prekeys');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Long-term identity (stored encrypted, used for lifetime of the account)
const bob = IdentityKeyPair.generate();

// Medium-term Signed PreKey — rotated every ~7 days
// Signed BY the identity key, so receivers can verify it's legit
const bobSpk = SignedPreKey.generate(bob, /* id */ 1);

// Short-term One-Time PreKeys — each used ONCE then deleted
// Generate 100 at a time, replenish when running low
const bobOpks = OneTimePreKey.generateBatch(/* startId */ 1, /* count */ 100);

console.log('Bob identity fingerprint:', bob.shortFingerprint());
console.log('Bob SignedPreKey ID:     ', bobSpk.id);
console.log('Bob SPK signature valid: ', bobSpk.verify(bob.toPublic()));
console.log('Bob OTPK batch size:     ', bobOpks.length);

// ════════════════════════════════════════════════════════════════════════
// 2. Bob publishes a Bundle to the server
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('2. Bob publishes a Bundle to the server');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// When Alice (or anyone) wants to message Bob, the server picks one of
// Bob's available one-time prekeys and packages it together with his
// identity + signed prekey into a Bundle.
const pickedOpk = bobOpks[0];

const bundleForAlice = PreKeyBundle.build({
  registrationId: 4242,           // Bob's account ID (range 1..16380)
  deviceId: 1,                    // Bob's device #1 (1..2^31)
  identityKey: bob.toPublic(),
  signedPreKey: bobSpk.toPublic(),
  oneTimePreKey: pickedOpk.toPublic(),
});

console.log('Bundle address:    ', bundleForAlice.address());
console.log('Bundle has OTPK?:  ', bundleForAlice.hasOneTimePreKey());

// The server stores this as JSON
const wireFormat = bundleForAlice.toPayload();
const serverJson = JSON.stringify(wireFormat, null, 2);
console.log('Bundle JSON (first 200 chars):');
console.log('  ' + serverJson.slice(0, 200).replace(/\n/g, '\n  ') + '...');

// ════════════════════════════════════════════════════════════════════════
// 3. Alice fetches and AUTOMATICALLY verifies
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('3. Alice fetches Bob\'s bundle and verifies');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Simulating a fetch from the server
const fetchedJson = serverJson;
const fetchedPayload = JSON.parse(fetchedJson);

// fromPayload AUTOMATICALLY verifies:
//   - The signed prekey signature against the identity key
//   - All field types and sizes
//   - The hex encoding of every key
// If anything is wrong, it throws SignatureError or SerializationError.
const verifiedBundle = PreKeyBundle.fromPayload(fetchedPayload);

console.log('Bundle verified ✅');
console.log('  Bob identity:  ', verifiedBundle.identityKey.shortFingerprint());
console.log('  SPK id:        ', verifiedBundle.signedPreKey.id);
console.log('  OTPK id:       ', verifiedBundle.oneTimePreKey?.id);

// ════════════════════════════════════════════════════════════════════════
// 4. Tampering is detected
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('4. Mallory tampers with the bundle');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Scenario A: A malicious server tries to swap Bob's identity with Mallory's
const mallory = IdentityKeyPair.generate();
const malloriousBundle = {
  ...fetchedPayload,
  identityKey: mallory.toPublic().toHex(),  // ← attacker subs identity
};

try {
  PreKeyBundle.fromPayload(malloriousBundle);
  console.log('⚠️  This should NEVER print');
} catch (e) {
  if (e instanceof SignatureError) {
    console.log('Tampered bundle REJECTED ✅');
    console.log('  Error code:', e.code);
    console.log('  Error msg:  ' + e.message);
  } else {
    throw e;
  }
}

// Scenario B: Tampering the signed prekey signature directly
console.log('');
const sigTamperedBundle = JSON.parse(serverJson);
sigTamperedBundle.signedPreKey.signature =
  '00'.repeat(64); // all zeros instead of real signature

try {
  PreKeyBundle.fromPayload(sigTamperedBundle);
  console.log('⚠️  This should NEVER print');
} catch (e) {
  if (e instanceof SignatureError) {
    console.log('Signature-tampered bundle REJECTED ✅');
  }
}

// ════════════════════════════════════════════════════════════════════════
// 5. Lifecycle helpers
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('5. SignedPreKey lifecycle (rotate every 7 days)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

console.log('Current SPK age (ms):', bobSpk.ageMs());
console.log('Needs rotation now?: ', bobSpk.needsRotation());
console.log('Expired?:            ', bobSpk.isExpired());

// In your app: run this weekly
if (bobSpk.needsRotation()) {
  console.log('\n→ Time to rotate! Generate a new SPK with id =', bobSpk.id + 1);
}

console.log('\n🎉 Example complete!\n');
