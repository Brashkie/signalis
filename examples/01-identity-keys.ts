/**
 * Example 01 — Identity Keys & Signatures
 * ════════════════════════════════════════════════════════════════════════
 *
 * The first thing every user needs: a long-term identity. Like the SSH key
 * on your laptop, except it can ALSO sign messages (XEd25519 signatures).
 *
 * Run with:
 *   npx tsx examples/01-identity-keys.ts
 *
 * Or compile and run:
 *   npx tsc examples/01-identity-keys.ts --outDir /tmp && node /tmp/01-identity-keys.js
 *
 * What this demonstrates:
 *   • Generating a Curve25519 + Ed25519 identity keypair
 *   • Signing arbitrary data
 *   • Verifying a signature using ONLY the public key
 *   • Detecting forged signatures
 *   • Safe serialization (private key never leaks via toString/JSON)
 *
 * Format: TypeScript ESM
 */

import {
  IdentityKeyPair,
  PublicIdentityKey,
  SignatureError,
} from '@brashkie/signalis';

// ════════════════════════════════════════════════════════════════════════
// 1. Generate an identity
// ════════════════════════════════════════════════════════════════════════

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('1. Generate Alice\'s identity');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const alice = IdentityKeyPair.generate();

console.log('Alice fingerprint (long): ', alice.fingerprint());
console.log('Alice fingerprint (short):', alice.shortFingerprint());
console.log('Alice safe toString:      ', alice.toString());
//                                       ↑ NEVER includes private key

// ════════════════════════════════════════════════════════════════════════
// 2. Sign a message
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('2. Sign and verify a message');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const message = Buffer.from('I authorize transferring $1,000 to Bob.');
const signature = alice.sign(message);

console.log('Message:        ', message.toString('utf-8'));
console.log('Signature bytes:', signature.length);
console.log('Signature (hex):', signature.toString('hex').slice(0, 32) + '...');

// ════════════════════════════════════════════════════════════════════════
// 3. Verify the signature using ONLY the public key
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('3. Verify using only Alice\'s PUBLIC key (e.g., on Bob\'s side)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const alicePub = alice.toPublic();

// In a real app, Bob got `alicePub.toHex()` over the network earlier
const alicePubHex = alicePub.toHex();
console.log('Alice public hex:', alicePubHex.slice(0, 32) + '...');

// Bob reconstructs the public key from the hex string
const aliceKeyOnBobSide = PublicIdentityKey.fromHex(alicePubHex);

// And verifies
const valid = aliceKeyOnBobSide.verifyBool(message, signature);
console.log('Signature valid:', valid, '←', valid ? '✅' : '❌');

// ════════════════════════════════════════════════════════════════════════
// 4. Detect a forged signature
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('4. Mallory tries to forge a signature');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Mallory has her own keypair but NOT Alice's private key
const mallory = IdentityKeyPair.generate();
const forgedSignature = mallory.sign(message);

const forgedValid = aliceKeyOnBobSide.verifyBool(message, forgedSignature);
console.log('Mallory\'s signature accepted as Alice\'s?', forgedValid, '←', forgedValid ? '⚠️' : '✅');

// The `verify` method (no -Bool suffix) throws an error instead of returning
try {
  aliceKeyOnBobSide.verify(message, forgedSignature);
} catch (e) {
  if (e instanceof SignatureError) {
    console.log('Verify threw SignatureError as expected ✅');
  }
}

// ════════════════════════════════════════════════════════════════════════
// 5. Tampering with the message also fails
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('5. Tampered message → signature no longer matches');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const tampered = Buffer.from('I authorize transferring $1,000,000 to Mallory.');
const tamperedValid = aliceKeyOnBobSide.verifyBool(tampered, signature);
console.log('Tampered message accepted?', tamperedValid, '←', tamperedValid ? '⚠️' : '✅');

// ════════════════════════════════════════════════════════════════════════
// 6. Persistence — serialize / deserialize
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('6. Persistence (always store private keys ENCRYPTED!)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Serialize includes the private key — only persist to encrypted storage
const serialized = alice.serialize();
console.log('Serialized keys:', Object.keys(serialized));

// Restore later (simulating app restart)
const aliceRestored = IdentityKeyPair.deserialize(serialized);

// Verify the restored key signs identically
const sig1 = alice.sign(message);
const sig2Restored = aliceRestored.sign(message);

// Note: XEd25519 signatures are randomized by default, so sig1 !== sig2.
// But both verify against the same public key:
console.log('Original key signs ok:  ', alicePub.verifyBool(message, sig1));
console.log('Restored key signs ok:  ', alicePub.verifyBool(message, sig2Restored));
console.log('Fingerprints match:     ',
  alice.fingerprint() === aliceRestored.fingerprint());

console.log('\n🎉 Example complete!\n');
