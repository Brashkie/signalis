/**
 * Example 05 — Full Flow: X3DH + Double Ratchet End-to-End
 * ════════════════════════════════════════════════════════════════════════
 *
 * Putting EVERYTHING together. This is what a real messaging app's first
 * conversation between two users looks like:
 *
 *   1. Bob registers his prekey bundle on the server (offline preparation)
 *   2. Alice fetches Bob's bundle and runs X3DH → sharedSecret
 *   3. Alice uses sharedSecret to seed the Double Ratchet
 *   4. Alice encrypts her first message; Bob decrypts using same secret
 *   5. They exchange several messages, chain ratchet advancing each time
 *
 * Note: until v0.6.0 ships the `Session` class, we manage the ratchet
 * state manually here. v0.6.0 will reduce this whole example to ~5 lines.
 *
 * Run with:
 *   npx tsx examples/05-full-flow.ts
 *
 * Format: TypeScript ESM
 */

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
  deriveRootKey,
  advanceChainKey,
  encryptWithMessageKey,
  decryptWithMessageKey,
  MessageHeader,
  asRootKey,
  asPublicKey,
  asPrivateKey,
  crypto,
  type RootKey,
  type ChainKey,
} from '@brashkie/signalis';

// ════════════════════════════════════════════════════════════════════════
// PHASE 1 — Setup (registration, prekey publishing, etc.)
// ════════════════════════════════════════════════════════════════════════

console.log('═══════════════════════════════════════════════════════════════');
console.log('  PHASE 1: SETUP');
console.log('═══════════════════════════════════════════════════════════════\n');

// Bob registers and publishes his bundle to a server (months ago)
const bob = IdentityKeyPair.generate();
const bobSpk = SignedPreKey.generate(bob, 1);
const bobOpks = OneTimePreKey.generateBatch(1, 100);

const bobBundleOnServer = PreKeyBundle.build({
  registrationId: 4242,
  identityKey: bob.toPublic(),
  signedPreKey: bobSpk.toPublic(),
  oneTimePreKey: bobOpks[0].toPublic(),
}).toPayload();

console.log('✅ Bob registered, bundle on server');
console.log('   Fingerprint:', bob.shortFingerprint());

// ════════════════════════════════════════════════════════════════════════
// PHASE 2 — Alice initiates a session
// ════════════════════════════════════════════════════════════════════════

console.log('\n═══════════════════════════════════════════════════════════════');
console.log('  PHASE 2: ALICE INITIATES (X3DH)');
console.log('═══════════════════════════════════════════════════════════════\n');

const alice = IdentityKeyPair.generate();
console.log('Alice fingerprint:', alice.shortFingerprint());

// Alice fetches Bob's bundle (auto-verifies signature)
const bobBundle = PreKeyBundle.fromPayload(bobBundleOnServer);

// Alice runs X3DH → sharedSecret
const handshake = X3DH.initiate(alice, bobBundle, {
  myRegistrationId: 1234,
});

console.log('✅ X3DH complete on Alice\'s side');
console.log('   sharedSecret:', handshake.sharedSecret.toString('hex').slice(0, 32) + '...');

// ════════════════════════════════════════════════════════════════════════
// PHASE 3 — Both sides initialize the Double Ratchet
// ════════════════════════════════════════════════════════════════════════

console.log('\n═══════════════════════════════════════════════════════════════');
console.log('  PHASE 3: BOTH SIDES SEED THE DOUBLE RATCHET');
console.log('═══════════════════════════════════════════════════════════════\n');

// The X3DH sharedSecret becomes the initial root key for the Double Ratchet.
const initialRootKey: RootKey = asRootKey(handshake.sharedSecret);

// ─── Alice's side ─────────────────────────────────────────────────────
// As the initiator, Alice generates her first ratchet DH pair and does
// the FIRST DH ratchet step against Bob's signed prekey.
const aliceFirstDh = crypto.generateKeyPair();
const aliceFirstStep = deriveRootKey(
  initialRootKey,
  asPrivateKey(aliceFirstDh.privateKey),
  bobBundle.signedPreKey.publicKey, // Bob's signed-prekey public is the initial target
);

interface AliceState {
  rootKey: RootKey;
  sendingChainKey: ChainKey | null;
  sendingCounter: number;
  myCurrentDhPub: ReturnType<typeof asPublicKey>;
  myCurrentDhPriv: ReturnType<typeof asPrivateKey>;
  previousChainLength: number;
}

const aliceState: AliceState = {
  rootKey: aliceFirstStep.rootKey,
  sendingChainKey: aliceFirstStep.chainKey,
  sendingCounter: 0,
  myCurrentDhPub: asPublicKey(aliceFirstDh.publicKey),
  myCurrentDhPriv: asPrivateKey(aliceFirstDh.privateKey),
  previousChainLength: 0,
};

// ─── Bob's side ───────────────────────────────────────────────────────
// Bob waits for Alice's first message before running his first DH ratchet.
// He stores the initial root key + his signed prekey as the starting point.
interface BobState {
  rootKey: RootKey;
  receivingChainKey: ChainKey | null;
  receivingCounter: number;
  myCurrentDhPub: ReturnType<typeof asPublicKey>;
  myCurrentDhPriv: ReturnType<typeof asPrivateKey>;
  lastSeenTheirDh: ReturnType<typeof asPublicKey> | null;
}

const bobState: BobState = {
  rootKey: initialRootKey,
  receivingChainKey: null, // will be set when first message arrives
  receivingCounter: 0,
  myCurrentDhPub: bobSpk.publicKey,
  myCurrentDhPriv: bobSpk.privateKey,
  lastSeenTheirDh: null,
};

console.log('✅ Both sides ready');

// ════════════════════════════════════════════════════════════════════════
// PHASE 4 — Alice sends, Bob receives
// ════════════════════════════════════════════════════════════════════════

console.log('\n═══════════════════════════════════════════════════════════════');
console.log('  PHASE 4: EXCHANGE MESSAGES');
console.log('═══════════════════════════════════════════════════════════════\n');

// ─── Alice encrypts message #0 ─────────────────────────────────────────
function aliceEncrypt(plaintext: string) {
  const step = advanceChainKey(
    aliceState.sendingChainKey!,
    aliceState.sendingCounter,
  );

  const header = new MessageHeader({
    dhPublicKey: aliceState.myCurrentDhPub,
    n: aliceState.sendingCounter,
    pn: aliceState.previousChainLength,
  });

  const { ciphertext, mac } = encryptWithMessageKey(
    step.messageKey,
    Buffer.from(plaintext, 'utf-8'),
    header.toBytes(),
  );

  // Advance state
  aliceState.sendingChainKey = step.nextChainKey;
  aliceState.sendingCounter++;

  return { header, ciphertext, mac };
}

// ─── Bob decrypts ──────────────────────────────────────────────────────
function bobDecrypt(packet: ReturnType<typeof aliceEncrypt>): string {
  // Check if Alice's DH public key is new (would trigger a DH ratchet step)
  if (
    bobState.lastSeenTheirDh === null ||
    !bobState.lastSeenTheirDh.equals(packet.header.dhPublicKey)
  ) {
    const dhStep = deriveRootKey(
      bobState.rootKey,
      bobState.myCurrentDhPriv,
      asPublicKey(packet.header.dhPublicKey),
    );
    bobState.rootKey = dhStep.rootKey;
    bobState.receivingChainKey = dhStep.chainKey;
    bobState.receivingCounter = 0;
    bobState.lastSeenTheirDh = packet.header.dhPublicKey;
  }

  // Advance the receiving chain to match
  const step = advanceChainKey(
    bobState.receivingChainKey!,
    bobState.receivingCounter,
  );

  const plaintext = decryptWithMessageKey(
    step.messageKey,
    packet.ciphertext,
    packet.mac,
    packet.header.toBytes(),
  );

  bobState.receivingChainKey = step.nextChainKey;
  bobState.receivingCounter++;

  return plaintext.toString('utf-8');
}

// Send 3 messages
const messages = [
  'Hola Bob! Soy Alice.',
  '¿Recibís esto?',
  'Tengo algo importante que contarte.',
];

for (const msg of messages) {
  const packet = aliceEncrypt(msg);
  const decoded = bobDecrypt(packet);

  console.log(`Alice → "${msg}"`);
  console.log(`Bob   ← "${decoded}"`);
  console.log(`         (header n=${packet.header.n}, ` +
    `ciphertext ${packet.ciphertext.length}B, mac ${packet.mac.length}B)\n`);
}

console.log('✅ All 3 messages decrypted successfully');
console.log('✅ Each used a different MessageKey (chain ratchet advancing)');
console.log('✅ If Bob\'s device is stolen now, past messages cannot be recovered\n');

console.log('🎉 Example complete!\n');
console.log('In v0.6.0 (Sprint 3 Part 2), this whole flow becomes:');
console.log('  const aliceSession = Session.initiateFromX3DH(...);');
console.log('  const packet = aliceSession.encrypt(plaintext);');
console.log('  const decoded = bobSession.decrypt(packet);');
