/**
 * Example 04 — Double Ratchet Primitives (Manual Encrypt/Decrypt)
 * ════════════════════════════════════════════════════════════════════════
 *
 * The v0.5.0 ratchet primitives — exactly what Signal/WhatsApp use for
 * EVERY message in a conversation. Each message has a unique key derived
 * from a one-way chain. If someone steals the current state, they CAN'T
 * decrypt past messages (forward secrecy).
 *
 * This example uses the low-level primitives directly. In v0.6.0 we'll
 * wrap all this in a high-level `Session` class so you write:
 *   session.encrypt(plaintext)
 *   session.decrypt(packet)
 *
 * Run with:
 *   node examples/04-ratchet-encrypt.js
 *
 * What this demonstrates:
 *   • Symmetric ratchet (chain key advancing)
 *   • Message key derivation
 *   • AES-256-CBC + HMAC-SHA256 encrypt-then-MAC
 *   • Forward secrecy in action (old keys are unrecoverable)
 *   • Tampering detection
 *
 * Format: CommonJS JavaScript (require)
 */

const {
  // Symmetric ratchet
  advanceChainKey,
  // Message encryption
  encryptWithMessageKey,
  decryptWithMessageKey,
  expandMessageKey,
  // Constants
  CHAIN_KEY_SIZE,
  // Errors
  SignatureError,
  // For seeding (in real apps, this comes from X3DH's sharedSecret)
  crypto,
} = require('@brashkie/signalis');

// Note: in a real app you'd use the `Session` class (v0.6.0) which handles
// all the chain state for you. We're showing the primitives here for
// educational purposes.

// ════════════════════════════════════════════════════════════════════════
// 1. Set up a chain key (in real app: comes from X3DH + DH ratchet)
// ════════════════════════════════════════════════════════════════════════

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('1. Initial chain key (would come from X3DH in real app)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Random initial chain key (this is JUST for the demo — real chain keys
// come from deriveRootKey() seeded by X3DH's sharedSecret)
const chainKey = crypto.randomBytes(CHAIN_KEY_SIZE);

console.log('Initial chain key:', chainKey.toString('hex').slice(0, 32) + '...');
console.log('Length:', chainKey.length, 'bytes');

// ════════════════════════════════════════════════════════════════════════
// 2. Alice sends 3 messages, advancing the chain each time
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('2. Alice encrypts 3 messages (advancing chain each time)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const messages = [
  'Hola Bob!',
  '¿Cómo estás?',
  'Te escribo desde Lima.',
];

// We need to remember the encrypted output to decrypt later
const wire = [];

// Alice and Bob both track the chain key. Alice uses it to derive each
// message key, then advances. Bob does the same on his side.
let aliceCk = chainKey;

for (let n = 0; n < messages.length; n++) {
  // Advance the chain — get a fresh message key for THIS message
  const step = advanceChainKey(aliceCk, n);
  const messageKey = step.messageKey;

  // Build associated data (in real app: this would be the MessageHeader)
  const associatedData = Buffer.from(`msg-${n}`);

  // Encrypt
  const { ciphertext, mac } = encryptWithMessageKey(
    messageKey,
    Buffer.from(messages[n]),
    associatedData,
  );

  wire.push({ n, ciphertext, mac, associatedData });

  console.log(`Msg #${n}: "${messages[n]}"`);
  console.log(`        ciphertext: ${ciphertext.toString('hex').slice(0, 32)}... (${ciphertext.length} bytes)`);
  console.log(`        mac (8B):   ${mac.toString('hex')}`);

  // Forget the message key (forward secrecy!) and advance the chain
  aliceCk = step.nextChainKey;
}

// ════════════════════════════════════════════════════════════════════════
// 3. Bob receives and decrypts
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('3. Bob decrypts each message in order');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Bob has the same initial chain key (derived independently via X3DH)
let bobCk = chainKey;

for (const packet of wire) {
  // Bob also advances his chain to derive the matching message key
  const step = advanceChainKey(bobCk, packet.n);

  const plaintext = decryptWithMessageKey(
    step.messageKey,
    packet.ciphertext,
    packet.mac,
    packet.associatedData,
  );

  console.log(`Msg #${packet.n} decrypted: "${plaintext.toString('utf-8')}"`);

  bobCk = step.nextChainKey;
}

// ════════════════════════════════════════════════════════════════════════
// 4. Forward Secrecy in action
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('4. Forward Secrecy: old chain keys cannot decrypt new messages');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// At this point bobCk is the chain key AFTER msg #2.
// Can we use it to decrypt msg #0? Let's try.
const wrongStep = advanceChainKey(bobCk, 0); // pretend it's still msg 0

try {
  decryptWithMessageKey(
    wrongStep.messageKey,
    wire[0].ciphertext,
    wire[0].mac,
    wire[0].associatedData,
  );
  console.log('⚠️  This should NEVER print');
} catch (e) {
  if (e instanceof SignatureError) {
    console.log('Old chain key CANNOT decrypt past message ✅');
    console.log('  → MAC verification failed (expected: chain advanced)');
  }
}

// ════════════════════════════════════════════════════════════════════════
// 5. Tampering detection
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('5. Tampering with ciphertext is detected');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Reset Bob's chain
bobCk = chainKey;
const step0 = advanceChainKey(bobCk, 0);

// Flip a single byte in the ciphertext
const tamperedCt = Buffer.from(wire[0].ciphertext);
tamperedCt[0] ^= 0xff;

try {
  decryptWithMessageKey(
    step0.messageKey,
    tamperedCt,
    wire[0].mac,
    wire[0].associatedData,
  );
  console.log('⚠️  This should NEVER print');
} catch (e) {
  if (e instanceof SignatureError) {
    console.log('Tampered ciphertext REJECTED ✅');
    console.log('  → MAC verification caught the bit flip');
  }
}

// ════════════════════════════════════════════════════════════════════════
// 6. What's inside the MessageKey
// ════════════════════════════════════════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('6. expandMessageKey — peek inside the encryption material');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const sampleMk = advanceChainKey(chainKey, 0).messageKey;
const expanded = expandMessageKey(sampleMk);

console.log('MessageKey seed (32 bytes) → HKDF expand → 80 bytes:');
console.log('  AES-256 key:', expanded.aesKey.toString('hex').slice(0, 32) + '...', `(${expanded.aesKey.length} bytes)`);
console.log('  HMAC key:   ', expanded.hmacKey.toString('hex').slice(0, 32) + '...', `(${expanded.hmacKey.length} bytes)`);
console.log('  AES-CBC IV: ', expanded.iv.toString('hex'), `(${expanded.iv.length} bytes)`);

console.log('\n🎉 Example complete!\n');
console.log('Note: the v0.6.0 Session class will hide all this state-keeping.');
console.log('You\'ll just call session.encrypt(msg) and session.decrypt(packet).');
