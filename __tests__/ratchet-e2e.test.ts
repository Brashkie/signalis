/**
 * E2E test: simulate a manual session using only the ratchet primitives.
 *
 * This proves the primitives compose correctly — Alice and Bob can exchange
 * encrypted messages, with the DH ratchet rotating as Bob responds.
 *
 * The full `Session` class arrives in v0.6.0 (Sprint 3 Part 2); this test
 * verifies the underlying machinery works.
 */

import { describe, it, expect } from 'vitest';

import {
  deriveRootKey,
  advanceChainKey,
  encryptWithMessageKey,
  decryptWithMessageKey,
  MessageHeader,
  ROOT_KEY_SIZE,
  crypto,
} from '../src';
import {
  asPublicKey,
  asPrivateKey,
  asRootKey,
} from '../src/types';

// ═══════════════════════════════════════════════════════════════════════════
// Helpers — minimal "manual session" state
// ═══════════════════════════════════════════════════════════════════════════

function freshDh() {
  const kp = crypto.generateKeyPair();
  return { pub: asPublicKey(kp.publicKey), priv: asPrivateKey(kp.privateKey) };
}

// ═══════════════════════════════════════════════════════════════════════════
// E2E test
// ═══════════════════════════════════════════════════════════════════════════

describe('Ratchet E2E (manual session via primitives)', () => {
  it('Alice and Bob exchange messages across DH ratchet rotation', () => {
    // ─── Initial setup ────────────────────────────────────────────────
    // Both sides start with the same initial root key (in v0.6.0 this
    // will come from X3DH's sharedSecret).
    const initialRk = asRootKey(crypto.randomBytes(ROOT_KEY_SIZE));

    // Alice generates her FIRST ratchet DH pair.
    // Bob has a "current" DH pair which Alice already knows (e.g., from
    // Bob's SignedPreKey via X3DH — but for this test we keep it simple).
    const aliceDh0 = freshDh();
    const bobDh0 = freshDh();

    // Alice runs the FIRST DH ratchet step on her side.
    // (Spec: the initiator does an extra ratchet step at setup to get a
    // sending chain seeded.)
    const aliceFirstStep = deriveRootKey(initialRk, aliceDh0.priv, bobDh0.pub);
    let aliceRootKey = aliceFirstStep.rootKey;
    let aliceSendingCk: Buffer | null = aliceFirstStep.chainKey;
    let aliceCounter = 0;
    const aliceCurrentDh = aliceDh0;

    // Bob doesn't ratchet yet — he waits for Alice's first message.
    let bobRootKey = initialRk;
    let bobReceivingCk: Buffer | null = null;
    const bobCurrentDh = bobDh0;
    let bobLastSeenAliceDh: ReturnType<typeof asPublicKey> | null = null;

    // ─── Alice sends msg #0 ───────────────────────────────────────────
    const ckAdv0 = advanceChainKey(aliceSendingCk!, aliceCounter);
    aliceSendingCk = ckAdv0.nextChainKey;
    const header0 = new MessageHeader({
      dhPublicKey: aliceCurrentDh.pub,
      n: aliceCounter,
      pn: 0,
    });
    const enc0 = encryptWithMessageKey(
      ckAdv0.messageKey,
      Buffer.from('Hola Bob, soy Alice'),
      header0.toBytes(),
    );
    aliceCounter++;

    // ─── Bob receives msg #0 ──────────────────────────────────────────
    const receivedHeader = header0;
    expect(receivedHeader.dhPublicKey.equals(aliceCurrentDh.pub)).toBe(true);

    // Bob's first DH ratchet step (using Alice's DH from the header)
    if (
      bobLastSeenAliceDh === null ||
      !bobLastSeenAliceDh.equals(receivedHeader.dhPublicKey)
    ) {
      const bobStep = deriveRootKey(
        bobRootKey,
        bobCurrentDh.priv,
        asPublicKey(receivedHeader.dhPublicKey),
      );
      bobRootKey = bobStep.rootKey;
      bobReceivingCk = bobStep.chainKey;
      bobLastSeenAliceDh = receivedHeader.dhPublicKey;
    }

    // Now advance the receiving chain and decrypt
    const bobCkAdv = advanceChainKey(bobReceivingCk!, 0);
    bobReceivingCk = bobCkAdv.nextChainKey;
    const decrypted0 = decryptWithMessageKey(
      bobCkAdv.messageKey,
      enc0.ciphertext,
      enc0.mac,
      receivedHeader.toBytes(),
    );

    expect(decrypted0.toString('utf-8')).toBe('Hola Bob, soy Alice');

    // ─── Alice sends msg #1 (same chain) ──────────────────────────────
    const ckAdv1 = advanceChainKey(aliceSendingCk, aliceCounter);
    aliceSendingCk = ckAdv1.nextChainKey;
    const header1 = new MessageHeader({
      dhPublicKey: aliceCurrentDh.pub,
      n: aliceCounter,
      pn: 0,
    });
    const enc1 = encryptWithMessageKey(
      ckAdv1.messageKey,
      Buffer.from('Como estas?'),
      header1.toBytes(),
    );
    aliceCounter++;

    // Bob receives msg #1 — no DH ratchet (same DH key)
    expect(header1.dhPublicKey.equals(bobLastSeenAliceDh)).toBe(true);
    const bobCkAdv1 = advanceChainKey(bobReceivingCk!, 1);
    bobReceivingCk = bobCkAdv1.nextChainKey;
    const decrypted1 = decryptWithMessageKey(
      bobCkAdv1.messageKey,
      enc1.ciphertext,
      enc1.mac,
      header1.toBytes(),
    );
    expect(decrypted1.toString('utf-8')).toBe('Como estas?');

    // ─── Bob responds → DH ratchet rotation ───────────────────────────
    // Bob generates a NEW DH pair, runs DH ratchet step to derive a
    // new RK + sending chain.
    const bobNewDh = freshDh();
    const bobStep2 = deriveRootKey(
      bobRootKey,
      bobNewDh.priv,
      aliceCurrentDh.pub,
    );
    bobRootKey = bobStep2.rootKey;
    let bobSendingCk: Buffer | null = bobStep2.chainKey;
    const bobCounter = 0;
    const bobPnPrevious = 2; // bob received 2 messages from Alice on prev chain

    const bobCkSendAdv = advanceChainKey(bobSendingCk, bobCounter);
    bobSendingCk = bobCkSendAdv.nextChainKey;
    const bobHeader = new MessageHeader({
      dhPublicKey: bobNewDh.pub,
      n: bobCounter,
      pn: bobPnPrevious,
    });
    const bobEnc = encryptWithMessageKey(
      bobCkSendAdv.messageKey,
      Buffer.from('Hola Alice, todo bien'),
      bobHeader.toBytes(),
    );

    // ─── Alice receives Bob's response → her DH ratchet ───────────────
    // Alice sees a NEW DH key from Bob → runs DH ratchet step
    const aliceStep2 = deriveRootKey(
      aliceRootKey,
      aliceCurrentDh.priv,
      bobHeader.dhPublicKey,
    );
    aliceRootKey = aliceStep2.rootKey;
    let aliceReceivingCk: Buffer | null = aliceStep2.chainKey;

    // Critical check: both sides have the SAME root key after rotation
    expect(aliceRootKey.equals(bobRootKey)).toBe(true);

    const aliceRecvAdv = advanceChainKey(aliceReceivingCk, 0);
    aliceReceivingCk = aliceRecvAdv.nextChainKey;
    const decryptedReply = decryptWithMessageKey(
      aliceRecvAdv.messageKey,
      bobEnc.ciphertext,
      bobEnc.mac,
      bobHeader.toBytes(),
    );

    expect(decryptedReply.toString('utf-8')).toBe('Hola Alice, todo bien');

    // ─── Final assertions ─────────────────────────────────────────────
    // Both sides ratcheted, both rotated root keys, all 3 messages decrypted.
    expect(aliceRootKey.equals(initialRk)).toBe(false); // root key has moved
    expect(bobRootKey.equals(initialRk)).toBe(false);
    expect(aliceRootKey.equals(aliceFirstStep.rootKey)).toBe(false); // rotated again
  });

  it('demonstrates forward secrecy: old message keys are gone', () => {
    const initialRk = asRootKey(crypto.randomBytes(ROOT_KEY_SIZE));
    const aliceDh = freshDh();
    const bobDh = freshDh();

    const step1 = deriveRootKey(initialRk, aliceDh.priv, bobDh.pub);
    let ck: Buffer | null = step1.chainKey;

    // Derive message key for n=0, then "forget" it
    const adv0 = advanceChainKey(ck!, 0);
    ck = adv0.nextChainKey;

    // Advance further
    const adv1 = advanceChainKey(ck, 1);
    ck = adv1.nextChainKey;

    // We cannot reconstruct adv0.messageKey from current ck alone — the
    // HMAC is one-way. (We'd need ck at step 0, which we destroyed.)
    // Proof: derive a fresh key from current ck — it's NOT adv0.messageKey
    const tryAgain = advanceChainKey(ck, 0);
    expect(tryAgain.messageKey.equals(adv0.messageKey)).toBe(false);
  });
});
