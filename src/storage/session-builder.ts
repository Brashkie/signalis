/**
 * SessionBuilder — orchestrates X3DH + Session + StoreBundle.
 *
 * Reduces the per-message boilerplate to ~3 lines:
 *
 * ```ts
 * const builder = new SessionBuilder(stores);
 * const packet = await builder.encrypt(bobAddress, Buffer.from('Hello'));
 * await builder.decrypt(aliceAddress, packet);
 * ```
 *
 * Handles:
 *  - Loading the existing session if any
 *  - Initiating from X3DH if no session exists
 *  - Saving the updated session after each encrypt/decrypt
 *  - Updating trusted-identity records (TOFU + change detection)
 *
 * @module storage/session-builder
 */

import { X3DH, type InitialMessagePayload } from '../x3dh';
import { Session, type EncryptedMessage } from '../session';
import { PublicIdentityKey } from '../identity/identity-key';
import type { PreKeyBundle } from '../prekeys/prekey-bundle';
import type { ProtocolAddress } from '../address';
import type { StoreBundle } from './bundle';
import { SessionError, ValidationError } from '../errors';

// ═══════════════════════════════════════════════════════════════════════════
// Wire packet for "first message" — includes X3DH InitialMessage
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The format sent by Alice the FIRST time she messages Bob (no session yet).
 *
 * It bundles the X3DH `InitialMessage` payload (so Bob can derive the same
 * shared secret) PLUS the first encrypted ratchet message.
 */
export interface InitialMessageWithPayload {
  readonly type: 'prekey';
  readonly initialMessage: InitialMessagePayload;
  readonly packet: EncryptedMessage;
}

/**
 * Subsequent messages (session already exists on both sides).
 */
export interface RegularMessage {
  readonly type: 'whisper';
  readonly packet: EncryptedMessage;
}

/**
 * Discriminated union representing any over-the-wire message.
 */
export type WireMessage = InitialMessageWithPayload | RegularMessage;

// ═══════════════════════════════════════════════════════════════════════════
// SessionBuilder
// ═══════════════════════════════════════════════════════════════════════════

export class SessionBuilder {
  constructor(public readonly stores: StoreBundle) {
    if (!stores) {
      throw new ValidationError('SessionBuilder: stores is required');
    }
  }

  // ─── ENCRYPT side ───────────────────────────────────────────────────

  /**
   * Encrypt a message to `recipient`.
   *
   * - If a session exists, encrypts and returns a `RegularMessage`.
   * - If no session exists, requires a `bundle` to initiate via X3DH
   *   and returns an `InitialMessageWithPayload`.
   *
   * @throws {SessionError} if no session and no bundle provided.
   */
  public async encrypt(
    recipient: ProtocolAddress,
    plaintext: Buffer,
    bundle?: PreKeyBundle,
  ): Promise<WireMessage> {
    if (!Buffer.isBuffer(plaintext)) {
      throw new ValidationError('SessionBuilder.encrypt: plaintext must be a Buffer');
    }

    let session = await this.stores.sessions.loadSession(recipient);

    // ─── First-time send: need bundle to initiate X3DH ───────────────
    if (session === null) {
      if (bundle === undefined) {
        throw new SessionError(
          `SessionBuilder.encrypt: no existing session for ${recipient.toString()} ` +
          `and no PreKeyBundle provided. Pass a bundle to initiate a new session.`,
          { recipient: recipient.toString() },
        );
      }

      const myIdentity = await this.stores.identity.getIdentityKeyPair();
      if (myIdentity === null) {
        throw new SessionError(
          'SessionBuilder.encrypt: own identity not registered. ' +
          'Call identityStore.saveIdentityKeyPair() first.',
        );
      }

      const myRegId = await this.stores.identity.getRegistrationId();
      if (myRegId === null) {
        throw new SessionError(
          'SessionBuilder.encrypt: own registrationId not set. ' +
          'Call identityStore.saveRegistrationId() first.',
        );
      }

      // TOFU / change-detection check on Bob's identity key
      const trusted = await this.stores.identity.isTrustedIdentity(
        recipient,
        bundle.identityKey,
      );
      if (!trusted) {
        throw new SessionError(
          `SessionBuilder.encrypt: identity for ${recipient.toString()} has changed ` +
          `from the previously trusted value. Possible MITM or peer re-registered. ` +
          `Call identityStore.saveTrustedIdentity() to accept the new key.`,
          { recipient: recipient.toString() },
        );
      }
      await this.stores.identity.saveTrustedIdentity(recipient, bundle.identityKey);

      // Run X3DH
      const handshake = X3DH.initiate(myIdentity, bundle, {
        myRegistrationId: myRegId,
      });

      // Create session
      session = Session.initiateFromX3DH({
        sharedSecret: handshake.sharedSecret,
        theirIdentityKey: bundle.identityKey,
        theirSignedPreKeyPublic: bundle.signedPreKey.publicKey,
      });

      // Encrypt the first message
      const packet = session.encrypt(plaintext);
      await this.stores.sessions.saveSession(recipient, session);

      return {
        type: 'prekey',
        // handshake.initialMessage is already an InitialMessagePayload
        // (X3DH.initiate returns the wire format directly)
        initialMessage: handshake.initialMessage,
        packet,
      };
    }

    // ─── Subsequent send: just encrypt with existing session ─────────
    const packet = session.encrypt(plaintext);
    await this.stores.sessions.saveSession(recipient, session);
    return { type: 'whisper', packet };
  }

  // ─── DECRYPT side ───────────────────────────────────────────────────

  /**
   * Decrypt a message from `sender`.
   *
   * - For `type: 'prekey'` (first-time receive), runs X3DH-receive,
   *   creates a new session, decrypts, persists.
   * - For `type: 'whisper'` (subsequent), loads existing session and
   *   decrypts.
   *
   * @throws {SessionError} for malformed packets, missing sessions, etc.
   */
  public async decrypt(sender: ProtocolAddress, message: WireMessage): Promise<Buffer> {
    if (
      message === null ||
      typeof message !== 'object' ||
      (message.type !== 'prekey' && message.type !== 'whisper')
    ) {
      throw new ValidationError(
        'SessionBuilder.decrypt: message must be { type: "prekey" | "whisper", ... }',
      );
    }

    if (message.type === 'prekey') {
      return this.decryptPreKey(sender, message);
    }

    // type === 'whisper'
    const session = await this.stores.sessions.loadSession(sender);
    if (session === null) {
      throw new SessionError(
        `SessionBuilder.decrypt: no session for ${sender.toString()}, ` +
        `but received non-prekey message. Sender may need to re-establish session.`,
        { sender: sender.toString() },
      );
    }
    const plaintext = session.decrypt(message.packet);
    await this.stores.sessions.saveSession(sender, session);
    return plaintext;
  }

  /**
   * @internal Decrypt a first-time message (with X3DH bootstrap).
   */
  private async decryptPreKey(
    sender: ProtocolAddress,
    message: InitialMessageWithPayload,
  ): Promise<Buffer> {
    const myIdentity = await this.stores.identity.getIdentityKeyPair();
    if (myIdentity === null) {
      throw new SessionError('SessionBuilder.decrypt: own identity not registered.');
    }

    // The payload is already in wire format; we don't need to parse into
    // an InitialMessage class instance — X3DH.receive accepts payloads.
    const payload = message.initialMessage;
    const signedPreKeyId = payload.signedPreKeyId;
    const oneTimePreKeyId =
      payload.oneTimePreKeyId === undefined ? null : payload.oneTimePreKeyId;

    // Look up the signed prekey by id
    const signedPreKey = await this.stores.signedPreKeys.getSignedPreKey(signedPreKeyId);
    if (signedPreKey === null) {
      throw new SessionError(
        `SessionBuilder.decrypt: signed prekey id=${signedPreKeyId} not found. ` +
        `This message is too old or the signed prekey was rotated.`,
        { signedPreKeyId },
      );
    }

    // Look up the one-time prekey, if used
    let oneTimePreKey = null;
    if (oneTimePreKeyId !== null) {
      oneTimePreKey = await this.stores.preKeys.getPreKey(oneTimePreKeyId);
      if (oneTimePreKey === null) {
        throw new SessionError(
          `SessionBuilder.decrypt: one-time prekey id=${oneTimePreKeyId} not found. ` +
          `Either already used (replay attempt!) or never existed.`,
          { oneTimePreKeyId },
        );
      }
    }

    // Reconstruct Alice's public identity from the hex on the wire
    const aliceIdentity = PublicIdentityKey.fromHex(payload.identityKey);

    // TOFU / change-detection on Alice's identity key
    const trusted = await this.stores.identity.isTrustedIdentity(sender, aliceIdentity);
    if (!trusted) {
      throw new SessionError(
        `SessionBuilder.decrypt: identity for ${sender.toString()} has changed ` +
        `from previously trusted value.`,
        { sender: sender.toString() },
      );
    }
    await this.stores.identity.saveTrustedIdentity(sender, aliceIdentity);

    // Run X3DH receive (accepts payload directly)
    const result = X3DH.receive(myIdentity, signedPreKey, oneTimePreKey, payload);

    // Create session
    const session = Session.receiveFromX3DH({
      sharedSecret: result.sharedSecret,
      myIdentityKey: myIdentity.toPublic(),
      mySignedPreKeyPrivate: signedPreKey.privateKey,
      mySignedPreKeyPublic: signedPreKey.publicKey,
      theirIdentityKey: aliceIdentity,
    });

    // Decrypt the first message
    const plaintext = session.decrypt(message.packet);
    await this.stores.sessions.saveSession(sender, session);

    // CRITICAL: delete the one-time prekey now that it's been used
    if (oneTimePreKeyId !== null) {
      await this.stores.preKeys.removePreKey(oneTimePreKeyId);
    }

    return plaintext;
  }

  // ─── Convenience ────────────────────────────────────────────────────

  /**
   * Delete the session with `peer`. Future messages will require a fresh
   * X3DH handshake.
   *
   * Common UI: "Reset secure session" / "Verify safety number" flow.
   */
  public async resetSession(peer: ProtocolAddress): Promise<void> {
    await this.stores.sessions.deleteSession(peer);
  }
}
