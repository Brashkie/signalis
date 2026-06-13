/**
 * Session — Double Ratchet Session
 *
 * Manages the full encrypted-conversation state between two parties:
 *   - Root key (rotates on DH ratchet)
 *   - Sending chain (advances with each outgoing message)
 *   - Receiving chain (advances with each incoming message)
 *   - Skipped message keys cache (for out-of-order delivery)
 *
 * Created via `Session.initiateFromX3DH(...)` or `Session.receiveFromX3DH(...)`,
 * after which you just call `encrypt(plaintext)` and `decrypt(packet)`.
 *
 * @module session/session
 *
 * @example
 * ```ts
 * // Alice's side after X3DH:
 * const aliceSession = Session.initiateFromX3DH({
 *   sharedSecret: handshake.sharedSecret,
 *   theirIdentityKey: bobBundle.identityKey,
 *   theirSignedPreKeyPublic: bobBundle.signedPreKey.publicKey,
 * });
 *
 * const packet = aliceSession.encrypt(Buffer.from('Hola Bob'));
 *
 * // Bob's side:
 * const bobSession = Session.receiveFromX3DH({
 *   sharedSecret: x3dhResult.sharedSecret,
 *   myIdentityKey: bob.toPublic(),
 *   mySignedPreKeyPrivate: bobSpk.privateKey,
 *   mySignedPreKeyPublic: bobSpk.publicKey,
 *   theirIdentityKey: aliceIdentityPub,
 * });
 *
 * const plaintext = bobSession.decrypt(packet);  // → "Hola Bob"
 * ```
 */

import {
  generateKeyPair,
} from '../crypto';
import {
  advanceChainKey,
  encryptWithMessageKey,
  decryptWithMessageKey,
  MessageHeader,
  SkippedMessageKeys,
} from '../ratchet';
import type { PublicIdentityKey } from '../identity/identity-key';
import { PublicIdentityKey as PublicIdentityKeyClass } from '../identity/identity-key';
import type {
  RootKey,
  ChainKey,
  PublicKey,
  PrivateKey,
} from '../types';
import {
  asRootKey,
  asChainKey,
  asMessageKey,
  asPublicKey,
  asPrivateKey,
} from '../types';
import {
  ROOT_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  MAC_TRUNCATE_SIZE,
  MAX_SKIPPED_MESSAGE_KEYS,
} from '../constants';
import {
  ValidationError,
  SessionError,
  SerializationError,
} from '../errors';
import {
  dhRatchetStep,
  skipMessageKeys,
  tryRecoverSkippedKey,
} from './session-helpers';
import type {
  EncryptedMessage,
  SessionInitiateArgs,
  SessionReceiveArgs,
  SerializedSession,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// Session
// ═══════════════════════════════════════════════════════════════════════════

export class Session {
  // ─── Identity reference (read-only metadata) ─────────────────────────
  public readonly theirIdentityKey: PublicIdentityKey;

  // ─── Ratchet state ───────────────────────────────────────────────────
  private rootKey: RootKey;

  // Sending state
  private myCurrentDhPublic: PublicKey;
  private myCurrentDhPrivate: PrivateKey;
  private sendingChainKey: ChainKey | null;
  private sendingCounter: number;
  private previousSendingCounter: number;

  // Receiving state
  private receivingChainKey: ChainKey | null;
  private receivingCounter: number;
  private lastReceivedDhPublic: PublicKey | null;

  // Skipped keys cache (anti-DoS)
  private readonly skippedKeys: SkippedMessageKeys;

  /**
   * @internal — Use Session.initiateFromX3DH or Session.receiveFromX3DH
   */
  private constructor(args: {
    rootKey: RootKey;
    theirIdentityKey: PublicIdentityKey;
    myCurrentDhPublic: PublicKey;
    myCurrentDhPrivate: PrivateKey;
    sendingChainKey: ChainKey | null;
    sendingCounter: number;
    previousSendingCounter: number;
    receivingChainKey: ChainKey | null;
    receivingCounter: number;
    lastReceivedDhPublic: PublicKey | null;
    skippedKeys: SkippedMessageKeys;
  }) {
    this.rootKey = args.rootKey;
    this.theirIdentityKey = args.theirIdentityKey;
    this.myCurrentDhPublic = args.myCurrentDhPublic;
    this.myCurrentDhPrivate = args.myCurrentDhPrivate;
    this.sendingChainKey = args.sendingChainKey;
    this.sendingCounter = args.sendingCounter;
    this.previousSendingCounter = args.previousSendingCounter;
    this.receivingChainKey = args.receivingChainKey;
    this.receivingCounter = args.receivingCounter;
    this.lastReceivedDhPublic = args.lastReceivedDhPublic;
    this.skippedKeys = args.skippedKeys;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Factories
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Initiate a session as the SENDER (Alice).
   *
   * Alice generates her first ratchet DH pair and runs the first DH ratchet
   * step against Bob's signed prekey, deriving a sending chain.
   */
  public static initiateFromX3DH(args: SessionInitiateArgs): Session {
    if (!Buffer.isBuffer(args.sharedSecret) || args.sharedSecret.length !== ROOT_KEY_SIZE) {
      throw ValidationError.wrongSize(
        'sharedSecret',
        ROOT_KEY_SIZE,
        args.sharedSecret?.length ?? 0,
      );
    }
    if (!(args.theirIdentityKey instanceof PublicIdentityKeyClass)) {
      throw ValidationError.wrongType(
        'theirIdentityKey',
        'PublicIdentityKey',
        args.theirIdentityKey,
      );
    }
    if (!Buffer.isBuffer(args.theirSignedPreKeyPublic) ||
        args.theirSignedPreKeyPublic.length !== PUBLIC_KEY_SIZE) {
      throw ValidationError.wrongSize(
        'theirSignedPreKeyPublic',
        PUBLIC_KEY_SIZE,
        args.theirSignedPreKeyPublic?.length ?? 0,
      );
    }

    // Generate Alice's first ratchet DH pair
    const myFirstDh = generateKeyPair();

    // Run the FIRST DH ratchet step
    const firstStep = dhRatchetStep({
      currentRootKey: asRootKey(args.sharedSecret),
      myDhPrivate: asPrivateKey(myFirstDh.privateKey),
      theirDhPublic: asPublicKey(args.theirSignedPreKeyPublic),
    });

    return new Session({
      rootKey: firstStep.rootKey,
      theirIdentityKey: args.theirIdentityKey,
      myCurrentDhPublic: asPublicKey(myFirstDh.publicKey),
      myCurrentDhPrivate: asPrivateKey(myFirstDh.privateKey),
      sendingChainKey: firstStep.chainKey,
      sendingCounter: 0,
      previousSendingCounter: 0,
      receivingChainKey: null,
      receivingCounter: 0,
      lastReceivedDhPublic: null,
      skippedKeys: new SkippedMessageKeys(
        args.maxSkippedKeys ?? MAX_SKIPPED_MESSAGE_KEYS,
      ),
    });
  }

  /**
   * Receive a session as the RESPONDER (Bob).
   *
   * Bob seeds his state with the shared secret + his signed prekey as the
   * initial DH. His sending chain is empty until he calls encrypt() —
   * which generates a new ratchet DH pair and triggers a DH ratchet step.
   */
  public static receiveFromX3DH(args: SessionReceiveArgs): Session {
    if (!Buffer.isBuffer(args.sharedSecret) || args.sharedSecret.length !== ROOT_KEY_SIZE) {
      throw ValidationError.wrongSize(
        'sharedSecret',
        ROOT_KEY_SIZE,
        args.sharedSecret?.length ?? 0,
      );
    }
    if (!(args.myIdentityKey instanceof PublicIdentityKeyClass)) {
      throw ValidationError.wrongType('myIdentityKey', 'PublicIdentityKey', args.myIdentityKey);
    }
    if (!(args.theirIdentityKey instanceof PublicIdentityKeyClass)) {
      throw ValidationError.wrongType('theirIdentityKey', 'PublicIdentityKey', args.theirIdentityKey);
    }
    if (!Buffer.isBuffer(args.mySignedPreKeyPrivate) ||
        args.mySignedPreKeyPrivate.length !== PRIVATE_KEY_SIZE) {
      throw ValidationError.wrongSize(
        'mySignedPreKeyPrivate',
        PRIVATE_KEY_SIZE,
        args.mySignedPreKeyPrivate?.length ?? 0,
      );
    }
    if (!Buffer.isBuffer(args.mySignedPreKeyPublic) ||
        args.mySignedPreKeyPublic.length !== PUBLIC_KEY_SIZE) {
      throw ValidationError.wrongSize(
        'mySignedPreKeyPublic',
        PUBLIC_KEY_SIZE,
        args.mySignedPreKeyPublic?.length ?? 0,
      );
    }

    return new Session({
      rootKey: asRootKey(args.sharedSecret),
      theirIdentityKey: args.theirIdentityKey,
      myCurrentDhPublic: asPublicKey(args.mySignedPreKeyPublic),
      myCurrentDhPrivate: asPrivateKey(args.mySignedPreKeyPrivate),
      sendingChainKey: null,  // ← Bob doesn't have a sending chain yet
      sendingCounter: 0,
      previousSendingCounter: 0,
      receivingChainKey: null,  // ← seeded on first decrypt()
      receivingCounter: 0,
      lastReceivedDhPublic: null,
      skippedKeys: new SkippedMessageKeys(
        args.maxSkippedKeys ?? MAX_SKIPPED_MESSAGE_KEYS,
      ),
    });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // encrypt
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Encrypt a message under the current sending chain.
   *
   * If no sending chain exists yet (responder before first send), generates
   * a new DH pair and runs a DH ratchet step to seed one.
   */
  public encrypt(plaintext: Buffer): EncryptedMessage {
    if (!Buffer.isBuffer(plaintext)) {
      throw new ValidationError('Session.encrypt: plaintext must be a Buffer');
    }

    // Lazy-init sending chain if responder hasn't sent yet
    // (this happens when Bob calls encrypt before receiving anything,
    // OR when we haven't rotated yet)
    if (this.sendingChainKey === null) {
      this.rotateSendingChain();
    }

    // Advance the sending chain
    const step = advanceChainKey(this.sendingChainKey!, this.sendingCounter);

    // Build header
    const header = new MessageHeader({
      dhPublicKey: this.myCurrentDhPublic,
      n: this.sendingCounter,
      pn: this.previousSendingCounter,
    });

    // Encrypt
    const { ciphertext, mac } = encryptWithMessageKey(
      step.messageKey,
      plaintext,
      header.toBytes(),
    );

    // Advance state
    this.sendingChainKey = step.nextChainKey;
    this.sendingCounter++;

    return {
      header: header.toBytes().toString('hex'),
      ciphertext: ciphertext.toString('hex'),
      mac: mac.toString('hex'),
    };
  }

  /**
   * @internal Rotate the sending DH key + chain (called when needed).
   */
  private rotateSendingChain(): void {
    // Generate a new DH pair
    const newDh = generateKeyPair();

    // Save the old sending counter as `pn`
    this.previousSendingCounter = this.sendingCounter;

    // DH ratchet step against the last seen peer DH key
    // (if we haven't seen any yet, we use our current ratchet — this
    // shouldn't happen for a responder, but we handle it defensively)
    if (this.lastReceivedDhPublic === null) {
      throw new SessionError(
        'Session.encrypt: cannot send before receiving any messages (responder has no peer DH yet)',
        { sendingCounter: this.sendingCounter },
      );
    }

    const step = dhRatchetStep({
      currentRootKey: this.rootKey,
      myDhPrivate: asPrivateKey(newDh.privateKey),
      theirDhPublic: this.lastReceivedDhPublic,
    });

    this.rootKey = step.rootKey;
    this.myCurrentDhPublic = asPublicKey(newDh.publicKey);
    this.myCurrentDhPrivate = asPrivateKey(newDh.privateKey);
    this.sendingChainKey = step.chainKey;
    this.sendingCounter = 0;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // decrypt
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Decrypt a message packet.
   *
   * Handles:
   *   - Detecting a new DH key from the peer → runs DH ratchet step
   *   - Out-of-order messages via the skipped-keys cache
   *   - Replay detection (counter going backwards with no cached key)
   *
   * @throws {SessionError} On malformed packet, missing skipped key, etc.
   * @throws {SignatureError} On MAC verification failure
   */
  public decrypt(packet: EncryptedMessage): Buffer {
    if (
      packet === null ||
      typeof packet !== 'object' ||
      typeof packet.header !== 'string' ||
      typeof packet.ciphertext !== 'string' ||
      typeof packet.mac !== 'string'
    ) {
      throw new SerializationError(
        'Session.decrypt: packet must have { header, ciphertext, mac } as hex strings',
      );
    }

    // Parse header
    const headerBytes = Buffer.from(packet.header, 'hex');
    const header = MessageHeader.fromBytes(headerBytes);

    const ciphertext = Buffer.from(packet.ciphertext, 'hex');
    const mac = Buffer.from(packet.mac, 'hex');

    if (mac.length !== MAC_TRUNCATE_SIZE) {
      throw new ValidationError(
        `Session.decrypt: mac must be ${MAC_TRUNCATE_SIZE} bytes (got ${mac.length})`,
        { actual: mac.length, expected: MAC_TRUNCATE_SIZE },
      );
    }

    // ─── 1. Try the skipped-keys cache (out-of-order delivery) ────────
    const cachedMk = tryRecoverSkippedKey({
      cache: this.skippedKeys,
      theirDhPublic: asPublicKey(header.dhPublicKey),
      counter: header.n,
    });

    if (cachedMk !== null) {
      // Out-of-order message; decrypt with cached key
      return decryptWithMessageKey(
        cachedMk,
        ciphertext,
        mac,
        headerBytes,
      );
    }

    // ─── 2. Check if we need a DH ratchet step ────────────────────────
    if (
      this.lastReceivedDhPublic === null ||
      !this.lastReceivedDhPublic.equals(header.dhPublicKey)
    ) {
      // Peer rotated their DH key → ratchet on our side too.
      //
      // BEFORE rotating, if we have an active receiving chain, skip any
      // remaining messages from the previous chain (using header.pn).
      if (this.receivingChainKey !== null && this.lastReceivedDhPublic !== null) {
        skipMessageKeys({
          chainKey: this.receivingChainKey,
          startCounter: this.receivingCounter,
          untilCounter: header.pn,
          theirDhPublic: this.lastReceivedDhPublic,
          skippedCache: this.skippedKeys,
        });
      }

      // Perform the DH ratchet
      const step = dhRatchetStep({
        currentRootKey: this.rootKey,
        myDhPrivate: this.myCurrentDhPrivate,
        theirDhPublic: asPublicKey(header.dhPublicKey),
      });

      this.rootKey = step.rootKey;
      this.receivingChainKey = step.chainKey;
      this.receivingCounter = 0;
      this.lastReceivedDhPublic = asPublicKey(header.dhPublicKey);

      // Schedule our own DH rotation on next encrypt()
      this.sendingChainKey = null;
    }

    // ─── 3. Skip ahead in current chain if needed ─────────────────────
    if (header.n > this.receivingCounter) {
      const skip = skipMessageKeys({
        chainKey: this.receivingChainKey!,
        startCounter: this.receivingCounter,
        untilCounter: header.n,
        theirDhPublic: this.lastReceivedDhPublic!,
        skippedCache: this.skippedKeys,
      });
      this.receivingChainKey = skip.chainKeyAtTarget;
      this.receivingCounter = header.n;
    } else if (header.n < this.receivingCounter) {
      // Message is "in the past" but not in the skipped cache → replay or
      // already-decrypted message
      throw new SessionError(
        `Session.decrypt: message counter ${header.n} is in the past (expected >= ${this.receivingCounter}). Possible replay or already-decrypted message.`,
        { receivedN: header.n, expectedAtLeast: this.receivingCounter },
      );
    }

    // ─── 4. Advance the chain and decrypt ─────────────────────────────
    const step = advanceChainKey(this.receivingChainKey!, this.receivingCounter);

    const plaintext = decryptWithMessageKey(
      step.messageKey,
      ciphertext,
      mac,
      headerBytes,
    );

    this.receivingChainKey = step.nextChainKey;
    this.receivingCounter++;

    return plaintext;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Accessors (read-only diagnostics)
  // ═══════════════════════════════════════════════════════════════════════

  /** Current number of skipped message keys in cache */
  public skippedKeysCount(): number {
    return this.skippedKeys.size;
  }

  /** How many messages we've sent in the current sending chain */
  public sendingCounterValue(): number {
    return this.sendingCounter;
  }

  /** How many messages we've decrypted in the current receiving chain */
  public receivingCounterValue(): number {
    return this.receivingCounter;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Serialization
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Snapshot the entire session state for persistence.
   *
   * The result is JSON-safe but SECRET — encrypt at rest in production.
   */
  public serialize(): SerializedSession {
    return {
      version: 1,
      rootKey: this.rootKey.toString('hex'),
      theirIdentityKeyHex: this.theirIdentityKey.toHex(),

      myCurrentDhPublicHex: this.myCurrentDhPublic.toString('hex'),
      myCurrentDhPrivateHex: this.myCurrentDhPrivate.toString('hex'),
      sendingChainKey: this.sendingChainKey?.toString('hex') ?? null,
      sendingCounter: this.sendingCounter,
      previousSendingCounter: this.previousSendingCounter,

      receivingChainKey: this.receivingChainKey?.toString('hex') ?? null,
      receivingCounter: this.receivingCounter,
      lastReceivedDhPublicHex: this.lastReceivedDhPublic?.toString('hex') ?? null,

      skippedKeys: this.skippedKeys.entries().map((e) => ({
        dhPublicKeyHex: e.dhPublicKeyHex,
        counter: e.counter,
        messageKeyHex: e.messageKey.toString('hex'),
      })),
      maxSkippedKeys: this.skippedKeys.maxKeys,
    };
  }

  /**
   * Restore a session from a serialized snapshot.
   */
  public static deserialize(data: SerializedSession): Session {
    if (data === null || typeof data !== 'object') {
      throw new SerializationError('Session.deserialize: expected object');
    }
    if (data.version !== 1) {
      throw new SerializationError(
        `Session.deserialize: unsupported version ${data.version} (expected 1)`,
        { version: data.version },
      );
    }

    const HEX = /^[0-9a-fA-F]*$/;
    const fields: Array<[string, unknown]> = [
      ['rootKey', data.rootKey],
      ['theirIdentityKeyHex', data.theirIdentityKeyHex],
      ['myCurrentDhPublicHex', data.myCurrentDhPublicHex],
      ['myCurrentDhPrivateHex', data.myCurrentDhPrivateHex],
    ];
    for (const [name, val] of fields) {
      if (typeof val !== 'string' || !HEX.test(val)) {
        throw new SerializationError(
          `Session.deserialize: ${name} must be a hex string`,
        );
      }
    }

    const skippedCache = new SkippedMessageKeys(data.maxSkippedKeys);
    if (Array.isArray(data.skippedKeys)) {
      for (const entry of data.skippedKeys) {
        const dhBuf = Buffer.from(entry.dhPublicKeyHex, 'hex');
        const mkBuf = Buffer.from(entry.messageKeyHex, 'hex');
        skippedCache.set(
          asPublicKey(dhBuf),
          entry.counter,
          asMessageKey(mkBuf),
        );
      }
    }

    return new Session({
      rootKey: asRootKey(Buffer.from(data.rootKey, 'hex')),
      theirIdentityKey: PublicIdentityKeyClass.fromHex(data.theirIdentityKeyHex),

      myCurrentDhPublic: asPublicKey(Buffer.from(data.myCurrentDhPublicHex, 'hex')),
      myCurrentDhPrivate: asPrivateKey(Buffer.from(data.myCurrentDhPrivateHex, 'hex')),
      sendingChainKey: data.sendingChainKey
        ? asChainKey(Buffer.from(data.sendingChainKey, 'hex'))
        : null,
      sendingCounter: data.sendingCounter,
      previousSendingCounter: data.previousSendingCounter,

      receivingChainKey: data.receivingChainKey
        ? asChainKey(Buffer.from(data.receivingChainKey, 'hex'))
        : null,
      receivingCounter: data.receivingCounter,
      lastReceivedDhPublic: data.lastReceivedDhPublicHex
        ? asPublicKey(Buffer.from(data.lastReceivedDhPublicHex, 'hex'))
        : null,

      skippedKeys: skippedCache,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Safe output
  // ═══════════════════════════════════════════════════════════════════════

  public toString(): string {
    return (
      `Session(peer=${this.theirIdentityKey.shortFingerprint()}, ` +
      `sent=${this.sendingCounter}, recv=${this.receivingCounter}, ` +
      `skipped=${this.skippedKeys.size})`
    );
  }

  public toJSON(): { type: string; peer: string; sent: number; recv: number; skipped: number } {
    return {
      type: 'Session',
      peer: this.theirIdentityKey.shortFingerprint(),
      sent: this.sendingCounter,
      recv: this.receivingCounter,
      skipped: this.skippedKeys.size,
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type guard
// ═══════════════════════════════════════════════════════════════════════════

export function isSession(value: unknown): value is Session {
  return value instanceof Session;
}
