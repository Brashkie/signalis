/**
 * X3DH Coverage Sweep
 *
 * Targets the last uncovered lines:
 *   - initial-message.ts 273-274: Symbol.for('nodejs.util.inspect.custom')
 *   - shared-secret.ts 152: defensive DH-length check (unreachable with Curve25519)
 *
 * The shared-secret.ts branch is unreachable in practice — Curve25519 ECDH
 * always returns 32 bytes — so we already marked it with `c8 ignore`. This
 * file just adds the missing inspect() coverage.
 */

import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';

import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  X3DH,
  InitialMessage,
} from '../src';

describe('Coverage: X3DH module final sweep', () => {
  it('InitialMessage inspect via util.inspect() returns safe representation', () => {
    const alice = IdentityKeyPair.generate();
    const msg = new InitialMessage({
      identityKey: alice.toPublic(),
      ephemeralKey: Buffer.alloc(32),
      signedPreKeyId: 1,
      oneTimePreKeyId: 42,
      registrationId: 100,
      deviceId: 1,
    });

    const inspected = inspect(msg);
    expect(inspected).toMatch(/InitialMessage\(from=100\.1, spk=1, otpk=42\)/);
  });

  it('InitialMessage inspect via util.inspect() without OPK', () => {
    const alice = IdentityKeyPair.generate();
    const msg = new InitialMessage({
      identityKey: alice.toPublic(),
      ephemeralKey: Buffer.alloc(32),
      signedPreKeyId: 1,
      registrationId: 100,
      deviceId: 1,
    });

    const inspected = inspect(msg);
    expect(inspected).toMatch(/InitialMessage\(from=100\.1, spk=1\)/);
    expect(inspected).not.toContain('otpk');
  });

  it('full E2E from package root (sanity)', () => {
    // Final integration sanity — make sure the public API surface from
    // '@brashkie/signalis' (src/index.ts) works end-to-end.
    const alice = IdentityKeyPair.generate();
    const bob = IdentityKeyPair.generate();
    const bobSpk = SignedPreKey.generate(bob, 1);
    const bobOpk = OneTimePreKey.generate(100);

    const bundle = PreKeyBundle.build({
      registrationId: 6789,
      identityKey: bob.toPublic(),
      signedPreKey: bobSpk.toPublic(),
      oneTimePreKey: bobOpk.toPublic(),
    });

    const aliceResult = X3DH.initiate(alice, bundle, {
      myRegistrationId: 12345,
    });

    const bobResult = X3DH.receive(bob, bobSpk, bobOpk, aliceResult.initialMessage);

    // The whole flow works through the public package entry point
    expect(aliceResult.sharedSecret.equals(bobResult.sharedSecret)).toBe(true);
    expect(aliceResult.sharedSecret.length).toBe(32);
  });
});
