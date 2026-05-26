/**
 * Signalis Protocol Errors
 *
 * Hierarchy:
 *   SignalisError (base)
 *   ├── ValidationError       - Bad input (wrong size, type, etc.)
 *   ├── SignatureError        - Invalid signature
 *   ├── KeyError              - Key generation/manipulation failed
 *   ├── PreKeyError           - PreKey-specific issues
 *   ├── SerializationError    - Encoding/decoding failed
 *   ├── ProtocolError         - General protocol violation
 *   └── SessionError          - Session management issues
 *
 * All errors carry a `code` property for programmatic handling and
 * an optional `context` object for debugging.
 *
 * @module errors
 */

// ─── Error Codes ──────────────────────────────────────────────────────────
export const ErrorCode = {
  // Base
  SIGNALIS_ERROR: 'SIGNALIS_ERROR',

  // Validation
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_SIZE: 'INVALID_SIZE',
  INVALID_TYPE: 'INVALID_TYPE',
  INVALID_FORMAT: 'INVALID_FORMAT',

  // Crypto
  SIGNATURE_ERROR: 'SIGNATURE_ERROR',
  KEY_ERROR: 'KEY_ERROR',
  ENCRYPTION_ERROR: 'ENCRYPTION_ERROR',
  DECRYPTION_ERROR: 'DECRYPTION_ERROR',

  // PreKey
  PREKEY_ERROR: 'PREKEY_ERROR',
  PREKEY_NOT_FOUND: 'PREKEY_NOT_FOUND',
  PREKEY_EXPIRED: 'PREKEY_EXPIRED',
  PREKEY_ALREADY_USED: 'PREKEY_ALREADY_USED',

  // Serialization
  SERIALIZATION_ERROR: 'SERIALIZATION_ERROR',
  DESERIALIZATION_ERROR: 'DESERIALIZATION_ERROR',

  // Protocol
  PROTOCOL_ERROR: 'PROTOCOL_ERROR',
  UNSUPPORTED_VERSION: 'UNSUPPORTED_VERSION',

  // Session
  SESSION_ERROR: 'SESSION_ERROR',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
} as const;

export type ErrorCodeType = (typeof ErrorCode)[keyof typeof ErrorCode];

// ─── Base Error ───────────────────────────────────────────────────────────
/**
 * Base error class for all Signalis errors.
 *
 * @example
 * ```ts
 * try {
 *   somethingThatMightFail();
 * } catch (e) {
 *   if (e instanceof SignalisError) {
 *     console.log('Code:', e.code);
 *     console.log('Context:', e.context);
 *   }
 * }
 * ```
 */
export class SignalisError extends Error {
  public override readonly name: string = 'SignalisError';
  public readonly code: ErrorCodeType;
  public readonly context: Readonly<Record<string, unknown>>;

  constructor(
    message: string,
    code: ErrorCodeType = ErrorCode.SIGNALIS_ERROR,
    context: Record<string, unknown> = {},
  ) {
    super(message);
    this.code = code;
    this.context = Object.freeze({ ...context });
    Object.setPrototypeOf(this, new.target.prototype);

    // Capture stack trace (V8 only)
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, new.target);
    }
  }

  /**
   * Convert error to a serializable object (for logging).
   */
  public toJSON(): {
    name: string;
    message: string;
    code: ErrorCodeType;
    context: Record<string, unknown>;
  } {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      context: { ...this.context },
    };
  }
}

// ─── Validation Errors ────────────────────────────────────────────────────
export class ValidationError extends SignalisError {
  public override readonly name = 'ValidationError';

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message, ErrorCode.VALIDATION_ERROR, context);
    Object.setPrototypeOf(this, ValidationError.prototype);
  }

  /**
   * Create a "wrong size" validation error with context.
   */
  public static wrongSize(
    field: string,
    expected: number,
    actual: number,
  ): ValidationError {
    return new ValidationError(
      `${field}: expected ${expected} bytes, got ${actual}`,
      { field, expected, actual },
    );
  }

  /**
   * Create a "wrong type" validation error with context.
   */
  public static wrongType(
    field: string,
    expected: string,
    actual: unknown,
  ): ValidationError {
    const actualType = actual === null ? 'null' : typeof actual;
    return new ValidationError(
      `${field}: expected ${expected}, got ${actualType}`,
      { field, expected, actualType },
    );
  }
}

// ─── Signature Errors ─────────────────────────────────────────────────────
export class SignatureError extends SignalisError {
  public override readonly name = 'SignatureError';

  constructor(
    message: string = 'Signature verification failed',
    context: Record<string, unknown> = {},
  ) {
    super(message, ErrorCode.SIGNATURE_ERROR, context);
    Object.setPrototypeOf(this, SignatureError.prototype);
  }
}

// ─── Key Errors ───────────────────────────────────────────────────────────
export class KeyError extends SignalisError {
  public override readonly name = 'KeyError';

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message, ErrorCode.KEY_ERROR, context);
    Object.setPrototypeOf(this, KeyError.prototype);
  }
}

// ─── PreKey Errors ────────────────────────────────────────────────────────
export class PreKeyError extends SignalisError {
  public override readonly name = 'PreKeyError';

  constructor(
    message: string,
    code: ErrorCodeType = ErrorCode.PREKEY_ERROR,
    context: Record<string, unknown> = {},
  ) {
    super(message, code, context);
    Object.setPrototypeOf(this, PreKeyError.prototype);
  }

  public static notFound(id: number): PreKeyError {
    return new PreKeyError(`PreKey with ID ${id} not found`, ErrorCode.PREKEY_NOT_FOUND, {
      id,
    });
  }

  public static expired(id: number, age: number): PreKeyError {
    return new PreKeyError(
      `PreKey ${id} has expired (age: ${age}ms)`,
      ErrorCode.PREKEY_EXPIRED,
      { id, age },
    );
  }

  public static alreadyUsed(id: number): PreKeyError {
    return new PreKeyError(
      `PreKey ${id} has already been used`,
      ErrorCode.PREKEY_ALREADY_USED,
      { id },
    );
  }
}

// ─── Serialization Errors ─────────────────────────────────────────────────
export class SerializationError extends SignalisError {
  public override readonly name = 'SerializationError';

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message, ErrorCode.SERIALIZATION_ERROR, context);
    Object.setPrototypeOf(this, SerializationError.prototype);
  }
}

// ─── Protocol Errors ──────────────────────────────────────────────────────
export class ProtocolError extends SignalisError {
  public override readonly name = 'ProtocolError';

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message, ErrorCode.PROTOCOL_ERROR, context);
    Object.setPrototypeOf(this, ProtocolError.prototype);
  }

  public static unsupportedVersion(version: number): ProtocolError {
    return new ProtocolError(
      `Unsupported protocol version: ${version}`,
      { version },
    );
  }
}

// ─── Session Errors ───────────────────────────────────────────────────────
export class SessionError extends SignalisError {
  public override readonly name = 'SessionError';

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message, ErrorCode.SESSION_ERROR, context);
    Object.setPrototypeOf(this, SessionError.prototype);
  }
}
