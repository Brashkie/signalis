import { describe, it, expect } from 'vitest';
import {
  SignalisError,
  ValidationError,
  SignatureError,
  KeyError,
  PreKeyError,
  SerializationError,
  ProtocolError,
  SessionError,
  ErrorCode,
} from '../src/errors';

describe('Errors', () => {
  describe('SignalisError (base)', () => {
    it('creates with message and default code', () => {
      const err = new SignalisError('test');
      expect(err.message).toBe('test');
      expect(err.code).toBe(ErrorCode.SIGNALIS_ERROR);
      expect(err.name).toBe('SignalisError');
    });

    it('creates with custom code and context', () => {
      const err = new SignalisError('test', ErrorCode.KEY_ERROR, { foo: 'bar' });
      expect(err.code).toBe(ErrorCode.KEY_ERROR);
      expect(err.context).toEqual({ foo: 'bar' });
    });

    it('context is frozen', () => {
      const err = new SignalisError('test', ErrorCode.SIGNALIS_ERROR, { foo: 'bar' });
      expect(Object.isFrozen(err.context)).toBe(true);
    });

    it('is instanceof Error', () => {
      const err = new SignalisError('test');
      expect(err).toBeInstanceOf(Error);
    });

    it('has stack trace', () => {
      const err = new SignalisError('test');
      expect(err.stack).toBeDefined();
      expect(typeof err.stack).toBe('string');
    });

    it('toJSON returns serializable object', () => {
      const err = new SignalisError('test', ErrorCode.SIGNALIS_ERROR, { x: 1 });
      const json = err.toJSON();
      expect(json).toEqual({
        name: 'SignalisError',
        message: 'test',
        code: ErrorCode.SIGNALIS_ERROR,
        context: { x: 1 },
      });
    });

    it('can be JSON.stringify-ed', () => {
      const err = new SignalisError('test', ErrorCode.SIGNALIS_ERROR, { x: 1 });
      const str = JSON.stringify(err);
      const parsed = JSON.parse(str);
      expect(parsed.message).toBe('test');
      expect(parsed.code).toBe(ErrorCode.SIGNALIS_ERROR);
    });
  });

  describe('ValidationError', () => {
    it('creates with correct name and code', () => {
      const err = new ValidationError('bad input');
      expect(err.name).toBe('ValidationError');
      expect(err.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(err).toBeInstanceOf(SignalisError);
      expect(err).toBeInstanceOf(ValidationError);
    });

    it('wrongSize() factory', () => {
      const err = ValidationError.wrongSize('publicKey', 32, 10);
      expect(err).toBeInstanceOf(ValidationError);
      expect(err.message).toContain('32');
      expect(err.message).toContain('10');
      expect(err.context).toEqual({ field: 'publicKey', expected: 32, actual: 10 });
    });

    it('wrongType() factory', () => {
      const err = ValidationError.wrongType('key', 'Buffer', 'string-value');
      expect(err).toBeInstanceOf(ValidationError);
      expect(err.message).toContain('Buffer');
      expect(err.message).toContain('string');
      expect(err.context).toEqual({
        field: 'key',
        expected: 'Buffer',
        actualType: 'string',
      });
    });

    it('wrongType() handles null', () => {
      const err = ValidationError.wrongType('key', 'Buffer', null);
      expect(err.context).toHaveProperty('actualType', 'null');
    });
  });

  describe('SignatureError', () => {
    it('default message', () => {
      const err = new SignatureError();
      expect(err.message).toBe('Signature verification failed');
      expect(err.code).toBe(ErrorCode.SIGNATURE_ERROR);
    });

    it('custom message and context', () => {
      const err = new SignatureError('bad sig', { keyId: 42 });
      expect(err.message).toBe('bad sig');
      expect(err.context).toEqual({ keyId: 42 });
    });
  });

  describe('KeyError', () => {
    it('basic construction', () => {
      const err = new KeyError('key failed');
      expect(err.name).toBe('KeyError');
      expect(err.code).toBe(ErrorCode.KEY_ERROR);
    });
  });

  describe('PreKeyError', () => {
    it('basic construction', () => {
      const err = new PreKeyError('prekey issue');
      expect(err.code).toBe(ErrorCode.PREKEY_ERROR);
    });

    it('notFound() factory', () => {
      const err = PreKeyError.notFound(42);
      expect(err.code).toBe(ErrorCode.PREKEY_NOT_FOUND);
      expect(err.message).toContain('42');
      expect(err.context).toEqual({ id: 42 });
    });

    it('expired() factory', () => {
      const err = PreKeyError.expired(10, 5000);
      expect(err.code).toBe(ErrorCode.PREKEY_EXPIRED);
      expect(err.context).toEqual({ id: 10, age: 5000 });
    });

    it('alreadyUsed() factory', () => {
      const err = PreKeyError.alreadyUsed(7);
      expect(err.code).toBe(ErrorCode.PREKEY_ALREADY_USED);
      expect(err.context).toEqual({ id: 7 });
    });
  });

  describe('SerializationError', () => {
    it('basic construction', () => {
      const err = new SerializationError('bad json');
      expect(err.code).toBe(ErrorCode.SERIALIZATION_ERROR);
    });
  });

  describe('ProtocolError', () => {
    it('basic construction', () => {
      const err = new ProtocolError('bad protocol');
      expect(err.code).toBe(ErrorCode.PROTOCOL_ERROR);
    });

    it('unsupportedVersion() factory', () => {
      const err = ProtocolError.unsupportedVersion(99);
      expect(err.context).toEqual({ version: 99 });
      expect(err.message).toContain('99');
    });
  });

  describe('SessionError', () => {
    it('basic construction', () => {
      const err = new SessionError('session issue');
      expect(err.code).toBe(ErrorCode.SESSION_ERROR);
    });
  });

  describe('Error hierarchy', () => {
    it('all errors extend SignalisError', () => {
      expect(new ValidationError('x')).toBeInstanceOf(SignalisError);
      expect(new SignatureError()).toBeInstanceOf(SignalisError);
      expect(new KeyError('x')).toBeInstanceOf(SignalisError);
      expect(new PreKeyError('x')).toBeInstanceOf(SignalisError);
      expect(new SerializationError('x')).toBeInstanceOf(SignalisError);
      expect(new ProtocolError('x')).toBeInstanceOf(SignalisError);
      expect(new SessionError('x')).toBeInstanceOf(SignalisError);
    });

    it('all errors extend Error', () => {
      expect(new ValidationError('x')).toBeInstanceOf(Error);
      expect(new SignatureError()).toBeInstanceOf(Error);
    });

    it('can be caught with try/catch', () => {
      try {
        throw new ValidationError('test');
      } catch (e) {
        expect(e).toBeInstanceOf(ValidationError);
        expect(e).toBeInstanceOf(SignalisError);
      }
    });

    it('can be distinguished by instanceof', () => {
      const errors: SignalisError[] = [
        new ValidationError('x'),
        new SignatureError(),
        new KeyError('x'),
      ];

      const validation = errors.filter((e) => e instanceof ValidationError);
      const signature = errors.filter((e) => e instanceof SignatureError);

      expect(validation).toHaveLength(1);
      expect(signature).toHaveLength(1);
    });
  });

  describe('ErrorCode constants', () => {
    it('has all expected codes', () => {
      expect(ErrorCode.SIGNALIS_ERROR).toBeDefined();
      expect(ErrorCode.VALIDATION_ERROR).toBeDefined();
      expect(ErrorCode.SIGNATURE_ERROR).toBeDefined();
      expect(ErrorCode.KEY_ERROR).toBeDefined();
      expect(ErrorCode.PREKEY_ERROR).toBeDefined();
      expect(ErrorCode.PREKEY_NOT_FOUND).toBeDefined();
      expect(ErrorCode.PREKEY_EXPIRED).toBeDefined();
      expect(ErrorCode.PREKEY_ALREADY_USED).toBeDefined();
      expect(ErrorCode.SERIALIZATION_ERROR).toBeDefined();
      expect(ErrorCode.PROTOCOL_ERROR).toBeDefined();
      expect(ErrorCode.SESSION_ERROR).toBeDefined();
    });
  });
});
