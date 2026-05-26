// @ts-check
/**
 * ESLint 9 flat config for @brashkie/signalis.
 *
 * Migrated from .eslintrc to the new flat config format
 * required by ESLint 9.x.
 *
 * https://eslint.org/docs/latest/use/configure/configuration-files
 */

import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
  // ─── Ignore patterns (replaces .eslintignore) ────────────────────────
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'node_modules/**',
      '*.tsbuildinfo',
      '**/*.d.ts',
    ],
  },

  // ─── Base ESLint recommended rules ───────────────────────────────────
  js.configs.recommended,

  // ─── TypeScript recommended rules ────────────────────────────────────
  ...tseslint.configs.recommended,

  // ─── Project-wide rules ──────────────────────────────────────────────
  {
    files: ['src/**/*.ts', '__tests__/**/*.ts'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        ...globals.node,
      },
      parserOptions: {
        ecmaVersion: 2023,
        sourceType: 'module',
      },
    },
    rules: {
      // ─── Style ──────────────────────────────────────────────────────
      'no-console': 'off',
      'prefer-const': 'error',
      'no-var': 'error',
      'eqeqeq': ['error', 'always'],

      // ─── TypeScript — relaxed for crypto library ────────────────────
      // Crypto code legitimately needs `Buffer`, type assertions for
      // branded types, and explicit `any` in some test helpers.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-empty-function': 'off',
      '@typescript-eslint/no-empty-object-type': 'off',
      '@typescript-eslint/ban-ts-comment': [
        'warn',
        {
          'ts-expect-error': 'allow-with-description',
          'ts-ignore': true,
          'ts-nocheck': true,
          'ts-check': false,
        },
      ],

      // ─── Disable rules that conflict with branded types ─────────────
      '@typescript-eslint/no-empty-interface': 'off',
      '@typescript-eslint/consistent-type-definitions': 'off',
    },
  },

  // ─── Tests — even more relaxed (allow any, type assertions) ──────────
  {
    files: ['__tests__/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
    },
  },
);
