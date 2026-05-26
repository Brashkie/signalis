import { defineConfig } from 'vitest/config';

/**
 * Vitest 3.x config for @brashkie/signalis.
 *
 * Uses `.mts` extension to force ESM loading, since vite (vitest's
 * underlying engine) is ESM-only and refuses to be loaded via CommonJS
 * `require()` when package.json declares `"type": "commonjs"`.
 *
 * See: https://vitest.dev/config/#configuring-vitest
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['__tests__/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov', 'json-summary', 'json'],
      exclude: [
        'node_modules/',
        'dist/',
        '__tests__/',
        '*.config.ts',
        '*.config.mts',
        '*.config.js',
        'src/index.ts', // Solo re-exports
      ],
      // Thresholds para Sprint 1 (Identity Keys only).
      // Subirán a 90% en Sprint 2 cuando coverage natural crezca.
      thresholds: {
        statements: 75,
        branches: 75,
        functions: 75,
        lines: 75,
      },
    },
  },
});
