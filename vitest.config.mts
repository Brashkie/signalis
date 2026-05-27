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
      // Solo medimos cobertura del código fuente real (src/)
      // Excluimos eslint.config.mjs (no es runtime) y src/index.ts (solo re-exports)
      include: ['src/**/*.ts'],
      exclude: [
        'node_modules/',
        'dist/',
        'coverage/',
        '__tests__/',
        '*.config.ts',
        '*.config.mts',
        '*.config.mjs',
        '*.config.js',
        'src/index.ts',           // Solo re-exports
        'src/**/index.ts',         // Re-exports de barrel files
      ],
      // Thresholds Sprint 2 (PreKeys completos).
      // Subirán a 95% en Sprint 3 cuando llegue Double Ratchet.
      thresholds: {
        statements: 90,
        branches: 85,
        functions: 90,
        lines: 90,
      },
    },
  },
});
