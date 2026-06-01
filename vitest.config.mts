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
      // Excluimos:
      //   - eslint.config.mjs (no es runtime)
      //   - barrel re-exports (sin lógica)
      //   - x3dh/types.ts (archivo solo-interfaces, desaparece en runtime)
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
        'src/x3dh/types.ts',       // Solo interfaces TS (desaparecen al compilar)
      ],
      // Thresholds Sprint 2 (PreKeys completos + X3DH).
      // Subirán a 95% en Sprint 3 cuando llegue Double Ratchet.
      thresholds: {
        statements: 95,
        branches: 90,
        functions: 95,
        lines: 95,
      },
    },
  },
});
