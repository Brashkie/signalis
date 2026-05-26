import { defineConfig } from 'vitest/config';

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
