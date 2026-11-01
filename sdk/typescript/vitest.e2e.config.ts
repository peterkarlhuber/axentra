import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/e2e/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
    // One server, shared state: run files and tests in order.
    fileParallelism: false,
  },
});
