import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  // The `cloudflare:email` built-in only exists in the Workers runtime; alias it
  // to a stub so src/index.ts (the email() handler) is importable under vitest.
  resolve: {
    alias: [
      {
        find: /^cloudflare:email$/,
        replacement: fileURLToPath(new URL('./test/stubs/cloudflare-email.ts', import.meta.url)),
      },
    ],
  },
  test: {
    // Test files import { describe, it, expect } from 'vitest' explicitly, so
    // ambient globals are not enabled.
    environment: 'node',
    include: ['test/**/*.test.{ts,mjs}'],
    setupFiles: ['./test/setup.ts'],
  },
});
