import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(`./src/${p}`, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@": src(""),
      // "server-only" throws outside React Server Components; tests run in plain Node.
      "server-only": src("test/server-only-stub.ts"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: process.env.INTEGRATION ? [] : ["src/**/*.int.test.ts"],
    fileParallelism: !process.env.INTEGRATION,
    // Interactive transactions are slow on Docker Desktop (~0.6s each); integration runs need headroom.
    testTimeout: process.env.INTEGRATION ? 60_000 : 5_000,
    hookTimeout: process.env.INTEGRATION ? 60_000 : 10_000,
  },
});
