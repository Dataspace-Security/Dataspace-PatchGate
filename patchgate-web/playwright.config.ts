import { defineConfig, devices } from "@playwright/test";

/**
 * UI end-to-end tests: a real browser clicking through the panel against a dedicated, freshly
 * seeded database (patchgate_e2e). Dev mode is required because production has no login until SSO.
 */
const PORT = 3200;
export const E2E_DB = process.env.E2E_DATABASE_URL ?? "postgresql://patchgate:patchgate-dev-only@127.0.0.1:55432/patchgate_e2e?schema=public";

export default defineConfig({
  testDir: "./e2e",
  timeout: 300_000,
  expect: { timeout: 60_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "e2e/report", open: "never" }]],
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL: `http://localhost:${PORT}`,
    navigationTimeout: 120_000,
    actionTimeout: 60_000,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
  webServer: {
    command: `npx next dev -p ${PORT}`,
    url: `http://localhost:${PORT}/api/patches`,
    timeout: 300_000,
    reuseExistingServer: false,
    // Only ONE Next dev server per project folder at a time (they rewrite next-env.d.ts and
    // trigger reload loops in each other) — stop any other dev server before running E2E.
    env: { DATABASE_URL: E2E_DB, DEV_USER_UPN: "viewer@dev.local" },
  },
});
