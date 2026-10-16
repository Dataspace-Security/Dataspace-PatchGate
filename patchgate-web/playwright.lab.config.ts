import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, devices } from "@playwright/test";

/**
 * LAB end-to-end tests against the RUNNING hosted lab (lab/up-all.sh): PatchGate = "our server" at
 * https://patchgate.patchgate-lab.internal:3443 with local accounts (password only), Bank A's real
 * connector + Tactical. No web server is started here, and no database is reset.
 *
 *   npx playwright test -c playwright.lab.config.ts
 *
 * TLS: Chromium does not trust the lab CA, so the lab server certificate is pinned by its SPKI hash
 * (--ignore-certificate-errors-spki-list) instead of ignoring certificate errors altogether.
 */
export const LAB_URL = process.env.LAB_URL ?? "https://patchgate.patchgate-lab.internal:3443";

function labCertSpki(): string {
  const pem = readFileSync(join(__dirname, "..", "lab", "certs", "out", "server.crt"), "utf8");
  const spki = new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("base64");
}

export default defineConfig({
  testDir: "./e2e-lab",
  timeout: 300_000,
  expect: { timeout: 60_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "e2e-lab/report", open: "never" }]],
  outputDir: "e2e-lab/test-results",
  use: {
    baseURL: LAB_URL,
    navigationTimeout: 120_000,
    actionTimeout: 60_000,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    launchOptions: { args: [`--ignore-certificate-errors-spki-list=${labCertSpki()}`] },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
});
