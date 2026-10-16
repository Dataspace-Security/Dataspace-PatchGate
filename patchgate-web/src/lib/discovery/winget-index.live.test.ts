/**
 * LIVE check of the winget index signature (opt-in: LIVE=1). Downloads the real
 * https://cdn.winget.microsoft.com/cache/source.msix (~20 MB) and verifies it exactly like the fetcher:
 *   - Windows: Get-AuthenticodeSignature (OS trust store);
 *   - Linux:   osslsigncode (the PATCHED build from the Dockerfile) + CODESIGN_CA_FILE, which must contain
 *              Microsoft Root Certificate Authority 2011 and 2010 (RUNBOOK §4.4).
 * Skipped when osslsigncode is not installed on a non-Windows host. In the image:
 *   docker run --rm -e LIVE=1 -e CODESIGN_CA_FILE=/ca/codesign-ca.pem -v "$PWD/ca:/ca:ro" … npx vitest run winget-index.live
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { WINGET_INDEX_URL, verifyIndexSignature } from "./winget-index";

function hasOsslsigncode(): boolean {
  try {
    execFileSync("osslsigncode", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const enabled = process.env.LIVE === "1" && (process.platform === "win32" || hasOsslsigncode());
const dir = mkdtempSync(join(tmpdir(), "pg-winget-index-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe.runIf(enabled)("live winget index signature", () => {
  const codesign = { codesignCaFile: process.env.CODESIGN_CA_FILE };
  const msix = join(dir, "source.msix");

  it("verifies the real source.msix as Microsoft-signed", { timeout: 300_000 }, async () => {
    if (process.platform !== "win32") expect(codesign.codesignCaFile, "set CODESIGN_CA_FILE").toBeTruthy();
    const res = await fetch(WINGET_INDEX_URL);
    expect(res.ok).toBe(true);
    writeFileSync(msix, Buffer.from(await res.arrayBuffer()));

    const sig = await verifyIndexSignature(msix, { codesign, scratch: join(dir, "roots-1.pem") });
    expect(sig, JSON.stringify(sig)).toMatchObject({ ok: true });
  });

  it("rejects a tampered copy", { timeout: 120_000 }, async () => {
    const bytes = readFileSync(msix);
    bytes[Math.floor(bytes.length / 2)] ^= 0x01; // inside Public/index.db
    const tampered = join(dir, "tampered.msix");
    writeFileSync(tampered, bytes);
    const sig = await verifyIndexSignature(tampered, { codesign, scratch: join(dir, "roots-2.pem") });
    expect(sig.ok).toBe(false);
  });
});
