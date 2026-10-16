import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { parseEnrolmentAuth } from "./bundle-access";
import { BundleError, bundleConfig, contentTypeOf, latestVersion, listedFile, parseRange, parseSha256Sums, readSums, resolveBundle, siteScript, signatureFile } from "./site-bundle";

const root = mkdtempSync(join(tmpdir(), "pg-site-bundles-"));
const H = (c: string) => c.repeat(64);
mkdirSync(join(root, "1.2.0"));
writeFileSync(join(root, "1.2.0", "SHA256SUMS"), `${H("a")}  patchgate-site-1.2.0.tar.gz\n${H("b")} *patchgate-site-1.2.0-online.tar.gz\n${H("c")}  install-site.sh\n${H("d")}  ../etc/passwd\nnot a line\n`);
writeFileSync(join(root, "1.2.0", "patchgate-site-1.2.0.tar.gz"), "0123456789");
writeFileSync(join(root, "1.2.0", "install-site.sh"), '#!/bin/bash\nDEFAULT_SERVER="__PATCHGATE_URL__"\nDEFAULT_BUNDLE_KEY="__PATCHGATE_BUNDLE_KEY__"\necho __PATCHGATE_URL__/x\n');
writeFileSync(join(root, "1.2.0", "unlisted.bin"), "secret");
writeFileSync(join(root, "LATEST"), "1.2.0\n");
const cfg = { dir: root, latest: null, pubkey: null };
afterAll(() => rmSync(root, { recursive: true, force: true }));

const status = (p: Promise<unknown>) => p.then(() => 200, (e: unknown) => (e instanceof BundleError ? e.status : 500));

describe("parseRange (resume with curl -C -)", () => {
  it.each([
    [null, 100, null],
    ["bytes=0-", 100, { start: 0, end: 99 }],
    ["bytes=10-19", 100, { start: 10, end: 19 }],
    ["bytes=90-500", 100, { start: 90, end: 99 }],
    ["bytes=-10", 100, { start: 90, end: 99 }],
    ["bytes=-500", 100, { start: 0, end: 99 }],
    ["bytes=100-", 100, "unsatisfiable"],
    ["bytes=-0", 100, "unsatisfiable"],
    ["bytes=20-10", 100, null],
    ["bytes=0-1,5-6", 100, null],
    ["items=0-1", 100, null],
    ["bytes=-", 100, null],
  ])("%s of %i → %j", (h, size, want) => {
    expect(parseRange(h, size)).toEqual(want);
  });
});

describe("SHA256SUMS allow-list", () => {
  it("parses text and binary mode lines, drops unsafe names and junk", () => {
    expect([...parseSha256Sums(`${H("a")}  a.tar.gz\n${H("B")} *b.tar.gz\n${H("c")}  ../x\n${H("d")}  /abs\n${H("e")}  SHA256SUMS\nzzz`).entries()]).toEqual([
      ["a.tar.gz", H("a")],
      ["b.tar.gz", H("b")],
    ]);
  });

  it("serves only listed files that exist; never traverses or follows a symlink out", async () => {
    const b = await resolveBundle(cfg, "latest");
    expect(b.version).toBe("1.2.0");
    expect((await readSums(b)).files.size).toBe(3);
    await expect(listedFile(b, "patchgate-site-1.2.0.tar.gz")).resolves.toMatchObject({ size: 10, sha256: H("a") });
    expect(await status(listedFile(b, "unlisted.bin"))).toBe(404);
    expect(await status(listedFile(b, "patchgate-site-1.2.0-online.tar.gz"))).toBe(404); // listed but missing
    expect(await status(listedFile(b, "../1.2.0/install-site.sh"))).toBe(404);
    expect(await status(listedFile(b, "..%2Fetc%2Fpasswd"))).toBe(404);
    expect(await status(signatureFile(b))).toBe(404); // unsigned bundle
    for (const v of ["..", ".", "../..", "1.2.0/..", "/etc", "a".repeat(41), "nope"]) expect(await status(resolveBundle(cfg, v))).toBe(404);
    expect(await status(resolveBundle(null, "latest"))).toBe(404);
  });

  it("refuses a version directory that is a symlink out of the bundle root", async () => {
    const outside = mkdtempSync(join(tmpdir(), "pg-outside-"));
    let linked = false;
    try {
      symlinkSync(outside, join(root, "evil"), "junction");
      linked = true;
    } catch {
      // symlinks may be unavailable for this account
    }
    if (linked) expect(await status(resolveBundle(cfg, "evil"))).toBe(404);
    rmSync(outside, { recursive: true, force: true });
  });

  it("latest: env pointer wins over the LATEST file", async () => {
    expect(await latestVersion(cfg)).toBe("1.2.0");
    expect(await latestVersion({ dir: root, latest: "9.9.9", pubkey: null })).toBe("9.9.9");
    expect(await status(resolveBundle({ dir: root, latest: "9.9.9", pubkey: null }, "latest"))).toBe(404);
  });
});

describe("site.sh and headers", () => {
  it("bakes the PatchGate origin into every placeholder", async () => {
    const s = await siteScript(cfg, "https://patchgate.example.com/some/path");
    expect(s.version).toBe("1.2.0");
    expect(s.body).toContain('DEFAULT_SERVER="https://patchgate.example.com"');
    expect(s.body).toContain("echo https://patchgate.example.com/x");
    expect(s.body).not.toContain("__PATCHGATE_URL__");
    expect(s.body).toContain("__PATCHGATE_BUNDLE_KEY__"); // no key configured: placeholder stays (script treats it as unset)
  });

  it("bakes the configured bundle-signing key; ignores a malformed one", async () => {
    const key = `ed25519:${Buffer.alloc(32, 7).toString("base64")}`;
    const s = await siteScript({ ...cfg, pubkey: key }, "https://patchgate.example.com");
    expect(s.body).toContain(`DEFAULT_BUNDLE_KEY="${key}"`);
    expect(bundleConfig({ PATCHGATE_SITE_BUNDLE_DIR: root, PATCHGATE_SITE_BUNDLE_PUBKEY: key })?.pubkey).toBe(key);
    expect(bundleConfig({ PATCHGATE_SITE_BUNDLE_DIR: root, PATCHGATE_SITE_BUNDLE_PUBKEY: 'x"; rm -rf /' })?.pubkey).toBeNull();
  });

  it("content types", () => {
    expect(contentTypeOf("a.tar.gz")).toBe("application/gzip");
    expect(contentTypeOf("install-site.sh")).toMatch(/shellscript/);
    expect(contentTypeOf("SHA256SUMS.sig")).toBe("application/octet-stream");
  });

  it("parses the enrolment Authorization header strictly", () => {
    expect(parseEnrolmentAuth("PatchGate-Enrolment 7Q2M-K9XD-4HPA-ZT3W-8NBC")).toBe("7Q2M-K9XD-4HPA-ZT3W-8NBC");
    expect(parseEnrolmentAuth("patchgate-enrolment   7Q2M-K9XD-4HPA-ZT3W-8NBC ")).toBe("7Q2M-K9XD-4HPA-ZT3W-8NBC");
    for (const h of [null, "", "Bearer 7Q2M-K9XD-4HPA-ZT3W-8NBC", "PatchGate-Enrolment 7q2m-k9xd-4hpa-zt3w-8nbc", "PatchGate-Enrolment 7Q2M-K9XD", "PatchGate-Enrolment 7Q2M-K9XD-4HPA-ZT3W-8NBC extra"]) {
      expect(parseEnrolmentAuth(h)).toBeNull();
    }
  });
});
