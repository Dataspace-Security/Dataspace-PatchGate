import type { WinUpdateFile } from "@prisma/client";
import { describe, expect, it } from "vitest";
import { jobPackageSchema, resultSchemas } from "@/lib/connector/protocol";
import { assertRepoRelPath } from "@/lib/fetch/repo";
import { isPermanentDownloadError, judgeFile } from "./files";
import { catalogReadiness, fileToPackage, updateReadiness } from "./install";
import {
  kbFromName,
  normalizeDigest,
  normalizeGuid,
  normalizeKb,
  normalizeUpdateUrl,
  scanCabRepoPath,
  scanCabVersion,
  sha1FromName,
  updateFileRepoPath,
} from "./microsoft";

const SHA1 = "5c27f9ceebeb31e1c962db9a4cd889a712b193c3";
const WU_URL = `http://download.windowsupdate.com/c/msdownload/update/software/secu/2025/04/wssmui-zh-cn_${SHA1}.cab`;
const DL_URL =
  "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/b7aa64b3-8441-4d36-b8f7-409f3cfeac1c/public/windows11.0-kb5074109-x64_fe29a336e6e650dda4038e82bcc0c6286c70b9a1.msu";
const GUID = "bbc221e1-2b4e-4eb4-be1b-78375c6747e4";

describe("normalizeUpdateUrl (exact Microsoft host allow-list)", () => {
  it("rewrites the plain-http Windows Update CDN to its TLS name, same path", () => {
    const r = normalizeUpdateUrl(WU_URL);
    expect(r).toEqual({ ok: true, url: `https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/04/wssmui-zh-cn_${SHA1}.cab`, name: `wssmui-zh-cn_${SHA1}.cab`, kind: "cab" });
  });
  it("rewrites the delivery-optimisation CDN", () => {
    const r = normalizeUpdateUrl(DL_URL);
    expect(r.ok && r.url.startsWith("https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/")).toBe(true);
    expect(r.ok && r.kind).toBe("msu");
  });
  it("accepts www.download.windowsupdate.com and already-TLS URLs", () => {
    expect(normalizeUpdateUrl(`http://www.download.windowsupdate.com/msdownload/update/software/secu/2020/01/x_${SHA1}.cab`).ok).toBe(true);
    expect(normalizeUpdateUrl(`https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/updt/2026/01/x_${SHA1}.msu`).ok).toBe(true);
  });
  it.each([
    ["suffix trick", `http://download.windowsupdate.com.evil.example/c/msdownload/update/software/secu/x_${SHA1}.cab`],
    ["other host", `http://example.com/c/msdownload/update/software/secu/x_${SHA1}.cab`],
    ["subdomain", `http://x.download.windowsupdate.com/c/msdownload/update/software/secu/x_${SHA1}.cab`],
    ["ip literal", `http://13.107.4.50/c/msdownload/update/software/secu/x_${SHA1}.cab`],
    ["port", `http://download.windowsupdate.com:8080/c/msdownload/update/software/secu/x_${SHA1}.cab`],
    ["credentials", `http://u:p@download.windowsupdate.com/c/msdownload/update/software/secu/x_${SHA1}.cab`],
    ["query", `http://download.windowsupdate.com/c/msdownload/update/software/secu/x_${SHA1}.cab?a=1`],
    ["ftp", `ftp://download.windowsupdate.com/c/msdownload/update/software/secu/x_${SHA1}.cab`],
    ["wrong path", `http://download.windowsupdate.com/other/x_${SHA1}.cab`],
    ["traversal", `http://download.windowsupdate.com/c/msdownload/update/software/../../x_${SHA1}.cab`],
    ["exe", `http://download.windowsupdate.com/c/msdownload/update/software/secu/x_${SHA1}.exe`],
    ["express psf", `http://download.windowsupdate.com/c/msdownload/update/software/secu/x_${SHA1}.psf`],
    ["delivery path", "http://dl.delivery.mp.microsoft.com/other/x.msu"],
  ])("rejects %s", (_n, url) => {
    expect(normalizeUpdateUrl(url).ok).toBe(false);
  });
});

describe("digest + naming helpers", () => {
  it("reads the SHA-1 Microsoft embeds in file names", () => {
    expect(sha1FromName(`wssmui-zh-cn_${SHA1}.cab`)).toBe(SHA1);
    expect(sha1FromName("plain.cab")).toBeNull();
  });
  it("normalises hex and base64 digests", () => {
    expect(normalizeDigest("XCf5zuvrMeHJYtuaTNiJpxKxk8M=", 20)).toBe(SHA1);
    expect(normalizeDigest(SHA1.toUpperCase(), 20)).toBe(SHA1);
    expect(normalizeDigest("abc", 20)).toBeNull();
    expect(normalizeDigest(SHA1, 32)).toBeNull();
  });
  it("KB and GUID normalisation", () => {
    expect(kbFromName("windows11.0-kb5074109-x64_ab.msu")).toBe("KB5074109");
    expect(kbFromName("wssmui-zh-cn_ab.cab")).toBeNull();
    expect(normalizeKb("5034441")).toBe("KB5034441");
    expect(normalizeKb("kb5034441")).toBe("KB5034441");
    expect(normalizeKb("x")).toBeNull();
    expect(normalizeGuid(GUID.toUpperCase())).toBe(GUID);
    expect(normalizeGuid("nope")).toBeNull();
  });
  it("repo paths are servable and content-addressed", () => {
    const p = updateFileRepoPath(GUID.toUpperCase(), `wssmui-zh-cn_${SHA1}.cab`);
    expect(p).toBe(`winupdate/${GUID}/wssmui-zh-cn_${SHA1}.cab`);
    expect(assertRepoRelPath(p)).toBe(p);
    const c = scanCabRepoPath("a".repeat(64));
    expect(assertRepoRelPath(c)).toBe(c);
    expect(() => updateFileRepoPath(GUID, "../x.cab")).toThrow();
    expect(scanCabVersion(new Date("2026-10-14T09:00:00Z"), "3ac6fe2a9ae1ee04" + "0".repeat(48))).toBe("20261014-3ac6fe2a");
  });
});

const fileRow = (o: Partial<WinUpdateFile> = {}): WinUpdateFile => ({
  id: "f1",
  updateId: GUID,
  url: "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/04/a.cab",
  name: "a.cab",
  kind: "cab",
  ordinal: 0,
  declaredSize: null,
  sha1: SHA1,
  sha256: "b".repeat(64),
  expectedSha256: null,
  sizeBytes: BigInt(100),
  verification: "VERIFIED",
  source: "CATALOG",
  rejectReason: null,
  signerSubject: "CN=Microsoft Corporation, O=Microsoft Corporation",
  repoPath: `winupdate/${GUID}/a.cab`,
  attempts: 1,
  nextAttemptAt: new Date(0),
  lastError: null,
  verifiedAt: new Date("2026-10-01T00:00:00Z"),
  availableAt: new Date("2026-10-03T00:00:00Z"),
  createdAt: new Date("2026-10-01T00:00:00Z"),
  updatedAt: new Date("2026-10-01T00:00:00Z"),
  ...o,
});

describe("judgeFile", () => {
  const ms = { ok: true as const, subject: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" };
  const actual = { sha1: SHA1, sha256: "b".repeat(64), size: 100 };
  it("accepts matching SHA-1 + Microsoft signature", () => {
    expect(judgeFile(fileRow(), actual, ms).ok).toBe(true);
  });
  it("rejects digest, size, signature and publisher problems", () => {
    expect(judgeFile(fileRow({ sha1: "0".repeat(40) }), actual, ms)).toMatchObject({ ok: false, reason: expect.stringContaining("SHA-1") });
    expect(judgeFile(fileRow({ expectedSha256: "c".repeat(64) }), actual, ms)).toMatchObject({ ok: false, reason: expect.stringContaining("SHA-256") });
    expect(judgeFile(fileRow({ declaredSize: BigInt(5) }), actual, ms)).toMatchObject({ ok: false, reason: expect.stringContaining("size") });
    expect(judgeFile(fileRow(), actual, { ok: false, reason: "signature NotSigned" })).toMatchObject({ ok: false, reason: "signature NotSigned" });
    expect(judgeFile(fileRow(), actual, { ok: true, subject: "CN=Evil, O=Microsoft Corporation Evil" })).toMatchObject({ ok: false, reason: expect.stringContaining("publisher") });
    expect(judgeFile(fileRow({ sha1: null, expectedSha256: null }), actual, ms).ok).toBe(false);
  });
  it("classifies download errors", () => {
    expect(isPermanentDownloadError("HTTP 404 from x")).toBe(true);
    expect(isPermanentDownloadError("Host evil is not allowed")).toBe(true);
    expect(isPermanentDownloadError("HTTP 503 from x")).toBe(false);
    expect(isPermanentDownloadError("The operation was aborted due to timeout")).toBe(false);
  });
});

describe("updateReadiness + packages", () => {
  const now = new Date("2026-10-15T00:00:00Z");
  it("ready only when every file is verified and out of quarantine, in reported order", () => {
    const r = updateReadiness([fileRow({ id: "b", ordinal: 1 }), fileRow({ id: "a", ordinal: 0 })], now);
    expect(r.state === "ready" && r.files.map((f) => f.id)).toEqual(["a", "b"]);
    expect(updateReadiness([fileRow({ availableAt: new Date("2026-10-16T00:00:00Z") })], now).state).toBe("wait");
    expect(updateReadiness([fileRow({ verification: "PENDING" })], now).state).toBe("wait");
    expect(updateReadiness([fileRow(), fileRow({ verification: "REJECTED" })], now).state).toBe("undeliverable");
    expect(updateReadiness([], now).state).toBe("undeliverable");
  });
  it("uses ONLY the Microsoft Update Catalog binding (never PC-reported files)", () => {
    const resolved = { catalogState: "RESOLVED" as const, resolveError: null };
    expect(catalogReadiness({ ...resolved, files: [fileRow()] }, now).state).toBe("ready");
    // a legacy PC-reported file is ignored, even when verified
    expect(catalogReadiness({ ...resolved, files: [fileRow({ source: "REPORTED" })] }, now).state).toBe("undeliverable");
    const mixed = catalogReadiness({ ...resolved, files: [fileRow({ id: "rep", source: "REPORTED" }), fileRow({ id: "cat" })] }, now);
    expect(mixed.state === "ready" && mixed.files.map((f) => f.id)).toEqual(["cat"]);
    expect(catalogReadiness({ catalogState: "PENDING", resolveError: null, files: [fileRow()] }, now).state).toBe("wait");
    expect(catalogReadiness({ catalogState: "UNRESOLVABLE", resolveError: "language-specific", files: [fileRow()] }, now)).toEqual({ state: "undeliverable", reason: "language-specific" });
  });
  it("builds protocol-valid msu/cab job packages", () => {
    const p = fileToPackage(fileRow(), "KB5034441", 200);
    expect(jobPackageSchema.parse(p)).toMatchObject({ kind: "cab", version: "KB5034441", publisher: "O=Microsoft Corporation", switches: "" });
    expect(fileToPackage(fileRow({ kind: "msu" }), null, 201).version).toBe("r201");
  });
  it("protocol WU_INSTALL result shape the connector reports", () => {
    expect(resultSchemas.WU_INSTALL.safeParse({ outcome: "PARTIAL", installed: [], failed: [{ updateId: GUID, error: "x" }], rebootRequired: false }).success).toBe(true);
  });
});
