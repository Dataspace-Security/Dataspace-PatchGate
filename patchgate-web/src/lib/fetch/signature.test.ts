import { describe, expect, it } from "vitest";
import {
  codesignOptions,
  filterCaBundle,
  isRootOf,
  osslsigncodeVerifyArgs,
  parseOsslsigncodeResult,
  parsePowerShellResult,
  publisherMatches,
} from "./signature";
import { ISRG_ROOT_X1, MS_MARKETPLACE_PCA_2011, MS_ROOT_2010, MS_ROOT_2011 } from "./signature.fixtures";

describe("publisherMatches", () => {
  it("matches PowerShell-style and OpenSSL-style subjects", () => {
    expect(publisherMatches("CN=Google LLC, O=Google LLC, L=Mountain View, C=US", "O=Google LLC")).toBe(true);
    expect(publisherMatches("/C=US/L=Mountain View/O=Google LLC/CN=Google LLC", "O=Google LLC")).toBe(true);
  });
  it("rejects a different organisation, and substring tricks", () => {
    expect(publisherMatches("CN=Evil Corp, O=Evil Corp", "O=Google LLC")).toBe(false);
    expect(publisherMatches("CN=x, O=Google LLC Evil", "O=Google LLC")).toBe(false);
  });
  it("matches the PowerShell UseNewLines format", () => {
    expect(publisherMatches("CN=Google LLC\r\nO=Google LLC\r\nC=US", "O=Google LLC")).toBe(true);
  });
});

describe("parsePowerShellResult", () => {
  it("parses ConvertTo-Json output", () => {
    expect(parsePowerShellResult('{"Status":"Valid","Subject":"CN=X, O=X"}')).toEqual({ status: "Valid", subject: "CN=X, O=X" });
  });
  it("returns null on garbage", () => {
    expect(parsePowerShellResult("oops")).toBeNull();
  });
});

describe("parseOsslsigncodeResult", () => {
  it("extracts ok + subject", () => {
    const out = "Signer's certificate:\n\tSubject: /C=US/O=Google LLC/CN=Google LLC\n...\nSignature verification: ok\n\nSucceeded\n";
    expect(parseOsslsigncodeResult(out)).toEqual({ ok: true, subject: "/C=US/O=Google LLC/CN=Google LLC" });
  });
  it("is not ok on failure output", () => {
    expect(parseOsslsigncodeResult("Signature verification: failed").ok).toBe(false);
  });
});

// Trimmed real output of the patched osslsigncode 2.14 verifying the winget source.msix (2026-10-16).
const SIGNER = [
  "Signer's certificate:",
  "\t------------------",
  "\tSigner #0:",
  "\t\tSubject: CN=Microsoft Corporation,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US",
  "\t\tIssuer : CN=Microsoft Marketplace CA G 026,OU=EOC,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US",
  "",
  "CAfile: /tmp/roots.pem",
  "TSA's certificates file: /tmp/roots.pem",
  "",
  "Timestamp verified using:",
  "\t\tSubject: CN=Microsoft Time-Stamp PCA 2010,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US",
  "",
].join("\n");
const WINGET_OK = [
  SIGNER,
  "Timestamp Server Signature verification: ok",
  "Signing certificate chain verified using:",
  "\tWarning: Ignoring critical Microsoft Application Policies extension",
  "CRL online verification disabled",
  "Signature verification: ok",
  "",
  "Number of verified signatures: 1",
  "Succeeded",
  "",
].join("\n");

describe("parseOsslsigncodeResult (real winget output)", () => {
  it("accepts a verified signature + verified timestamp and returns the signer subject, not the TSA's", () => {
    const r = parseOsslsigncodeResult(WINGET_OK);
    expect(r.ok).toBe(true);
    expect(r.subject).toBe("CN=Microsoft Corporation,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US");
    expect(publisherMatches(r.subject, "O=Microsoft Corporation")).toBe(true);
  });
  it("never counts 'Timestamp Server Signature verification: ok' as the file signature", () => {
    const out = [SIGNER, "Timestamp Server Signature verification: ok", "\tError: unhandled critical extension", "PKCS7_verify error", "Signature verification: failed", "", "Failed", ""].join("\n");
    expect(parseOsslsigncodeResult(out).ok).toBe(false);
  });
  it("rejects a present-but-unverifiable timestamp even when osslsigncode 2.14 says Succeeded", () => {
    const out = WINGET_OK.replace("Timestamp Server Signature verification: ok", "Timestamp Server Signature verification: failed");
    expect(parseOsslsigncodeResult(out).ok).toBe(false);
  });
  it("accepts a file without a timestamp (validated at the current time)", () => {
    const out = WINGET_OK.replace("Timestamp Server Signature verification: ok", "Timestamp is not available");
    expect(parseOsslsigncodeResult(out).ok).toBe(true);
  });
  it("rejects when any of several signatures fails, or the final verdict is missing", () => {
    expect(parseOsslsigncodeResult(WINGET_OK.replace("Number of", "Signature verification: failed\nNumber of")).ok).toBe(false);
    expect(parseOsslsigncodeResult(WINGET_OK.replace("Succeeded", "Failed")).ok).toBe(false);
    expect(parseOsslsigncodeResult("").ok).toBe(false);
  });
  it("rejects a digest mismatch (tampered package)", () => {
    expect(parseOsslsigncodeResult("Calculated message digest : FAFA     MISMATCH!!!\nFailed\n").ok).toBe(false);
  });
});

describe("osslsigncodeVerifyArgs", () => {
  it("passes the CA bundle as TSA bundle too and skips online CRLs by default", () => {
    expect(osslsigncodeVerifyArgs("/r/f.msix", { codesignCaFile: "/ca/cs.pem" })).toEqual([
      "verify", "-in", "/r/f.msix", "-CAfile", "/ca/cs.pem", "-TSA-CAfile", "/ca/cs.pem", "-ignore-crl",
    ]);
  });
  it("uses a separate TSA bundle and online CRL checks when asked", () => {
    expect(osslsigncodeVerifyArgs("/r/f.exe", { codesignCaFile: "/ca/cs.pem", tsaCaFile: "/ca/tsa.pem", crlCheck: "online" })).toEqual([
      "verify", "-in", "/r/f.exe", "-CAfile", "/ca/cs.pem", "-TSA-CAfile", "/ca/tsa.pem",
    ]);
  });
  it("maps env to options", () => {
    expect(codesignOptions({ CODESIGN_CA_FILE: "/ca/x.pem", CODESIGN_CRL_CHECK: "online" })).toEqual({ codesignCaFile: "/ca/x.pem", crlCheck: "online" });
  });
});

describe("filterCaBundle + isRootOf (Microsoft-only trust for the winget index)", () => {
  const garbage = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----";
  const bundle = [ISRG_ROOT_X1, MS_ROOT_2011, MS_MARKETPLACE_PCA_2011, garbage, MS_ROOT_2010].join("\n");
  it("keeps only self-signed Microsoft roots", () => {
    const r = filterCaBundle(bundle, isRootOf("Microsoft Corporation"));
    expect(r.count).toBe(2);
    expect(r.pem).toContain(MS_ROOT_2011.trim());
    expect(r.pem).toContain(MS_ROOT_2010.trim());
    expect(r.pem).not.toContain(MS_MARKETPLACE_PCA_2011.trim()); // intermediate: not a trust anchor
    expect(r.pem).not.toContain(ISRG_ROOT_X1.trim());
  });
  it("returns an empty bundle when no Microsoft root is present", () => {
    expect(filterCaBundle(ISRG_ROOT_X1, isRootOf("Microsoft Corporation"))).toEqual({ pem: "", count: 0 });
    expect(filterCaBundle("", isRootOf("Microsoft Corporation"))).toEqual({ pem: "", count: 0 });
  });
  it("matches the organisation exactly", () => {
    expect(filterCaBundle(MS_ROOT_2011, isRootOf("Microsoft")).count).toBe(0);
  });
});

