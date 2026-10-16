import { describe, expect, it } from "vitest";
import { parseOsslsigncodeResult, parsePowerShellResult, publisherMatches } from "./signature";

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
    const out = "Signer's certificate:\n\tSubject: /C=US/O=Google LLC/CN=Google LLC\n...\nSignature verification: ok\n";
    expect(parseOsslsigncodeResult(out)).toEqual({ ok: true, subject: "/C=US/O=Google LLC/CN=Google LLC" });
  });
  it("is not ok on failure output", () => {
    expect(parseOsslsigncodeResult("Signature verification: failed").ok).toBe(false);
  });
});
