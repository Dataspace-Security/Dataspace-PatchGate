import { describe, expect, it } from "vitest";
import { appendPin, signerOrgOf } from "@/lib/fetch/dn";
import { decideTrust, type TrustInput } from "./trust";

const H = "a".repeat(64);
const G = "b".repeat(64);
const sig = (subject: string) => ({ ok: true as const, subject });
const base: TrustInput = { signature: sig("CN=Mozilla Corporation, O=Mozilla Corporation, C=US"), pins: "O=Mozilla Corporation", catalogSha256: H, actualSha256: H, allowHashDrift: false };

describe("decideTrust", () => {
  it("publishes a catalog-matching file from a pinned signer", () => {
    expect(decideTrust(base)).toEqual({ action: "publish", signerOrg: "Mozilla Corporation" });
  });
  it("holds the first download of an app with no pins", () => {
    expect(decideTrust({ ...base, pins: null })).toMatchObject({ action: "hold", reason: "FIRST_SIGNER", signerOrg: "Mozilla Corporation" });
  });
  it("holds a valid signature from an organisation not in the pin list", () => {
    expect(decideTrust({ ...base, signature: sig("CN=x, O=Mozilla Foundation") })).toMatchObject({ action: "hold", reason: "SIGNER_CHANGED" });
  });
  it("rejects invalid signatures even when the hash matches", () => {
    expect(decideTrust({ ...base, signature: { ok: false, reason: "signature NotSigned" } })).toEqual({ action: "reject", reason: "signature NotSigned" });
  });
  it("rejects certificates without an organisation", () => {
    expect(decideTrust({ ...base, signature: sig("CN=Igor Pavlov") }).action).toBe("reject");
  });
  it("rejects organisations that can't be expressed as a pin", () => {
    expect(decideTrust({ ...base, pins: null, signature: sig("CN=x, O=Evil<Corp>") }).action).toBe("reject");
  });
  it("rejects hash drift by default", () => {
    expect(decideTrust({ ...base, actualSha256: G })).toMatchObject({ action: "reject", reason: expect.stringMatching(/sha256 mismatch/) });
  });
  it("holds hash drift only for a pinned signer when the app allows it", () => {
    expect(decideTrust({ ...base, actualSha256: G, allowHashDrift: true })).toMatchObject({ action: "hold", reason: "HASH_DRIFT" });
    expect(decideTrust({ ...base, actualSha256: G, allowHashDrift: true, pins: null }).action).toBe("reject");
    expect(decideTrust({ ...base, actualSha256: G, allowHashDrift: true, signature: sig("O=Other") }).action).toBe("reject");
  });
  it("hash comparison is case-insensitive", () => {
    expect(decideTrust({ ...base, catalogSha256: H.toUpperCase() }).action).toBe("publish");
  });
});

describe("pin helpers", () => {
  it("reads the organisation from Windows and OpenSSL subjects", () => {
    expect(signerOrgOf("CN=Google LLC\r\nO=Google LLC\r\nC=US")).toBe("Google LLC");
    expect(signerOrgOf("/C=US/O=Notepad++/CN=Notepad++")).toBe("Notepad++");
    expect(signerOrgOf("CN=nobody")).toBeNull();
  });
  it("appends pins without duplicates and caps the list", () => {
    expect(appendPin(null, "A Corp")).toBe("O=A Corp");
    expect(appendPin("O=A Corp", "a corp")).toBe("O=A Corp");
    expect(appendPin("O=A Corp", "B Inc.")).toBe("O=A Corp; O=B Inc.");
    expect(() => appendPin("O=Aa; O=Bb; O=Cc; O=Dd", "Ee")).toThrow(/already has 4/);
    expect(() => appendPin(null, "bad;org")).toThrow(/cannot be pinned/);
  });
});
