import { describe, expect, it } from "vitest";
import { keyId } from "@/lib/auth/secret-box";
import { isPlainUrl, openOutboxTarget, openSettingUrl, readSettingUrls, sealOutboxTarget, sealSettingUrl, sealedColumns } from "./webhook-store";

const OLD = "ab".repeat(32);
const NEW = "cd".repeat(32);
const URL_A = "https://hooks.example.com/services/T0/B0/secretA";
const URL_B = "https://hooks.example.com/services/T0/B0/secretB";

describe("webhook URLs at rest", () => {
  it("seals with the current key: no plaintext, no ':' (DB check constraint), key id embedded", () => {
    const box = sealSettingUrl(URL_A, "tenant-a", { current: NEW });
    expect(box).not.toContain("secretA");
    expect(isPlainUrl(box)).toBe(false);
    expect(box.endsWith(`.${keyId(NEW)}`)).toBe(true);
    expect(openSettingUrl(box, "tenant-a", { current: NEW })).toEqual({ url: URL_A, stale: false });
  });

  it("binds a setting box to its scope and keeps setting / outbox boxes apart", () => {
    const box = sealSettingUrl(URL_A, "tenant-a", { current: NEW });
    expect(() => openSettingUrl(box, "tenant-b", { current: NEW })).toThrow();
    expect(() => openOutboxTarget(box, { current: NEW })).toThrow();
    const out = sealOutboxTarget(URL_A, { current: NEW });
    expect(openOutboxTarget(out, { current: NEW }).url).toBe(URL_A);
  });

  it("decrypts with the previous key (stale → rewrite) and refuses without a key", () => {
    const old = sealSettingUrl(URL_A, "platform", { current: OLD });
    expect(openSettingUrl(old, "platform", { current: NEW, previous: OLD })).toEqual({ url: URL_A, stale: true });
    expect(() => openSettingUrl(old, "platform", { current: NEW })).toThrow(/unknown key/);
    expect(() => openSettingUrl(old, "platform", null)).toThrow(/AUTH_ENC_KEY/);
    // legacy plaintext is readable without a key, and always stale
    expect(openOutboxTarget(URL_B, null)).toEqual({ url: URL_B, stale: true });
  });

  it("reads sealed + legacy URLs of a row, keeps undecryptable boxes, and re-seals everything under the current key", () => {
    const ring = { current: NEW, previous: OLD };
    const foreign = sealSettingUrl(URL_B, "tenant-a", { current: "ef".repeat(32) });
    const row = { scope: "tenant-a", webhookUrlsEnc: [sealSettingUrl(URL_A, "tenant-a", { current: OLD }), foreign], webhookUrlsLegacy: [URL_B, URL_A] };
    const r = readSettingUrls(row, ring);
    expect(r).toEqual({ urls: [URL_A, URL_B], undecryptable: [foreign], stale: true });

    const cols = sealedColumns(row.scope, r.urls, r.undecryptable, ring);
    expect(cols.webhookUrlsLegacy).toEqual([]);
    expect(cols.webhookUrlsEnc).toHaveLength(3);
    expect(cols.webhookUrlsEnc.join("|")).not.toContain(":");
    const again = readSettingUrls({ scope: row.scope, ...cols }, { current: NEW });
    expect(again).toEqual({ urls: [URL_A, URL_B], undecryptable: [foreign], stale: false });
  });
});
