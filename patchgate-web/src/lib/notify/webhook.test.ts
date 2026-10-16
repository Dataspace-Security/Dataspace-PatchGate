import { describe, expect, it, vi } from "vitest";
import { maskWebhookUrl, parseAllowedHosts, postWebhook, validateWebhookUrl } from "./webhook";

const HOSTS = ["hooks.slack.com", "bank.webhook.office.com"];
const publicLookup = async () => [{ address: "52.1.2.3" }];

function fakeFetch(status = 200) {
  return vi.fn<(url: string, init: RequestInit) => Promise<Response>>(async () => new Response("ok", { status }));
}

describe("webhook SSRF guard", () => {
  it("parses the allow-list: DNS names only", () => {
    expect(parseAllowedHosts(" hooks.slack.com, 10.0.0.1 ,localhost;Bank.Webhook.Office.com. ")).toEqual(["hooks.slack.com", "bank.webhook.office.com"]);
    expect(parseAllowedHosts(undefined)).toEqual([]);
  });

  it("refuses http, IP literals, ports, credentials and hosts not allow-listed (no request made)", async () => {
    for (const url of [
      "http://hooks.slack.com/services/x",
      "https://127.0.0.1/x",
      "https://[::1]/x",
      "https://hooks.slack.com:8443/x",
      "https://u:p@hooks.slack.com/x",
      "https://evil.example.com/x",
      "https://hooks.slack.com.evil.example/x",
    ]) {
      const f = fakeFetch();
      const r = await postWebhook(url, { text: "t" }, { allowedHosts: HOSTS, fetchImpl: f as unknown as typeof fetch, lookup: publicLookup });
      expect(r, url).toMatchObject({ ok: false, permanent: true });
      expect(f).not.toHaveBeenCalled();
    }
  });

  it("refuses an allow-listed host that resolves to a private address", async () => {
    for (const address of ["10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "fd00::1"]) {
      const f = fakeFetch();
      const r = await postWebhook("https://hooks.slack.com/services/x", {}, { allowedHosts: HOSTS, fetchImpl: f as unknown as typeof fetch, lookup: async () => [{ address: "52.1.2.3" }, { address }] });
      expect(r, address).toMatchObject({ ok: false, permanent: true });
      expect(f).not.toHaveBeenCalled();
    }
  });

  it("posts JSON without following redirects, and classifies HTTP errors", async () => {
    const f = fakeFetch(200);
    expect(await postWebhook("https://hooks.slack.com/services/x", { text: "hi" }, { allowedHosts: HOSTS, fetchImpl: f as unknown as typeof fetch, lookup: publicLookup })).toEqual({ ok: true, status: 200 });
    const init = f.mock.calls[0][1];
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("manual");
    expect(JSON.parse(String(init.body))).toEqual({ text: "hi" });

    const post = (status: number) => postWebhook("https://hooks.slack.com/x", {}, { allowedHosts: HOSTS, fetchImpl: fakeFetch(status) as unknown as typeof fetch, lookup: publicLookup });
    expect(await post(302)).toMatchObject({ ok: false, permanent: true });
    expect(await post(404)).toMatchObject({ ok: false, permanent: true });
    expect(await post(429)).toMatchObject({ ok: false, permanent: false });
    expect(await post(503)).toMatchObject({ ok: false, permanent: false });
  });

  it("network errors and timeouts are retryable", async () => {
    const f = vi.fn(async () => {
      throw new DOMException("t", "TimeoutError");
    });
    expect(await postWebhook("https://hooks.slack.com/x", {}, { allowedHosts: HOSTS, fetchImpl: f as unknown as typeof fetch, lookup: publicLookup })).toEqual({ ok: false, permanent: false, error: "timed out" });
  });

  it("validates for storage and masks for display", () => {
    expect(() => validateWebhookUrl("https://hooks.slack.com/x", [])).toThrow(/disabled/);
    expect(() => validateWebhookUrl("https://evil.example/x", HOSTS)).toThrow(/not allowed/);
    expect(validateWebhookUrl(" https://hooks.slack.com/services/T/B/secret#frag ", HOSTS)).toBe("https://hooks.slack.com/services/T/B/secret");
    expect(maskWebhookUrl("https://hooks.slack.com/services/T/B/abcdSECRET")).toBe("https://hooks.slack.com/…CRET");
  });
});
