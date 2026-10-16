import { describe, expect, it } from "vitest";
import { requireSameOrigin } from "./session";

const req = (headers: Record<string, string>) => new Request("https://patchgate.bank.local/api/x", { method: "POST", headers });

describe("requireSameOrigin", () => {
  it("accepts same-origin requests", () => {
    expect(() => requireSameOrigin(req({ origin: "https://patchgate.bank.local", host: "patchgate.bank.local" }))).not.toThrow();
  });
  it("honours the reverse proxy forwarded host", () => {
    expect(() =>
      requireSameOrigin(req({ origin: "https://patchgate.bank.local", host: "127.0.0.1:3000", "x-forwarded-host": "patchgate.bank.local" })),
    ).not.toThrow();
  });
  it.each([
    ["cross-site origin", { origin: "https://evil.example", host: "patchgate.bank.local" }],
    ["missing origin", { host: "patchgate.bank.local" }],
    ["null origin", { origin: "null", host: "patchgate.bank.local" }],
  ])("blocks %s", (_n, h) => {
    expect(() => requireSameOrigin(req(h))).toThrow();
  });
});
