import { describe, expect, it, vi } from "vitest";
import { createTacticalClient, TacticalError } from "./client";

const AGENT = "aBcDeFgHiJkLmNoPqRsT";

function client(response: { status?: number; body?: unknown }) {
  const fetchImpl = vi.fn(
    async () =>
      new Response(JSON.stringify(response.body ?? null), { status: response.status ?? 200 }),
  );
  const c = createTacticalClient({
    baseUrl: "https://tactical.bank.local/",
    apiKey: "k".repeat(32),
    timeoutMs: 1000,
    fetchImpl: fetchImpl as unknown as typeof fetch,
  });
  return { c, fetchImpl };
}

describe("Tactical client", () => {
  it("sends X-API-KEY and parses updates", async () => {
    const { c, fetchImpl } = client({
      body: [
        { id: 7, guid: "g", kb: "KB1", title: "x", installed: false, action: "nothing", severity: "Critical", extra: 1 },
      ],
    });
    const ups = await c.getUpdates(AGENT);
    expect(ups[0]).toMatchObject({ id: 7, guid: "g", action: "nothing" });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`https://tactical.bank.local/winupdate/${AGENT}/`);
    expect((init.headers as Record<string, string>)["X-API-KEY"]).toHaveLength(32);
  });

  it("sends the action body when changing approval", async () => {
    const { c, fetchImpl } = client({ body: "ok" });
    await c.setUpdateAction(12, "approve");
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/winupdate\/12\/$/);
    expect(init.method).toBe("PUT");
    expect(JSON.parse(String(init.body))).toEqual({ action: "approve" });
  });

  it("rejects path-injection in agent ids", async () => {
    const { c, fetchImpl } = client({ body: [] });
    await expect(c.getUpdates("../agents")).rejects.toBeInstanceOf(TacticalError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("raises TacticalError on HTTP errors", async () => {
    const { c } = client({ status: 403, body: { detail: "no" } });
    await expect(c.listAgents()).rejects.toMatchObject({ status: 403 });
  });

  it("raises on unexpected payload shape", async () => {
    const { c } = client({ body: { not: "an array" } });
    await expect(c.getUpdates(AGENT)).rejects.toThrow(/Unexpected/);
  });

  it("handles empty software inventory ([]) and populated ({software})", async () => {
    expect(await client({ body: [] }).c.getSoftware(AGENT)).toEqual([]);
    const sw = await client({ body: { software: [{ name: "7-Zip", version: "24.08" }] } }).c.getSoftware(AGENT);
    expect(sw[0]).toMatchObject({ name: "7-Zip", version: "24.08" });
  });
});
