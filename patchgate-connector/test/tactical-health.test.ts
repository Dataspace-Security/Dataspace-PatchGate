import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { heartbeatSchema } from "../src/protocol.ts";
import { createTacticalClient, TacticalError } from "../src/tactical/client.ts";
import { observeTactical, parseWatchdogFile, TacticalHealthTracker, WATCHDOG_FRESH_MS } from "../src/tactical/health.ts";
import { silentLogger } from "../src/util/log.ts";
import { tempDir } from "./helpers/common.ts";
import { FakeTactical } from "./helpers/fake-tactical.ts";

const KEY = "TACTICAL-HEALTH-KEY-1";
const A1 = "agentAAAA1111";
const T0 = Date.parse("2026-10-17T10:00:00Z");

let dir: string;
let cleanup: () => Promise<void>;
let now: number;
let file: string;
const tracker = () => new TacticalHealthTracker({ healthFile: file, log: silentLogger, now: () => now });
const wd = (over: Record<string, unknown> = {}) =>
  writeFile(file, JSON.stringify({ v: 1, nats: "ok", since: null, checkedAt: new Date(now).toISOString(), restartsLastHour: 0, lastRestartAt: null, detail: "nats-server running", ...over }));

beforeEach(async () => {
  ({ dir, cleanup } = await tempDir("pgc-health-"));
  file = join(dir, "tactical-health.json");
  now = T0;
});
afterEach(async () => cleanup());

describe("TacticalHealthTracker", () => {
  it("starts ok; no watchdog file = connector observations only", async () => {
    const h = await tracker().snapshot();
    expect(h).toEqual({ state: "ok", since: new Date(T0).toISOString(), detail: null, watchdog: null });
    expect(heartbeatSchema.shape.tacticalHealth.safeParse(h).success).toBe(true);
  });

  it("natsdown from a script answer keeps its first 'since' until a script gets through", async () => {
    const t = tracker();
    t.natsDown();
    now += 60_000;
    t.natsDown();
    now += 60_000;
    const down = await t.snapshot();
    expect(down).toMatchObject({ state: "natsdown", since: new Date(T0).toISOString() });
    t.natsOk();
    const ok = await t.snapshot();
    expect(ok).toMatchObject({ state: "ok", since: new Date(now).toISOString(), detail: null });
  });

  it("the watchdog's 'down' (and 'starting' inside a down episode) is natsdown since the watchdog's since", async () => {
    const t = tracker();
    await wd({ nats: "down", since: new Date(T0 - 10 * 60_000).toISOString(), restartsLastHour: 2, lastRestartAt: new Date(T0 - 60_000).toISOString(), detail: "next restart in 60s (back-off)" });
    const h = await t.snapshot();
    expect(h).toMatchObject({ state: "natsdown", since: new Date(T0 - 10 * 60_000).toISOString(), watchdog: { nats: "down", restartsLastHour: 2 } });
    expect(h.detail).toMatch(/site watchdog: next restart in 60s.*2 restart/);
    await wd({ nats: "starting", since: new Date(T0 - 10 * 60_000).toISOString(), restartsLastHour: 3 });
    expect((await t.snapshot()).state).toBe("natsdown");
    // a container that simply started (no down episode) is not down
    await wd({ nats: "starting", since: null });
    expect((await t.snapshot()).state).toBe("ok");
  });

  it("a newer watchdog 'ok' ends a natsdown episode observed by the connector; an older one does not", async () => {
    const t = tracker();
    await wd({ nats: "ok", checkedAt: new Date(T0 - 30_000).toISOString() });
    t.natsDown();
    expect((await t.snapshot()).state).toBe("natsdown");
    now += 60_000;
    await wd({ nats: "ok" });
    expect((await t.snapshot()).state).toBe("ok");
  });

  it("ignores a stale, future-dated or malformed watchdog file", async () => {
    const t = tracker();
    await wd({ nats: "down", since: new Date(T0).toISOString(), checkedAt: new Date(T0 - WATCHDOG_FRESH_MS - 1000).toISOString() });
    expect(await t.snapshot()).toMatchObject({ state: "ok", watchdog: null });
    await wd({ nats: "down", since: new Date(T0).toISOString(), checkedAt: new Date(T0 + WATCHDOG_FRESH_MS + 60_000).toISOString() });
    expect((await t.snapshot()).state).toBe("ok");
    await writeFile(file, '{"v":1,"nats":"exploded"}');
    expect((await t.snapshot()).state).toBe("ok");
    expect(parseWatchdogFile("not json")).toBeNull();
    expect(parseWatchdogFile(JSON.stringify({ v: 2, nats: "ok", since: null, checkedAt: new Date().toISOString(), restartsLastHour: 0, lastRestartAt: null }))).toBeNull();
  });

  it("unreachable wins over natsdown and clears when the API answers again", async () => {
    const t = tracker();
    t.natsDown();
    now += 1000;
    t.apiDown("Tactical unreachable (GET /agents/): ECONNREFUSED");
    expect(await t.snapshot()).toMatchObject({ state: "unreachable", detail: expect.stringContaining("ECONNREFUSED") });
    t.apiOk();
    expect((await t.snapshot()).state).toBe("natsdown"); // the API is back, NATS still unproven
  });
});

describe("observeTactical (real client against a fake Tactical)", () => {
  let tactical: FakeTactical;
  beforeEach(async () => {
    tactical = new FakeTactical({ apiKey: KEY });
    await tactical.start();
    tactical.addAgent({ agent_id: A1 });
  });
  afterEach(async () => tactical.stop());

  const client = (t: TacticalHealthTracker) => observeTactical(createTacticalClient({ baseUrl: tactical.url, apiKey: KEY, timeoutMs: 5000 }), t);

  it("Tactical's natsdown answer → heartbeat tacticalHealth natsdown; errors pass through unchanged", async () => {
    const t = new TacticalHealthTracker({ log: silentLogger });
    const c = client(t);
    tactical.onRunScript = async () => "natsdown";
    const err = await c.runScript(A1, { scriptId: 1, envVars: {}, timeoutSec: 30 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TacticalError);
    expect((err as TacticalError).detail).toBe("natsdown");
    const hb = { version: "1.0.0", cache: { files: 0, bytes: 0 }, tactical: { reachable: true, agents: 1 }, tacticalHealth: await t.snapshot() };
    expect(heartbeatSchema.parse(hb).tacticalHealth).toMatchObject({ state: "natsdown", detail: expect.stringContaining("natsdown") });
    // other calls keep working (the API answers) without ending the NATS episode
    await c.listAgents();
    expect((await t.snapshot()).state).toBe("natsdown");
    // a script that gets through proves NATS works again
    tactical.onRunScript = async () => "PATCHGATE_RESULT ok";
    await c.runScript(A1, { scriptId: 1, envVars: {}, timeoutSec: 30 });
    expect((await t.snapshot()).state).toBe("ok");
  });

  it("no answer from the API → unreachable; a proxy timeout on a script run is not a health signal", async () => {
    const t = new TacticalHealthTracker({ log: silentLogger });
    const c = client(t);
    tactical.runScriptStatus = { status: 504, body: "gateway timeout" };
    await expect(c.runScript(A1, { scriptId: 1, envVars: {}, timeoutSec: 30 })).rejects.toBeInstanceOf(TacticalError);
    expect((await t.snapshot()).state).toBe("ok");
    await tactical.stop();
    await expect(c.listAgents()).rejects.toThrow(/unreachable/);
    expect((await t.snapshot()).state).toBe("unreachable");
    await tactical.start(); // afterEach stops it again
  });
});
