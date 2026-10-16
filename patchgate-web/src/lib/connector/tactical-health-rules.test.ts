import { describe, expect, it } from "vitest";
import { isTacticalNatsDown, TACTICAL_MESSAGING_DOWN_NOTE } from "./policy";
import { decideTacticalAlert, tacticalHealthAlertKey, tacticalHealthLabel, tacticalHealthView, TACTICAL_UNHEALTHY_AFTER_MS, unhealthyForMs } from "./tactical-health-rules";

const NOW = new Date("2026-10-17T10:00:00Z");
const ago = (ms: number) => new Date(NOW.getTime() - ms).toISOString();
const hb = (tacticalHealth: unknown, reachable = true) => ({ version: "1.0.0", cache: { files: 0, bytes: 0 }, tactical: { reachable, agents: 1 }, tacticalHealth });

describe("tacticalHealthView (stored heartbeat = untrusted JSON)", () => {
  it("reads tacticalHealth; falls back to tactical.reachable for older connectors; null for garbage", () => {
    expect(tacticalHealthView(hb({ state: "natsdown", since: ago(60_000), detail: "x", watchdog: { nats: "down", checkedAt: ago(0), restartsLastHour: 2 } }))).toEqual({
      state: "natsdown",
      since: new Date(ago(60_000)),
      detail: "x",
      watchdogRestarts: 2,
      reported: true,
    });
    expect(tacticalHealthView({ tactical: { reachable: false } })).toMatchObject({ state: "unreachable", since: null, reported: false });
    expect(tacticalHealthView({ tactical: { reachable: true } })).toMatchObject({ state: "ok", reported: false });
    expect(tacticalHealthView(hb({ state: "on-fire" }))).toMatchObject({ reported: false }); // invalid → fallback
    expect(tacticalHealthView(null)).toBeNull();
    expect(tacticalHealthView("x")).toBeNull();
    expect(tacticalHealthView({})).toBeNull();
    expect(tacticalHealthView(hb({ state: "ok", since: "not a date" }))).toMatchObject({ state: "ok", since: null });
  });

  it("unhealthyForMs: 0 when ok / unknown start; a future since counts as now", () => {
    const v = tacticalHealthView(hb({ state: "natsdown", since: ago(7 * 60_000) }));
    expect(unhealthyForMs(v, NOW)).toBe(7 * 60_000);
    expect(unhealthyForMs(tacticalHealthView(hb({ state: "natsdown", since: ago(-60_000) })), NOW)).toBe(0);
    expect(unhealthyForMs(tacticalHealthView(hb({ state: "ok", since: ago(7 * 60_000) })), NOW)).toBe(0);
    expect(unhealthyForMs(null, NOW)).toBe(0);
  });
});

describe("decideTacticalAlert", () => {
  const view = (state: string, sinceMs: number | null) => tacticalHealthView(hb({ state, since: sinceMs === null ? null : ago(sinceMs) }));
  it("raises only after the threshold, once per episode, and only for an online connector", () => {
    expect(decideTacticalAlert({ view: view("natsdown", TACTICAL_UNHEALTHY_AFTER_MS - 1000), online: true, alertOpen: false, now: NOW })).toBe("none");
    expect(decideTacticalAlert({ view: view("natsdown", TACTICAL_UNHEALTHY_AFTER_MS + 1000), online: true, alertOpen: false, now: NOW })).toBe("raise");
    expect(decideTacticalAlert({ view: view("unreachable", TACTICAL_UNHEALTHY_AFTER_MS + 1000), online: true, alertOpen: false, now: NOW })).toBe("raise");
    expect(decideTacticalAlert({ view: view("natsdown", TACTICAL_UNHEALTHY_AFTER_MS + 1000), online: true, alertOpen: true, now: NOW })).toBe("none");
    expect(decideTacticalAlert({ view: view("natsdown", TACTICAL_UNHEALTHY_AFTER_MS + 1000), online: false, alertOpen: false, now: NOW })).toBe("none");
    expect(decideTacticalAlert({ view: view("natsdown", null), online: true, alertOpen: false, now: NOW })).toBe("none");
    // older connector: unreachable but untimed → never alerted
    expect(decideTacticalAlert({ view: tacticalHealthView({ tactical: { reachable: false } }), online: true, alertOpen: false, now: NOW })).toBe("none");
  });

  it("recovers an open alert when ok (but not while the connector is offline)", () => {
    expect(decideTacticalAlert({ view: view("ok", 0), online: true, alertOpen: true, now: NOW })).toBe("recover");
    expect(decideTacticalAlert({ view: view("ok", 0), online: true, alertOpen: false, now: NOW })).toBe("none");
    expect(decideTacticalAlert({ view: view("ok", 0), online: false, alertOpen: true, now: NOW })).toBe("none");
    expect(decideTacticalAlert({ view: null, online: true, alertOpen: true, now: NOW })).toBe("none");
  });

  it("labels, keys and the natsdown error classifier", () => {
    expect(tacticalHealthLabel("natsdown")).toBe("messaging down");
    expect(tacticalHealthLabel("unreachable")).toBe("unreachable");
    expect(tacticalHealthLabel("ok")).toBe("healthy");
    expect(tacticalHealthAlertKey("c1")).toBe("tactical-health:c1");
    expect(isTacticalNatsDown("Tactical cannot reach its NATS message bus (natsdown): the script was not sent to the PC: natsdown")).toBe(true);
    expect(isTacticalNatsDown("agent offline")).toBe(false);
    expect(isTacticalNatsDown("natsdownstream")).toBe(false);
    expect(isTacticalNatsDown(null)).toBe(false);
    expect(TACTICAL_MESSAGING_DOWN_NOTE).toBe("Tactical messaging down at the site — retrying automatically");
  });
});
