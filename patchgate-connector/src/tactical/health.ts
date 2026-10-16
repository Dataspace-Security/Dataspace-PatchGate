import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { TacticalHealth } from "../protocol.ts";
import { errorMessage, type Logger } from "../util/log.ts";
import { NATS_DOWN, TacticalError, type TacticalClient } from "./client.ts";

/**
 * Tactical health for the heartbeat (protocol §6 tacticalHealth): ok | natsdown | unreachable, since when.
 * Two sources, the more pessimistic wins:
 *  - the connector's own Tactical calls (observeTactical wraps the client): no answer from the API = unreachable;
 *    a script run answered "natsdown" = Tactical cannot reach its NATS bus; any other script answer = NATS works;
 *  - the site's host watchdog (installers/site/tactical/tactical-watchdog.sh), which checks nats-server every minute
 *    and writes <config dir>/tactical-health.json (read-only mount). It is the only source while no script runs.
 *    A file older than WATCHDOG_FRESH_MS is ignored (watchdog stopped / not installed).
 */

export const WATCHDOG_FRESH_MS = 5 * 60_000;
const DETAIL_MAX = 300;

const iso = z.string().max(40).refine((s) => Number.isFinite(Date.parse(s)), "ISO date");
export const watchdogFileSchema = z.object({
  v: z.literal(1),
  nats: z.enum(["ok", "down", "starting", "unknown"]),
  since: iso.nullable(),
  checkedAt: iso,
  restartsLastHour: z.number().int().min(0).max(1000),
  lastRestartAt: iso.nullable(),
  detail: z.string().max(DETAIL_MAX).optional(),
});
export type WatchdogFile = z.infer<typeof watchdogFileSchema>;

export function parseWatchdogFile(text: string): WatchdogFile | null {
  try {
    const r = watchdogFileSchema.safeParse(JSON.parse(text));
    return r.success ? r.data : null;
  } catch {
    return null;
  }
}

type State = TacticalHealth["state"];

export interface TacticalHealthOptions {
  /** Watchdog health file (undefined = no watchdog source). */
  healthFile?: string;
  log: Logger;
  now?: () => number;
}

const clip = (s: string): string => s.replace(/[^\x20-\x7e]/g, " ").slice(0, DETAIL_MAX);

export class TacticalHealthTracker {
  private readonly now: () => number;
  private unreachableSince: number | null = null;
  private unreachableDetail = "";
  private natsDownSince: number | null = null;
  private current: { state: State; since: number; detail: string | null };
  private fileWarned = false;

  constructor(private readonly opts: TacticalHealthOptions) {
    this.now = opts.now ?? Date.now;
    this.current = { state: "ok", since: this.now(), detail: null };
  }

  /** Tactical's API answered (any HTTP status that is not a gateway error). */
  apiOk(): void {
    this.unreachableSince = null;
  }

  /** No (valid) answer from Tactical's API. */
  apiDown(detail: string): void {
    this.unreachableSince ??= this.now();
    this.unreachableDetail = clip(detail);
  }

  /** A script run was answered with "natsdown": nothing reached the PC. */
  natsDown(): void {
    this.apiOk();
    this.natsDownSince ??= this.now();
  }

  /** A script run got a real answer: Tactical reached NATS. */
  natsOk(): void {
    this.apiOk();
    this.natsDownSince = null;
  }

  private async readWatchdog(): Promise<WatchdogFile | null> {
    if (!this.opts.healthFile) return null;
    let text: string;
    try {
      text = await readFile(this.opts.healthFile, "utf8");
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && !this.fileWarned) {
        this.fileWarned = true;
        this.opts.log.warn("cannot read the site watchdog's Tactical health file", { file: this.opts.healthFile, error: errorMessage(err) });
      }
      return null;
    }
    const wd = parseWatchdogFile(text.slice(0, 4096));
    if (!wd) return null;
    const age = this.now() - Date.parse(wd.checkedAt);
    // stale (watchdog stopped) or from the future (clock jump): not a usable source
    return age <= WATCHDOG_FRESH_MS && age >= -WATCHDOG_FRESH_MS ? wd : null;
  }

  /** Current health (reads the watchdog file; call once per heartbeat). */
  async snapshot(): Promise<TacticalHealth> {
    const wd = await this.readWatchdog();
    const now = this.now();
    // The watchdog saw NATS healthy AFTER our last natsdown answer: the episode is over.
    if (wd && wd.nats === "ok" && this.natsDownSince !== null && Date.parse(wd.checkedAt) > this.natsDownSince) this.natsDownSince = null;
    // "starting" with a since = the watchdog restarted trmm-nats inside a down episode (still down).
    const wdDown = wd !== null && (wd.nats === "down" || (wd.nats === "starting" && wd.since !== null));
    let state: State = "ok";
    let since: number | null = null;
    let detail: string | null = null;
    if (this.unreachableSince !== null) {
      state = "unreachable";
      since = this.unreachableSince;
      detail = this.unreachableDetail || "Tactical API unreachable";
    } else if (wdDown || this.natsDownSince !== null) {
      state = "natsdown";
      const wdSince = wdDown && wd.since ? Date.parse(wd.since) : null;
      since = Math.min(...[wdSince, this.natsDownSince].filter((t): t is number => t !== null && Number.isFinite(t)), now);
      detail = wdDown ? `site watchdog: ${wd.detail ?? "NATS down"} (${wd.restartsLastHour} restart(s) in the last hour)` : "Tactical answered natsdown to a script run";
    }
    if (state !== this.current.state) {
      const prev = this.current;
      this.current = { state, since: since ?? now, detail };
      const fields = { from: prev.state, to: state, since: new Date(this.current.since).toISOString(), detail };
      if (state === "ok") this.opts.log.info("Tactical healthy again", fields);
      else this.opts.log.warn(state === "natsdown" ? "Tactical cannot reach its NATS message bus (no PC reachable)" : "Tactical API unreachable", fields);
    } else {
      // same state: keep the episode start (an earlier source may refine it)
      if (since !== null && since < this.current.since) this.current.since = since;
      this.current.detail = detail;
    }
    return {
      state: this.current.state,
      since: new Date(this.current.since).toISOString(),
      detail: this.current.detail,
      watchdog: wd ? { nats: wd.nats, checkedAt: wd.checkedAt, restartsLastHour: wd.restartsLastHour, lastRestartAt: wd.lastRestartAt } : null,
    };
  }
}

/** Gateway statuses nginx returns while Tactical's backend is down (for runScript they may mean "still running"). */
const GATEWAY = new Set([502, 503, 504]);

/**
 * Wrap a Tactical client so every call feeds the health tracker. Behaviour of the calls is unchanged (results and
 * errors pass through as they are).
 */
export function observeTactical(client: TacticalClient, health: TacticalHealthTracker): TacticalClient {
  const observe = <A extends unknown[], R>(name: keyof TacticalClient, fn: (...a: A) => Promise<R>) =>
    async (...args: A): Promise<R> => {
      try {
        const r = await fn(...args);
        if (name === "runScript") health.natsOk();
        else health.apiOk();
        return r;
      } catch (err) {
        if (err instanceof TacticalError) {
          if (err.detail === NATS_DOWN) health.natsDown();
          else if (err.status === undefined) health.apiDown(err.message);
          // A long script run can end in a proxy timeout while Tactical works: not a health signal.
          else if (GATEWAY.has(err.status) && name !== "runScript") health.apiDown(err.message);
          else if (!GATEWAY.has(err.status)) health.apiOk(); // Tactical answered (4xx, 500 …)
        }
        throw err;
      }
    };
  return {
    listAgents: observe("listAgents", client.listAgents.bind(client)),
    getAgent: observe("getAgent", client.getAgent.bind(client)),
    scanUpdates: observe("scanUpdates", client.scanUpdates.bind(client)),
    getUpdates: observe("getUpdates", client.getUpdates.bind(client)),
    setUpdateAction: observe("setUpdateAction", client.setUpdateAction.bind(client)),
    installApproved: observe("installApproved", client.installApproved.bind(client)),
    getSoftware: observe("getSoftware", client.getSoftware.bind(client)),
    refreshSoftware: observe("refreshSoftware", client.refreshSoftware.bind(client)),
    runScript: observe("runScript", client.runScript.bind(client)),
    auditLogPage: observe("auditLogPage", client.auditLogPage.bind(client)),
  };
}
