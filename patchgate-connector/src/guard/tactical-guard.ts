import { readFile } from "node:fs/promises";
import { z } from "zod";
import { tacticalAuditSync } from "../jobs/tactical-audit.ts";
import { PatchGateError, type PatchGateClient } from "../pg-client.ts";
import {
  approvalResetSchema,
  guardAllowEntrySchema,
  MAX_PUSH_APPROVAL_RESETS,
  MAX_PUSH_AUDIT_EVENTS,
  type ApprovalReset,
  type Heartbeat,
  type JobPayload,
  type TacticalPush,
} from "../protocol.ts";
import { TacticalError, type TacticalClient } from "../tactical/client.ts";
import { AbortedError, sleep } from "../util/backoff.ts";
import { writeFileAtomic } from "../util/fsx.ts";
import { errorMessage, type Logger } from "../util/log.ts";
import { AllowSet, MAX_ALLOW_AGENTS } from "./allow-set.ts";

/**
 * Real-time Tactical guard (protocol §8; RUNBOOK "Tactical is sealed"). Every intervalMs (default 30 s):
 *
 *  1. Approvals — Tactical 1.5.x does not audit update approvals, so they are read: one GET /agents/ (each agent
 *     carries has_patches_pending) and GET /winupdate/<agent>/ only for agents with pending approvals (PCs
 *     without an open PatchGate window first, then in-flight PCs in rotation), at most maxAgentReadsPerTick. An
 *     approval PatchGate did not authorise is reset at once (action "nothing", same as RESET_APPROVALS) and
 *     reported; PatchGate's own approvals of an open window are never touched; leftovers of a window that ended
 *     are withdrawn quietly. Nothing is reset while the allow-set is unknown (after a start, until every
 *     part of PatchGate's signed TACTICAL_GUARD_SYNC arrived).
 *  2. Audit log — read from the local cursor (small pages); out-of-band entries are pushed to PatchGate.
 *  3. Push — POST /tactical-events (signed like every connector request), bounded batches; the cursor and the
 *     report outbox move only after PatchGate accepted the batch (at-least-once, PatchGate de-duplicates).
 * TACTICAL_AUDIT_SYNC jobs and PatchGate's COLLECT comparison stay as catch-up / backstop.
 * State (allow-set, cursor, unsent reports) lives in stateDir/tactical-guard.json (0600).
 */

const DEFAULT_AUDIT_PAGE_SIZE = 50;
const MAX_PUSHES_PER_TICK = 5;
const MAX_OUTBOX = 1000;
/** A reset Tactical keeps refusing is reported again at most this often. */
const FAILED_RESET_REPORT_EVERY_MS = 60 * 60_000;
/** Incomplete TACTICAL_GUARD_SYNC sets kept at once (a newer sync replaces older ones). */
const MAX_PENDING_SYNCS = 3;
const AGENT_ID_RE = /^[A-Za-z0-9_-]{6,64}$/;

const stateSchema = z.object({
  v: z.literal(1),
  allow: z.array(guardAllowEntrySchema).max(MAX_ALLOW_AGENTS),
  auditCursor: z.number().int().min(0).nullable(),
  outbox: z.array(approvalResetSchema).max(MAX_OUTBOX),
});

export interface TacticalGuardOptions {
  tactical: TacticalClient;
  pg: PatchGateClient;
  stateFile: string;
  /** 0 = guard off (TACTICAL_AUDIT_SYNC + COLLECT backstop only). */
  intervalMs: number;
  maxAgentReadsPerTick: number;
  auditPageSize?: number;
  log: Logger;
  now?: () => number;
}

export interface GuardTickSummary {
  skipped?: "disabled" | "allow-set unknown";
  agentsRead: number;
  resets: number;
  reported: number;
  auditEvents: number;
  pushes: number;
}

type GuardStatus = NonNullable<Heartbeat["guard"]>;
type SyncPayload = JobPayload<"TACTICAL_GUARD_SYNC">;

export class TacticalGuard {
  private allow = new AllowSet();
  private auditCursor: number | null = null;
  private outbox: ApprovalReset[] = [];
  private known = false;
  private dirty = false;
  private readonly pendingSyncs = new Map<string, Map<number, SyncPayload>>();
  private readonly busy = new Map<string, number>();
  private readonly failedReported = new Map<string, number>();
  private rotation = 0;
  private resetsTotal = 0;
  private lastCheckAt: string | null = null;
  private lastError: string | null = null;
  private readonly stopCtl = new AbortController();
  private loop: Promise<void> | undefined;
  private ticking: Promise<GuardTickSummary> | undefined;

  private constructor(private readonly o: TacticalGuardOptions) {}

  static async open(o: TacticalGuardOptions): Promise<TacticalGuard> {
    const g = new TacticalGuard(o);
    let text: string | undefined;
    try {
      text = await readFile(o.stateFile, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") o.log.warn("tactical guard state unreadable; starting empty", { error: errorMessage(err) });
    }
    if (text !== undefined) {
      let parsed: z.ZodSafeParseResult<z.infer<typeof stateSchema>> | undefined;
      try {
        parsed = stateSchema.safeParse(JSON.parse(text));
      } catch {
        parsed = undefined;
      }
      if (parsed?.success) {
        g.allow = AllowSet.fromEntries(parsed.data.allow);
        g.auditCursor = parsed.data.auditCursor;
        g.outbox = parsed.data.outbox;
      } else {
        o.log.warn("tactical guard state invalid; starting empty (PatchGate re-sends the allow-set)");
      }
    }
    return g;
  }

  private now(): number {
    return (this.o.now ?? Date.now)();
  }

  get enabled(): boolean {
    return this.o.intervalMs > 0;
  }

  get allowSetKnown(): boolean {
    return this.known;
  }

  get cursor(): number | null {
    return this.auditCursor;
  }

  get pendingReports(): readonly ApprovalReset[] {
    return this.outbox;
  }

  status(): GuardStatus {
    return {
      enabled: this.enabled,
      allowSetKnown: this.known,
      intervalSec: Math.round(this.o.intervalMs / 1000),
      lastCheckAt: this.lastCheckAt,
      resets: this.resetsTotal,
      error: this.lastError,
    };
  }

  /** A verified DEPLOY_WINDOWS job: PatchGate authorises these guids on this PC until the job's window ends. */
  allowDeployment(agentId: string, guids: readonly string[], expiresAtIso: string): void {
    this.allow.add(agentId, guids, Date.parse(expiresAtIso));
    this.dirty = true;
  }

  /** TACTICAL_GUARD_SYNC part (signed, verified by the runner). The allow-set becomes known once all parts are in. */
  async applySync(p: SyncPayload): Promise<{ allowEntries: number; known: boolean }> {
    const parts = this.pendingSyncs.get(p.syncId) ?? new Map<number, SyncPayload>();
    if (parts.size > 0 && [...parts.values()][0]!.parts !== p.parts) throw new Error("TACTICAL_GUARD_SYNC parts disagree");
    parts.set(p.part, p);
    this.pendingSyncs.delete(p.syncId);
    this.pendingSyncs.set(p.syncId, parts);
    while (this.pendingSyncs.size > MAX_PENDING_SYNCS) this.pendingSyncs.delete(this.pendingSyncs.keys().next().value!);
    if (parts.size === p.parts) {
      // Union with what this connector recorded itself: allowing more never resets one of PatchGate's approvals.
      for (const part of parts.values()) for (const e of part.allow) this.allow.add(e.agentId, e.guids, Date.parse(e.until));
      this.auditCursor = Math.max(this.auditCursor ?? 0, p.auditCursor);
      this.pendingSyncs.delete(p.syncId);
      if (!this.known) this.o.log.info("tactical guard armed: allow-set received from PatchGate", { agents: this.allow.size, auditCursor: this.auditCursor });
      this.known = true;
      this.dirty = true;
      await this.persist();
    }
    return { allowEntries: this.allow.size, known: this.known };
  }

  /** Run fn while the guard leaves this PC alone (DEPLOY_WINDOWS / RESET_APPROVALS executing on it). */
  async busyAgent<T>(agentId: string, fn: () => Promise<T>): Promise<T> {
    this.busy.set(agentId, (this.busy.get(agentId) ?? 0) + 1);
    try {
      return await fn();
    } finally {
      const n = (this.busy.get(agentId) ?? 1) - 1;
      if (n <= 0) this.busy.delete(agentId);
      else this.busy.set(agentId, n);
    }
  }

  /** One guard round (tests call it directly). Never throws. Concurrent calls share the running round. */
  tick(): Promise<GuardTickSummary> {
    this.ticking ??= this.runTick().finally(() => {
      this.ticking = undefined;
    });
    return this.ticking;
  }

  private async runTick(): Promise<GuardTickSummary> {
    const s: GuardTickSummary = { agentsRead: 0, resets: 0, reported: 0, auditEvents: 0, pushes: 0 };
    if (!this.enabled) return { ...s, skipped: "disabled" };
    if (!this.known) return { ...s, skipped: "allow-set unknown" };
    const errors: string[] = [];
    try {
      await this.checkApprovals(s);
    } catch (err) {
      errors.push(`approvals: ${errorMessage(err)}`);
    }
    try {
      await this.readAuditAndPush(s);
    } catch (err) {
      errors.push(`report: ${errorMessage(err)}`);
    }
    if (this.allow.prune(this.now()) > 0) this.dirty = true;
    this.lastCheckAt = new Date(this.now()).toISOString();
    this.lastError = errors.length ? errors.join("; ").slice(0, 2000) : null;
    if (errors.length) this.o.log.warn("tactical guard round incomplete", { error: this.lastError });
    try {
      await this.persist();
    } catch (err) {
      this.o.log.warn("tactical guard state not saved", { error: errorMessage(err) });
    }
    return s;
  }

  /** Agents to read this round: pending approvals without an open PatchGate window first, then in-flight ones. */
  private candidates(agents: Awaited<ReturnType<TacticalClient["listAgents"]>>, nowMs: number): string[] {
    const max = this.o.maxAgentReadsPerTick;
    const ids = agents.map((a) => a.agent_id).filter((id) => AGENT_ID_RE.test(id) && !this.busy.has(id));
    const flagKnown = agents.some((a) => typeof a.has_patches_pending === "boolean");
    const rotate = (list: string[], take: number): string[] => {
      if (list.length === 0 || take <= 0) return [];
      const start = this.rotation % list.length;
      this.rotation += take;
      return [...list.slice(start), ...list.slice(0, start)].slice(0, take);
    };
    if (!flagKnown) return rotate(ids, max); // older Tactical without the flag: round-robin over every PC
    const pending = new Set(agents.filter((a) => a.has_patches_pending === true).map((a) => a.agent_id));
    const flagged = ids.filter((id) => pending.has(id));
    const idle = flagged.filter((id) => !this.allow.inFlight(id, nowMs)).slice(0, max);
    return [...idle, ...rotate(flagged.filter((id) => this.allow.inFlight(id, nowMs)), max - idle.length)];
  }

  private async checkApprovals(s: GuardTickSummary): Promise<void> {
    const agents = await this.o.tactical.listAgents();
    const host = new Map(agents.map((a) => [a.agent_id, a.hostname]));
    for (const agentId of this.candidates(agents, this.now())) {
      if (this.stopCtl.signal.aborted) return;
      let updates;
      try {
        updates = await this.o.tactical.getUpdates(agentId);
      } catch (err) {
        if (err instanceof TacticalError && err.status === undefined) throw err; // Tactical down: end the round
        this.o.log.debug("tactical guard: updates not readable", { agentId, error: errorMessage(err) });
        continue;
      }
      s.agentsRead++;
      const foreign: Array<{ u: (typeof updates)[number]; error: string | null }> = [];
      for (const u of updates) {
        if (u.installed || u.action !== "approve") continue;
        const cls = this.allow.classify(agentId, u.guid, this.now());
        if (cls === "allowed" || this.busy.has(agentId)) continue;
        let error: string | null = null;
        try {
          await this.o.tactical.setUpdateAction(u.id, "nothing");
        } catch (err) {
          error = errorMessage(err).slice(0, 300);
        }
        if (cls === "own-expired") {
          this.o.log.info("PatchGate approval withdrawn after its window ended", { agentId, kb: u.kb, ok: error === null });
          continue;
        }
        foreign.push({ u, error });
      }
      if (foreign.length === 0) continue;
      await this.verifyResets(agentId, foreign);
      for (const { u, error } of foreign) {
        if (error === null) {
          s.resets++;
          this.resetsTotal++;
          this.o.log.warn("approval set outside PatchGate reset", { agentId, kb: u.kb, guid: u.guid, security: true });
        } else {
          const key = `${agentId}|${u.guid.toLowerCase()}`;
          const last = this.failedReported.get(key);
          if (last !== undefined && this.now() - last < FAILED_RESET_REPORT_EVERY_MS) continue;
          this.failedReported.set(key, this.now());
          this.o.log.error("approval set outside PatchGate could NOT be reset", { agentId, kb: u.kb, error, security: true });
        }
        this.enqueueReport({
          agentId,
          hostname: host.get(agentId)?.slice(0, 255) ?? null,
          guid: u.guid.slice(0, 64),
          kb: u.kb?.slice(0, 64) ?? null,
          title: u.title?.slice(0, 300) ?? null,
          detectedAt: new Date(this.now()).toISOString(),
          reset: error === null,
          error,
        });
        s.reported++;
      }
    }
  }

  /** Re-read once: a Tactical patch policy that auto-approves puts the approval straight back. */
  private async verifyResets(agentId: string, foreign: Array<{ u: { id: number }; error: string | null }>): Promise<void> {
    try {
      const after = new Map((await this.o.tactical.getUpdates(agentId)).map((u) => [u.id, u]));
      for (const f of foreign) {
        const now = after.get(f.u.id);
        if (f.error === null && now && !now.installed && now.action === "approve") {
          f.error = "still approved after the reset: a Tactical patch policy auto-approves (set every severity to manual)";
        }
      }
    } catch (err) {
      this.o.log.debug("tactical guard: reset not verified", { agentId, error: errorMessage(err) });
    }
  }

  private enqueueReport(r: ApprovalReset): void {
    this.outbox.push(r);
    if (this.outbox.length > MAX_OUTBOX) {
      const dropped = this.outbox.length - MAX_OUTBOX;
      this.outbox = this.outbox.slice(dropped);
      this.o.log.error("tactical guard outbox full; oldest unsent reports dropped (PatchGate unreachable?)", { dropped });
    }
    this.dirty = true;
  }

  private async readAuditAndPush(s: GuardTickSummary): Promise<void> {
    for (let i = 0; i < MAX_PUSHES_PER_TICK; i++) {
      let audit: TacticalPush["audit"];
      let more = false;
      if (this.auditCursor !== null) {
        const afterId = this.auditCursor;
        const r = await tacticalAuditSync(this.o.tactical, { afterId, limit: MAX_PUSH_AUDIT_EVENTS }, this.o.auditPageSize ?? DEFAULT_AUDIT_PAGE_SIZE);
        more = r.more;
        if (r.events.length > 0 || r.reset) {
          audit = { afterId, events: r.events, cursor: r.cursor, ...(r.reset ? { reset: true } : {}) };
        } else if (r.cursor !== afterId) {
          this.auditCursor = r.cursor; // only PatchGate's own entries: nothing to report
          this.dirty = true;
        }
      }
      const resets = this.outbox.slice(0, MAX_PUSH_APPROVAL_RESETS);
      if (!audit && resets.length === 0) return;
      const push: TacticalPush = { ...(audit ? { audit } : {}), ...(resets.length ? { approvalResets: resets } : {}) };
      try {
        await this.o.pg.pushTacticalEvents(push, this.stopCtl.signal);
      } catch (err) {
        if (err instanceof AbortedError || this.stopCtl.signal.aborted) return;
        if (!(err instanceof PatchGateError) || err.retryable) throw err; // kept; sent again next round
        // PatchGate refuses this batch for good (400/413/422): never loop on it.
        this.o.log.error("PatchGate refused a tactical guard report; dropped", { status: err.status, events: audit?.events.length ?? 0, resets: resets.length });
      }
      if (audit) this.auditCursor = audit.cursor;
      this.outbox = this.outbox.slice(resets.length);
      this.dirty = true;
      s.pushes++;
      s.auditEvents += audit?.events.length ?? 0;
      if (!more && this.outbox.length === 0) return;
    }
  }

  private async persist(): Promise<void> {
    if (!this.dirty) return;
    this.dirty = false;
    const state: z.infer<typeof stateSchema> = { v: 1, allow: this.allow.toEntries(), auditCursor: this.auditCursor, outbox: this.outbox };
    try {
      await writeFileAtomic(this.o.stateFile, JSON.stringify(state), 0o600);
    } catch (err) {
      this.dirty = true;
      throw err;
    }
  }

  start(): void {
    if (!this.enabled || this.loop) return;
    this.loop = (async () => {
      while (!this.stopCtl.signal.aborted) {
        try {
          await sleep(this.o.intervalMs, this.stopCtl.signal);
        } catch {
          return;
        }
        await this.tick();
      }
    })();
  }

  async stop(): Promise<void> {
    this.stopCtl.abort();
    await this.loop;
    await this.ticking;
    try {
      await this.persist();
    } catch (err) {
      this.o.log.warn("tactical guard state not saved on stop", { error: errorMessage(err) });
    }
  }
}
