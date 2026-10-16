import type { GuardAllowEntry } from "../protocol.ts";

/**
 * The approvals PatchGate authorised on this site's PCs (real-time Tactical guard, protocol §8).
 * Built ONLY from signed jobs: DEPLOY_WINDOWS (guids + window end) and TACTICAL_GUARD_SYNC (PatchGate's baseline).
 *
 *  - "allowed":     the PC's PatchGate window is still open (in-flight deployment) — never touched;
 *  - "own-expired": PatchGate approved it, the window ended (kept OWN_APPROVAL_MEMORY_MS) — withdrawn quietly;
 *  - "foreign":     PatchGate never approved it — reset at once and reported.
 * One entry per PC (union of guids, latest window end); bounded in PCs and guids per PC.
 */

/** Same memory as PatchGate's COLLECT backstop (tactical-activity.ts OWN_APPROVAL_MEMORY_MS). */
export const OWN_APPROVAL_MEMORY_MS = 7 * 24 * 3_600_000;
export const MAX_ALLOW_AGENTS = 25_000;
export const MAX_GUIDS_PER_AGENT = 2000;

export type ApprovalClass = "allowed" | "own-expired" | "foreign";

interface Entry {
  readonly guids: ReadonlySet<string>;
  readonly until: number;
}

const norm = (g: string): string => g.toLowerCase();

export class AllowSet {
  private readonly byAgent = new Map<string, Entry>();

  get size(): number {
    return this.byAgent.size;
  }

  /** Merge PatchGate's authorisation for one PC (union of guids, latest window end). */
  add(agentId: string, guids: Iterable<string>, untilMs: number): void {
    if (!Number.isFinite(untilMs)) return;
    const prev = this.byAgent.get(agentId);
    const merged = [...(prev?.guids ?? []), ...[...guids].map(norm)];
    const unique = [...new Set(merged)];
    // Over the cap: keep the most recently authorised guids (Set keeps insertion order).
    const kept = unique.length > MAX_GUIDS_PER_AGENT ? unique.slice(unique.length - MAX_GUIDS_PER_AGENT) : unique;
    this.byAgent.delete(agentId); // re-insert: Map order = least recently authorised first
    this.byAgent.set(agentId, { guids: new Set(kept), until: Math.max(prev?.until ?? 0, untilMs) });
    while (this.byAgent.size > MAX_ALLOW_AGENTS) {
      const oldest = this.byAgent.keys().next().value;
      if (oldest === undefined) break;
      this.byAgent.delete(oldest);
    }
  }

  classify(agentId: string, guid: string, nowMs: number): ApprovalClass {
    const e = this.byAgent.get(agentId);
    if (!e || !e.guids.has(norm(guid))) return "foreign";
    return e.until > nowMs ? "allowed" : "own-expired";
  }

  /** A PatchGate window is open on this PC. */
  inFlight(agentId: string, nowMs: number): boolean {
    const e = this.byAgent.get(agentId);
    return e !== undefined && e.until > nowMs;
  }

  /** Forget PCs whose last PatchGate window ended more than OWN_APPROVAL_MEMORY_MS ago. */
  prune(nowMs: number): number {
    let n = 0;
    for (const [id, e] of this.byAgent) {
      if (e.until + OWN_APPROVAL_MEMORY_MS < nowMs) {
        this.byAgent.delete(id);
        n++;
      }
    }
    return n;
  }

  toEntries(): GuardAllowEntry[] {
    return [...this.byAgent.entries()].map(([agentId, e]) => ({ agentId, guids: [...e.guids], until: new Date(e.until).toISOString() }));
  }

  static fromEntries(entries: readonly GuardAllowEntry[]): AllowSet {
    const s = new AllowSet();
    for (const e of entries) s.add(e.agentId, e.guids, Date.parse(e.until));
    return s;
  }
}
