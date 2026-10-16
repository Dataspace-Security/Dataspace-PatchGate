import "server-only";
import { AuthError, type SessionUser } from "@/lib/auth/session";
import { isPlatformUser } from "@/lib/tenancy/policy";
import { opsSnapshot } from "./collect";
import { bankRag, complianceRatio, jobsFailedTotal, failureRate, ragRank, type BankRag } from "./thresholds";
import type { BankOps, OpsSnapshot } from "./types";

/**
 * View model of /operations (platform staff only): one aggregated row per bank, worst first, paged.
 * Bank users never reach the snapshot (403 before any query) — the page spans every bank.
 */

export const OPS_PAGE_SIZE = 25;

export type OpsFilter = "all" | "issues";

export interface OpsBankRow {
  bank: BankOps;
  rag: BankRag;
  online: number;
  offline: number;
  /** stalest ACTIVE connector (null = none, Infinity = one never seen) */
  worstLastSeenAgeSec: number | null;
  versions: string[];
  minCacheFreeBytes: number | null;
  openJobs: number;
  failed24h: number;
  failureRate: number | null;
  compliancePct: number | null;
}

export interface OpsView {
  snapshot: OpsSnapshot;
  rows: OpsBankRow[];
  page: number;
  pages: number;
  totalBanks: number;
  matchingBanks: number;
  banksWithIssues: number;
  filter: OpsFilter;
}

/** Platform staff (any role) may open the cross-bank operations view; bank users get 403. */
export function requirePlatformStaff(user: Pick<SessionUser, "tenantId" | "role">): void {
  if (!isPlatformUser(user)) throw new AuthError("Platform staff only", 403);
}

export function toRow(bank: BankOps): OpsBankRow {
  const online = bank.connectors.filter((c) => c.online).length;
  const ages = bank.connectors.map((c) => c.lastSeenAgeSec ?? Infinity);
  const frees = bank.connectors.map((c) => c.cacheFreeBytes).filter((v): v is number => v !== null);
  const failed = jobsFailedTotal(bank);
  const ratio = complianceRatio(bank.compliance);
  return {
    bank,
    rag: bankRag(bank),
    online,
    offline: bank.connectors.length - online,
    worstLastSeenAgeSec: ages.length > 0 ? Math.max(...ages) : null,
    versions: [...new Set(bank.connectors.map((c) => c.version ?? "unknown"))].sort(),
    minCacheFreeBytes: frees.length > 0 ? Math.min(...frees) : null,
    openJobs: bank.jobBacklog.reduce((n, j) => n + j.count, 0),
    failed24h: failed,
    failureRate: failureRate(failed, bank.jobsSucceeded24h),
    compliancePct: ratio === null ? null : Math.round(ratio * 1000) / 10,
  };
}

/** Worst status first, then by name; suspended banks last. */
export function sortRows(rows: readonly OpsBankRow[]): OpsBankRow[] {
  return [...rows].sort(
    (a, b) =>
      Number(b.bank.active) - Number(a.bank.active) ||
      ragRank(b.rag.overall) - ragRank(a.rag.overall) ||
      a.bank.name.localeCompare(b.bank.name),
  );
}

export function parsePage(raw: unknown): number {
  const n = typeof raw === "string" ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n >= 1 && n <= 10_000 ? n : 1;
}

export function parseFilter(raw: unknown): OpsFilter {
  return raw === "issues" ? "issues" : "all";
}

export function pageRows(all: readonly OpsBankRow[], filter: OpsFilter, page: number) {
  const matching = filter === "issues" ? all.filter((r) => r.rag.overall === "red" || r.rag.overall === "amber") : all;
  const pages = Math.max(1, Math.ceil(matching.length / OPS_PAGE_SIZE));
  const p = Math.min(page, pages);
  return { rows: matching.slice((p - 1) * OPS_PAGE_SIZE, p * OPS_PAGE_SIZE), page: p, pages, matching: matching.length };
}

export async function loadOperations(user: Pick<SessionUser, "tenantId" | "role">, opts: { page?: number; filter?: OpsFilter } = {}): Promise<OpsView> {
  requirePlatformStaff(user);
  const snapshot = await opsSnapshot();
  const all = sortRows(snapshot.banks.map(toRow));
  const filter = opts.filter ?? "all";
  const paged = pageRows(all, filter, opts.page ?? 1);
  return {
    snapshot,
    rows: paged.rows,
    page: paged.page,
    pages: paged.pages,
    totalBanks: all.length,
    matchingBanks: paged.matching,
    banksWithIssues: all.filter((r) => r.rag.overall === "red" || r.rag.overall === "amber").length,
    filter,
  };
}
