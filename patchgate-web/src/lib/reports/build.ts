import "server-only";
import { prisma } from "@/lib/db";
import { DomainError } from "@/lib/errors";
import { withTenant } from "@/lib/tenancy/db";
import { appVersions, auditEvidence, changesInPeriod, connectorUptime, exceptions } from "./activity";
import { fleetAndRings, gapsByAge, missingTotals, topMissingPatches } from "./fleet";
import type { Period } from "./period";
import type { BankReport, BankSummaryRow, PlatformSummary } from "./types";

/** Report builders. Each bank is read in its own RLS scope (withTenant); the summary loops over banks. */

const REPORT_TX = { timeoutMs: 120_000 };

async function tenantName(tenantId: string): Promise<string> {
  const t = await prisma.tenant.findUnique({ where: { id: tenantId }, select: { name: true } });
  if (!t) throw new DomainError("Bank not found", 404);
  return t.name;
}

export async function buildBankReport(tenantId: string, period: Period, generatedBy: string, now = new Date()): Promise<BankReport> {
  const bankName = await tenantName(tenantId);
  return withTenant(
    tenantId,
    async (tx) => {
      const { fleet, rings } = await fleetAndRings(tx, tenantId);
      const gaps = await gapsByAge(tx, tenantId, now);
      return {
        meta: { bankId: tenantId, bankName, periodLabel: period.label, from: period.from, to: period.to, generatedAt: now, generatedBy },
        fleet: { ...fleet, ...missingTotals(gaps) },
        rings,
        gaps,
        topMissing: await topMissingPatches(tx, tenantId),
        apps: await appVersions(tx, tenantId),
        changes: await changesInPeriod(tx, tenantId, period),
        exceptions: await exceptions(tx, tenantId),
        connectors: await connectorUptime(tx, tenantId, period, now),
        evidence: await auditEvidence(tx, tenantId, period),
      };
    },
    REPORT_TX,
  );
}

async function bankSummary(tenantId: string, bank: string, period: Period, now: Date): Promise<BankSummaryRow> {
  return withTenant(
    tenantId,
    async (tx) => {
      const { fleet } = await fleetAndRings(tx, tenantId);
      const totals = missingTotals(await gapsByAge(tx, tenantId, now));
      const inRange = { gte: period.from, lt: period.to };
      const crWhere = { tenantId, OR: [{ createdAt: inRange }, { submittedAt: inRange }, { decidedAt: inRange }, { completedAt: inRange }] };
      const [changes, failedChanges, emergencyChanges, offline, cp] = await Promise.all([
        tx.changeRequest.count({ where: crWhere }),
        tx.changeRequest.count({ where: { tenantId, completedAt: inRange, status: { in: ["FAILED", "PARTIAL"] } } }),
        tx.changeRequest.count({ where: { ...crWhere, emergency: true } }),
        tx.connectorOutage.count({ where: { tenantId, endedAt: null } }),
        tx.auditVerifyCheckpoint.findUnique({ where: { chain: tenantId }, select: { valid: true } }),
      ]);
      return {
        bankId: tenantId,
        bank,
        endpoints: fleet.endpoints,
        scanned: fleet.scanned,
        compliancePct: fleet.compliancePct,
        ...totals,
        changes,
        failedChanges,
        emergencyChanges,
        connectorsOfflineNow: offline,
        auditChainValid: cp ? cp.valid : null,
      };
    },
    REPORT_TX,
  );
}

export async function buildPlatformSummary(period: Period, generatedBy: string, now = new Date()): Promise<PlatformSummary> {
  const tenants = await prisma.tenant.findMany({ where: { active: true }, orderBy: { name: "asc" }, select: { id: true, name: true } });
  const banks: BankSummaryRow[] = [];
  for (const t of tenants) banks.push(await bankSummary(t.id, t.name, period, now));
  return {
    meta: { bankId: null, bankName: "All banks", periodLabel: period.label, from: period.from, to: period.to, generatedAt: now, generatedBy },
    banks,
  };
}
