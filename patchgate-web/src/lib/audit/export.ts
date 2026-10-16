import "server-only";
import { createHmac } from "node:crypto";
import { hostname } from "node:os";
import { withPlatform } from "@/lib/tenancy/db";
import { env } from "@/lib/env";
import { createSyslogSender, formatSyslog, parseSiemUrl, type SyslogSender } from "@/lib/siem/syslog";
import { auditChains, chainName } from "./service";

/**
 * Ship every audit event + signed chain-head records to the SIEM, chain by chain (one chain per bank
 * plus the platform chain). Every record carries `chain="<bank id|platform>"`; the SIEM rules in
 * lib/siem/verify-stream.ts run per chain (chain-break, regression, fork, missing heartbeat).
 * Later phase: each bank's chain is relayed to that bank's own SIEM by its connector.
 *
 * This is a platform job: it walks every chain with an explicit tenantId filter inside withPlatform()
 * (RLS applies to the runtime DB role). SIEM sends happen outside any transaction.
 */

const BATCH = 500;
const MAX_BATCHES_PER_TICK = 20;
const HEARTBEAT_MS = 60 * 60_000;
const SEND_TIMEOUT_MS = 15_000;

export function siemSenderFromEnv(): SyslogSender | null {
  const e = env();
  if (!e.SIEM_SYSLOG_URL) return null;
  return createSyslogSender(parseSiemUrl(e.SIEM_SYSLOG_URL), {
    timeoutMs: SEND_TIMEOUT_MS,
    caFile: e.SIEM_CA_FILE,
  });
}

/**
 * HMAC over a head record so an offline verifier holding the key can prove it came from PatchGate.
 * The chain id is part of the MAC, so a head record cannot be replayed as another bank's.
 */
function headMac(key: string, msgId: string, chain: string, seq: string, hash: string, count: string, ts: Date): string {
  return createHmac("sha256", key).update(`${msgId}|${chain}|${seq}|${hash}|${count}|${ts.toISOString()}`).digest("hex");
}

export interface ChainExportResult {
  exported: number;
  anchorSeq: string | null;
  heartbeat: boolean;
}

export interface ExportResult extends ChainExportResult {
  /** Per chain ("platform" or bank id) */
  chains: Record<string, ChainExportResult>;
}

async function exportChain(sender: SyslogSender, tenantId: string | null, now: Date, host: string): Promise<ChainExportResult> {
  const key = env().AUDIT_HMAC_KEY;
  const chain = chainName(tenantId);
  let exported = 0;
  let anchorSeq: string | null = null;

  for (let i = 0; i < MAX_BATCHES_PER_TICK; i++) {
    const events = await withPlatform(async (tx) => {
      const last = await tx.auditAnchor.findFirst({ where: { tenantId, eventCount: { gt: 0 } }, orderBy: { seq: "desc" } });
      return tx.auditEvent.findMany({
        where: { tenantId, seq: { gt: last?.seq ?? BigInt(0) } },
        orderBy: { seq: "asc" },
        take: BATCH,
      });
    });
    if (events.length === 0) break;

    const head = events[events.length - 1];
    const seq = head.seq.toString();
    const count = String(events.length);
    const lines = events.map((ev) =>
      formatSyslog({
        ts: ev.ts,
        hostname: host,
        msgId: "AUDIT",
        sd: { seq: ev.seq.toString(), hash: ev.hash, prevHash: ev.prevHash, chain },
        msg: JSON.stringify({
          actor: ev.actor,
          action: ev.action,
          entity: ev.entity,
          entityId: ev.entityId,
          payload: ev.payload,
        }),
      }),
    );
    lines.push(
      formatSyslog({
        ts: now,
        hostname: host,
        msgId: "ANCHOR",
        sd: { seq, hash: head.hash, count, mac: headMac(key, "ANCHOR", chain, seq, head.hash, count, now), chain },
        msg: "audit chain head",
      }),
    );

    // Record the anchor only after the SIEM accepted the batch; on failure the next tick resends.
    await sender.send(lines);
    await withPlatform((tx) =>
      tx.auditAnchor.create({
        data: { tenantId, seq: head.seq, hash: head.hash, eventCount: events.length, target: sender.target },
      }),
    );
    exported += events.length;
    anchorSeq = seq;
    if (events.length < BATCH) break;
  }

  // Hourly HEARTBEAT reports the REAL DB head of the chain (not the last anchor), so deleting rows
  // without writing new ones shows up in the SIEM as a regression.
  let heartbeat = false;
  const lastBeat = await withPlatform((tx) =>
    tx.auditAnchor.findFirst({ where: { tenantId, eventCount: 0 }, orderBy: { exportedAt: "desc" } }),
  );
  if (!lastBeat || now.getTime() - lastBeat.exportedAt.getTime() >= HEARTBEAT_MS) {
    const { head, total } = await withPlatform(async (tx) => ({
      head: await tx.auditEvent.findFirst({ where: { tenantId }, orderBy: { seq: "desc" }, select: { seq: true, hash: true } }),
      total: await tx.auditEvent.count({ where: { tenantId } }),
    }));
    const seq = head?.seq.toString() ?? "0";
    const hash = head?.hash ?? "-";
    await sender.send([
      formatSyslog({
        ts: now,
        hostname: host,
        msgId: "HEARTBEAT",
        sd: { seq, hash, total: String(total), mac: headMac(key, "HEARTBEAT", chain, seq, hash, String(total), now), chain },
        msg: "patchgate audit exporter alive",
      }),
    ]);
    await withPlatform((tx) =>
      tx.auditAnchor.create({
        data: { tenantId, seq: head?.seq ?? BigInt(0), hash, eventCount: 0, target: sender.target },
      }),
    );
    heartbeat = true;
  }

  return { exported, anchorSeq, heartbeat };
}

/** Export every chain. A SIEM failure aborts the tick (the next tick resumes from each chain's last anchor). */
export async function exportAuditToSiem(sender: SyslogSender, now = new Date()): Promise<ExportResult> {
  const host = env().SIEM_HOSTNAME ?? hostname();
  const chains: Record<string, ChainExportResult> = {};
  let exported = 0;
  let anchorSeq: string | null = null;
  let heartbeat = false;
  for (const tenantId of await auditChains()) {
    const r = await exportChain(sender, tenantId, now, host);
    chains[chainName(tenantId)] = r;
    exported += r.exported;
    anchorSeq = r.anchorSeq ?? anchorSeq;
    heartbeat = heartbeat || r.heartbeat;
  }
  return { exported, anchorSeq, heartbeat, chains };
}

/** Export lag of ONE chain (bank or platform), shown on the audit page and dashboard. */
export async function auditExportStatus(tenantId: string | null = null) {
  const { anchor, exportedSeq, head, pending } = await withPlatform(async (tx) => {
    const anchor = await tx.auditAnchor.findFirst({ where: { tenantId, eventCount: { gt: 0 } }, orderBy: { seq: "desc" } });
    const exportedSeq = anchor?.seq ?? BigInt(0);
    return {
      anchor,
      exportedSeq,
      head: await tx.auditEvent.findFirst({ where: { tenantId }, orderBy: { seq: "desc" }, select: { seq: true } }),
      // count rows, not seq arithmetic: sequences have gaps (rolled-back transactions, other chains)
      pending: await tx.auditEvent.count({ where: { tenantId, seq: { gt: exportedSeq } } }),
    };
  });
  const headSeq = head?.seq ?? BigInt(0);
  return {
    chain: chainName(tenantId),
    headSeq: headSeq.toString(),
    exportedSeq: exportedSeq.toString(),
    pending,
    lastExportAt: anchor?.exportedAt ?? null,
    minutesSinceExport: anchor ? Math.round((Date.now() - anchor.exportedAt.getTime()) / 60_000) : null,
    target: anchor?.target ?? null,
  };
}

/** Readiness: is ANY chain's export stale? (pending events and no export within `staleMinutes`) */
export async function anyChainExportStale(staleMinutes: number): Promise<boolean> {
  for (const tenantId of await auditChains()) {
    const s = await auditExportStatus(tenantId);
    if (s.pending > 0 && (s.minutesSinceExport === null || s.minutesSinceExport > staleMinutes)) return true;
  }
  return false;
}
