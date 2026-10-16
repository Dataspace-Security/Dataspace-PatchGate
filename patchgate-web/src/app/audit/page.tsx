import Link from "next/link";
import { canRead } from "@/lib/auth/roles";
import { Suspense } from "react";
import { Clock, Database, ShieldCheck, Upload } from "lucide-react";
import { getPageUser } from "@/lib/auth/page-user";
import { verifyAuditLogCached } from "@/lib/audit/service";
import { auditExportStatus } from "@/lib/audit/export";
import { resolveAuditChain } from "@/lib/audit/chain-scope";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { Alert, Badge, Card, Loading, PageHeader, Stat, fmtDate, rowCls, tableCls, theadCls } from "@/components/ui";
import { VerifyAnchorForm } from "./verify-anchor-form";

interface RelayHeartbeat {
  siem?: { configured?: boolean; lastForwardedSeq?: string | null } | null;
}

/** SIEM delivery of a bank's chain via its connectors' audit relay (from their heartbeats). */
async function connectorRelayStatus(tx: Tx, tenantId: string): Promise<{ pending: number; minutesSinceExport: number | null; target: string; forwardedSeq: string } | null> {
  const connectors = await tx.connector.findMany({
    where: { tenantId, status: "ACTIVE" },
    select: { name: true, lastSeenAt: true, heartbeat: true },
  });
  let best: { name: string; seq: bigint; seenAt: Date | null } | null = null;
  for (const c of connectors) {
    const siem = (c.heartbeat as RelayHeartbeat | null)?.siem;
    if (!siem?.configured) continue;
    const seq = siem.lastForwardedSeq && /^\d{1,19}$/.test(siem.lastForwardedSeq) ? BigInt(siem.lastForwardedSeq) : BigInt(0);
    if (!best || seq > best.seq) best = { name: c.name, seq, seenAt: c.lastSeenAt };
  }
  if (!best) return null;
  const pending = await tx.auditEvent.count({ where: { tenantId, seq: { gt: best.seq } } });
  const minutesSinceExport = best.seenAt ? Math.round((Date.now() - best.seenAt.getTime()) / 60_000) : null;
  return { pending, minutesSinceExport, target: `bank SIEM via connector “${best.name}”`, forwardedSeq: best.seq.toString() };
}

async function AuditContent({ requested }: { requested: string | undefined }) {
  const user = await getPageUser();
  const privileged = canRead(user); // admins and auditors verify the chain and SIEM anchors
  // One chain per bank + the platform chain. Bank users only ever see their own bank's chain.
  const scope = await resolveAuditChain(user, requested);
  const chainId = scope.tenantId;
  const latest = (tx: Tx) => tx.auditEvent.findMany({ where: { tenantId: chainId }, orderBy: { seq: "desc" }, take: 50 });

  const [direct, events, relay] = await Promise.all([
    auditExportStatus(chainId),
    chainId ? withTenant(chainId, latest) : withPlatform(latest),
    chainId ? withTenant(chainId, (tx) => connectorRelayStatus(tx, chainId)) : Promise.resolve(null),
  ]);
  const verification = privileged ? await verifyAuditLogCached(chainId) : null;
  // A bank's chain reaches the BANK's SIEM through its site connector(s) (audit relay), not through our
  // own exporter — prefer the relay figures when a connector reports a configured SIEM.
  const exp = relay ?? { pending: direct.pending, minutesSinceExport: direct.minutesSinceExport, target: direct.target };
  const lagMin = exp.minutesSinceExport;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span className="text-muted">Chain:</span>
        <span className="font-medium text-fg">{scope.tenant ? scope.tenant.name : "PatchGate platform"}</span>
        {scope.canViewPlatform && (
          <Link href={chainId ? "/audit?chain=platform" : "/audit"} className="font-medium text-primary hover:underline">
            {chainId ? "Show platform chain" : "Show selected bank’s chain"}
          </Link>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Chain integrity"
          value={verification ? (verification.valid ? "Valid" : "BROKEN") : "—"}
          tone={verification ? (verification.valid ? "good" : "bad") : "neutral"}
          icon={<ShieldCheck size={18} />}
          hint={verification ? `${verification.anchorsChecked} SIEM anchors cross-checked` : "approvers & admins"}
        />
        <Stat label="Events" value={verification?.count ?? "—"} icon={<Database size={18} />} />
        <Stat label="Not yet in SIEM" value={exp.pending} tone={exp.pending > 0 ? "bad" : "good"} icon={<Upload size={18} />} />
        <Stat
          label={relay ? "Last relayed to bank SIEM" : "Last SIEM export"}
          value={lagMin === null ? "never" : `${lagMin} min`}
          tone={lagMin === null || lagMin > 15 ? "bad" : "good"}
          icon={<Clock size={18} />}
          hint={exp.target ?? "SIEM not configured"}
        />
      </div>

      {verification && !verification.valid && (
        <Alert tone="bad">
          <b>Tamper alert:</b> {verification.problem}. Treat as a security incident and compare with the SIEM copy.
        </Alert>
      )}

      {privileged && (
        <Card
          title="Verify an anchor from the SIEM"
          description="Copy seq and hash from any ANCHOR record in the SIEM — the copy PatchGate cannot modify — and check it against this database."
        >
          <VerifyAnchorForm platformChain={chainId === null} />
        </Card>
      )}

      <Card title="Latest events" description={relay ? `Relayed to the bank SIEM up to seq ${relay.forwardedSeq} of ${direct.headSeq}.` : `Exported up to seq ${direct.exportedSeq} of ${direct.headSeq}.`} padded={false}>
        <table className={tableCls}>
          <thead className={theadCls}>
            <tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Entity</th></tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.seq.toString()} className={rowCls}>
                <td className="font-mono text-xs text-muted">{e.seq.toString()}</td>
                <td className="whitespace-nowrap text-xs text-muted">{fmtDate(e.ts)}</td>
                <td className="whitespace-nowrap">{e.actor}</td>
                <td><Badge tone="info" dot={false}>{e.action}</Badge></td>
                <td className="text-xs text-muted">{e.entity} <span className="font-mono">{e.entityId.slice(0, 12)}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

export default function AuditPage(props: PageProps<"/audit">) {
  return (
    <div>
      <PageHeader title="Audit" description="Append-only, HMAC-chained audit log — one chain per bank plus the platform chain — continuously exported to the SIEM." />
      <Suspense fallback={<Loading />}>
        <AuditFromParams searchParams={props.searchParams} />
      </Suspense>
    </div>
  );
}

async function AuditFromParams({ searchParams }: { searchParams: PageProps<"/audit">["searchParams"] }) {
  const sp = await searchParams;
  return <AuditContent requested={typeof sp.chain === "string" ? sp.chain : undefined} />;
}
