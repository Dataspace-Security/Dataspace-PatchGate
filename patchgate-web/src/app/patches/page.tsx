import { Suspense } from "react";
import { canMake } from "@/lib/auth/roles";
import { eligibilityErrors } from "@/lib/approvals/eligibility";
import { enabledAppIds, toEligible } from "@/lib/approvals/load-eligible";
import { withTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { Loading, PageHeader } from "@/components/ui";
import { FilterPills } from "./filter-pills";
import { PatchPicker, type PatchRow } from "./patch-picker";

const KINDS = ["WINDOWS", "THIRD_PARTY", "AGENT_UPGRADE"] as const;
const SEVERITIES = ["CRITICAL", "IMPORTANT", "MODERATE", "LOW", "UNSPECIFIED"] as const;

type Search = Record<string, string | string[] | undefined>;

async function PatchList({ searchParams }: { searchParams: Promise<Search> }) {
  const { user, tenant } = await getPageTenant();
  const tenantId = tenant.id;
  const sp = await searchParams;
  const kind = KINDS.find((k) => k === sp.kind);
  const severity = SEVERITIES.find((s) => s === sp.severity);
  const onlyNeeded = sp.needed !== "0";
  const now = new Date();

  // Shared catalog, seen through the bank: its own PCs' needs, and only the third-party apps it enabled.
  const { patches, rings, eligible } = await withTenant(tenantId, async (tx) => {
    const patches = await tx.patch.findMany({
      where: {
        supersededById: null,
        kind,
        severity,
        OR: [{ kind: { not: "THIRD_PARTY" } }, { appVersion: { app: { tenants: { some: { tenantId } } } } }],
        ...(onlyNeeded ? { states: { some: { tenantId, status: "NEEDED" } } } : {}),
      },
      orderBy: [{ severity: "asc" }, { releasedAt: { sort: "desc", nulls: "last" } }],
      take: 300,
      include: {
        appVersion: { include: { app: true } },
        _count: { select: { states: { where: { tenantId, status: "NEEDED" } } } },
      },
    });
    const rings = await tx.ring.findMany({
      where: { tenantId },
      orderBy: { order: "asc" },
      include: { windows: { where: { tenantId }, select: { id: true, name: true } } },
    });
    const eligible = await toEligible(patches, await enabledAppIds(tx, tenantId), tx);
    return { patches, rings, eligible };
  });
  const rows: PatchRow[] = patches.map((p, i) => {
    const errs = eligibilityErrors([eligible[i]], now);
    return {
      id: p.id,
      title: p.title,
      kb: p.kb,
      kind: p.kind,
      severity: p.severity,
      classification: p.classification,
      needed: p._count.states,
      blockedReason: errs[0]?.split(": ").slice(1).join(": ") ?? null,
    };
  });

  return (
    <PatchPicker
      patches={rows}
      rings={rings.map((r) => ({ id: r.id, name: r.name, windows: r.windows }))}
      canCreate={canMake(user)}
    />
  );
}

export default function PatchesPage(props: PageProps<"/patches">) {
  return (
    <div>
      <PageHeader
        title="Patches"
        description="Windows updates, approved third-party packages and Tactical agent upgrades. Select patches to raise a change request."
      />
      <Suspense fallback={null}>
        <FilterPills />
      </Suspense>
      <Suspense fallback={<Loading />}>
        <PatchList searchParams={props.searchParams} />
      </Suspense>
    </div>
  );
}
