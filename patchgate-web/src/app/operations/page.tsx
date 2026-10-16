import Link from "next/link";
import { Suspense } from "react";
import { getPageUser } from "@/lib/auth/page-user";
import { AuthError } from "@/lib/auth/session";
import { loadOperations, parseFilter, parsePage } from "@/lib/metrics/operations";
import { Alert, Loading, PageHeader, fmtDate } from "@/components/ui";
import { BankTable } from "./bank-table";
import { FetchAndAudit, PlatformStats, WorkerSteps } from "./platform-tiles";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

async function OperationsContent({ searchParams }: { searchParams: SearchParams }) {
  const user = await getPageUser();
  const sp = await searchParams;
  let view;
  try {
    view = await loadOperations(user, { page: parsePage(sp.page), filter: parseFilter(sp.filter) });
  } catch (err: unknown) {
    if (err instanceof AuthError && err.status === 403) {
      return (
        <Alert tone="bad">
          The operations view spans every bank and is for PatchGate platform staff only. <Link href="/" className="underline">Back to the dashboard</Link>
        </Alert>
      );
    }
    throw err;
  }
  const s = view.snapshot;
  return (
    <div className="space-y-6">
      {s.errors.length > 0 && (
        <Alert tone="warn">
          Some figures could not be refreshed ({s.errors.join(", ")}); the rest is current. Details are in the web log (
          <span className="font-mono">metrics.collect.part_failed</span>).
        </Alert>
      )}
      <PlatformStats s={s} />
      <BankTable rows={view.rows} page={view.page} pages={view.pages} matching={view.matchingBanks} total={view.totalBanks} issues={view.banksWithIssues} filter={view.filter} />
      <FetchAndAudit s={s} />
      <WorkerSteps s={s} />
      <p className="text-xs text-muted">
        Live figures refresh every 15 s, compliance and 24 h totals every 5 min (last {fmtDate(s.collect.slowAt)}). Generated {fmtDate(s.generatedAt)}.
        The same data is scraped by Prometheus from <span className="font-mono">/api/metrics</span>.
      </p>
    </div>
  );
}

export default function OperationsPage(props: { searchParams: SearchParams }) {
  return (
    <div>
      <PageHeader title="Operations" description="Platform health across every bank: connectors, job pipeline, approvals, compliance, audit export and the worker." />
      <Suspense fallback={<Loading />}>
        <OperationsContent searchParams={props.searchParams} />
      </Suspense>
    </div>
  );
}
