import { env } from "@/lib/env";
import { fail, handle, ok } from "@/lib/api/response";
import { tokenMatches } from "@/lib/api/token";
import { withLease } from "@/lib/deploy/lease";
import { runWorkerTick } from "@/lib/deploy/worker";
import { ingestDueEndpoints } from "@/lib/scan/ingest";
import { DIRECT_TACTICAL_NOT_CONFIGURED, tacticalFromEnvOrNull } from "@/lib/tactical/from-env";
import { purgeExpiredAuth } from "@/lib/auth/oidc";
import { stepTimer } from "@/lib/metrics/worker-steps";
import { runNotificationWatch } from "@/lib/notify/watch";
import { deliverNotifications } from "@/lib/notify/deliver";
import { drainLegacyWebhooks } from "@/lib/notify/webhook-rotation";
import { optionalAuthKeyring } from "@/lib/auth/enc-keys";

/**
 * Fast loop — call every minute from a local scheduler (systemd timer / Task Scheduler):
 *   curl -X POST -H "x-worker-token: $WORKER_TOKEN" https://localhost/api/worker/tick
 * SIEM export → deploy queue → confirm installs → finalise CRs → scan ingestion → SIEM export.
 */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    if (!tokenMatches(req.headers.get("x-worker-token"), env().WORKER_TOKEN)) {
      return fail("Unauthorized", 401);
    }
    // null in hosted mode (no direct Tactical link): the legacy steps report "skipped".
    const tactical = tacticalFromEnvOrNull();
    const timer = stepTimer(); // step durations → WorkerStepRun (/api/metrics, /operations)
    // One tick at a time across all instances; a crashed holder's lease expires after 10 min.
    const result = await withLease("tick", 10 * 60_000, () =>
      runWorkerTick({
        tactical,
        onStep: timer.onStep,
        extraSteps: [
          { name: "scanIngest", run: async () => (tactical ? ingestDueEndpoints(tactical) : DIRECT_TACTICAL_NOT_CONFIGURED) },
          { name: "authCleanup", run: () => purgeExpiredAuth() },
          { name: "notifyWatch", run: async () => { const r = await runNotificationWatch(); return `offline ${r.offline}, online ${r.online}, siem stale ${r.siemStale}`; } },
          {
            name: "notifyDeliver",
            run: async () => {
              // Data migration 20261016120000: seal any remaining plaintext webhook URLs first (no-op once drained).
              const sealed = await drainLegacyWebhooks(optionalAuthKeyring());
              const r = await deliverNotifications();
              return `sent ${r.sent}, retrying ${r.retrying}, dead ${r.dead}, skipped ${r.skipped}${sealed ? `, webhook URLs encrypted ${sealed}` : ""}`;
            },
          },
        ],
      }),
    );
    await timer.finish(result !== null, result?.ok ?? false);
    return ok(result ?? { skipped: "another tick is still running" });
  });
}
