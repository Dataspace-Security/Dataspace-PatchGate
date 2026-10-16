import "server-only";
import { appendAudit } from "@/lib/audit/service";
import type { EncKeyring } from "@/lib/auth/secret-box";
import { log } from "@/lib/log";
import { withPlatform } from "@/lib/tenancy";
import { openOutboxTarget, readSettingUrls, sealOutboxTarget, sealedColumns } from "./webhook-store";

/**
 * Re-seal stored webhook URLs under the CURRENT AUTH_ENC_KEY:
 *  - full sweep (rotation CLI, RUNBOOK §9.4): every NotificationSetting row and every WEBHOOK outbox row whose
 *    box is under the previous key / old format / still plaintext;
 *  - legacyOnly (data migration 20261016120000, every worker tick): only rows that still hold plaintext.
 * Both tables are bank-scoped under RLS → withPlatform. A row is rewritten only if it still holds what was read
 * (concurrent settings changes win). Counts only — never a URL.
 */

export interface WebhookSweepCounts {
  scanned: number;
  reencrypted: number;
  alreadyCurrent: number;
  /** holds a box that neither key decrypts (left untouched; re-add the webhook) */
  failed: number;
  skippedConcurrent: number;
}

export interface WebhookSweepReport {
  settings: WebhookSweepCounts;
  outbox: WebhookSweepCounts;
}

export interface WebhookSweepOptions {
  ring: EncKeyring;
  dryRun?: boolean;
  batchSize?: number;
  legacyOnly?: boolean;
}

interface SettingRow {
  scope: string;
  webhookUrlsEnc: string[];
  webhookUrlsLegacy: string[];
}

const zero = (): WebhookSweepCounts => ({ scanned: 0, reencrypted: 0, alreadyCurrent: 0, failed: 0, skippedConcurrent: 0 });

async function sweepSettings(o: Required<WebhookSweepOptions>): Promise<WebhookSweepCounts> {
  const c = zero();
  let cursor: string | null = null;
  for (;;) {
    const after: string | null = cursor;
    const rows: SettingRow[] = await withPlatform((tx) =>
      tx.notificationSetting.findMany({
        where: { ...(o.legacyOnly ? { NOT: { webhookUrlsLegacy: { isEmpty: true } } } : {}), ...(after ? { scope: { gt: after } } : {}) },
        orderBy: { scope: "asc" },
        take: o.batchSize,
        select: { scope: true, webhookUrlsEnc: true, webhookUrlsLegacy: true },
      }),
    );
    if (rows.length === 0) break;
    cursor = rows[rows.length - 1].scope;
    c.scanned += rows.length;
    const rewrites: { row: SettingRow; data: ReturnType<typeof sealedColumns> }[] = [];
    for (const row of rows) {
      const r = readSettingUrls(row, o.ring);
      if (r.undecryptable.length > 0) c.failed++;
      if (!r.stale) {
        if (r.undecryptable.length === 0) c.alreadyCurrent++;
        continue;
      }
      rewrites.push({ row, data: sealedColumns(row.scope, r.urls, r.undecryptable, o.ring) });
    }
    if (rewrites.length === 0) continue;
    if (o.dryRun) {
      c.reencrypted += rewrites.length;
      continue;
    }
    const changed = await withPlatform(async (tx) => {
      let n = 0;
      for (const { row, data } of rewrites) {
        const where = { scope: row.scope, webhookUrlsEnc: { equals: row.webhookUrlsEnc }, webhookUrlsLegacy: { equals: row.webhookUrlsLegacy } };
        n += (await tx.notificationSetting.updateMany({ where, data })).count;
      }
      return n;
    });
    c.reencrypted += changed;
    c.skippedConcurrent += rewrites.length - changed;
  }
  return c;
}

async function sweepOutbox(o: Required<WebhookSweepOptions>): Promise<WebhookSweepCounts> {
  const c = zero();
  let cursor: string | null = null;
  for (;;) {
    const after: string | null = cursor;
    const rows: { id: string; target: string }[] = await withPlatform((tx) =>
      tx.notification.findMany({
        where: { channel: "WEBHOOK", ...(o.legacyOnly ? { target: { contains: ":" } } : {}), ...(after ? { id: { gt: after } } : {}) },
        orderBy: { id: "asc" },
        take: o.batchSize,
        select: { id: true, target: true },
      }),
    );
    if (rows.length === 0) break;
    cursor = rows[rows.length - 1].id;
    c.scanned += rows.length;
    const rewrites: { id: string; old: string; box: string }[] = [];
    for (const row of rows) {
      try {
        const opened = openOutboxTarget(row.target, o.ring);
        if (!opened.stale) c.alreadyCurrent++;
        else rewrites.push({ id: row.id, old: row.target, box: sealOutboxTarget(opened.url, o.ring) });
      } catch {
        c.failed++;
      }
    }
    if (rewrites.length === 0) continue;
    if (o.dryRun) {
      c.reencrypted += rewrites.length;
      continue;
    }
    const changed = await withPlatform(async (tx) => {
      let n = 0;
      for (const r of rewrites) n += (await tx.notification.updateMany({ where: { id: r.id, target: r.old }, data: { target: r.box } })).count;
      return n;
    });
    c.reencrypted += changed;
    c.skippedConcurrent += rewrites.length - changed;
  }
  return c;
}

export async function sweepWebhookSecrets(opts: WebhookSweepOptions): Promise<WebhookSweepReport> {
  const o: Required<WebhookSweepOptions> = {
    ring: opts.ring,
    dryRun: opts.dryRun ?? false,
    batchSize: Math.max(1, Math.min(opts.batchSize ?? 100, 1000)),
    legacyOnly: opts.legacyOnly ?? false,
  };
  return { settings: await sweepSettings(o), outbox: await sweepOutbox(o) };
}

/**
 * Data migration step (worker tick): encrypt remaining plaintext webhook URLs. Cheap when there is nothing to do
 * (two indexed-by-filter queries returning no rows). Audited once per run that changed something.
 */
export async function drainLegacyWebhooks(ring: EncKeyring | null): Promise<number> {
  if (!ring) return 0;
  const r = await sweepWebhookSecrets({ ring, legacyOnly: true });
  const changed = r.settings.reencrypted + r.outbox.reencrypted;
  if (changed > 0) {
    await appendAudit({
      actor: "system:worker",
      action: "notification.webhooks_encrypted",
      entity: "NotificationSetting",
      entityId: "webhook-urls",
      payload: { settings: { ...r.settings }, outbox: { ...r.outbox } },
    });
    log.info("notify.webhooks_encrypted", { settings: r.settings.reencrypted, outbox: r.outbox.reencrypted });
  }
  return changed;
}
