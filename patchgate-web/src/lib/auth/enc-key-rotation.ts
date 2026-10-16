import "server-only";
import { prisma } from "@/lib/db";
import { auditAuth } from "./audit";
import { encryptSecret, keyId, needsReencryption, openSecret, type EncKeyring } from "./secret-box";
import { authTx } from "./tx";
import { sweepWebhookSecrets, type WebhookSweepCounts } from "@/lib/notify/webhook-rotation";

/**
 * AUTH_ENC_KEY rotation (RUNBOOK §9.4): re-encrypt every stored TOTP secret (User.totpSecretEnc), every
 * pending enrolment secret (AuthChallenge.pendingSecretEnc) and every notification webhook URL
 * (NotificationSetting.webhookUrlsEnc + legacy plaintext, WEBHOOK outbox targets) with the CURRENT key. Rows already under the
 * current key in the current format are left alone, so a second run changes nothing (idempotent).
 * Each batch is one transaction; a row is only rewritten if it still holds the ciphertext we decrypted
 * (a concurrent enrolment / sign-in wins). Never returns or logs a secret — counts only.
 */

export const ROTATION_ACTOR = "cli:rotate-auth-enc-key";
export const DEFAULT_BATCH_SIZE = 100;

export interface RotationCounts {
  scanned: number;
  reencrypted: number;
  alreadyCurrent: number;
  /** Not decryptable with either key (tampered / unknown key): left untouched, needs an MFA reset. */
  failed: number;
  /** Changed by someone else between read and write: left untouched (re-run to pick up). */
  skippedConcurrent: number;
}

export interface RotationReport {
  dryRun: boolean;
  currentKeyId: string;
  previousKeyId: string | null;
  users: RotationCounts;
  challenges: RotationCounts;
  /** NotificationSetting rows (counted per row: all its webhook URLs) */
  webhookSettings: WebhookSweepCounts;
  /** Notification outbox rows of channel WEBHOOK */
  webhookOutbox: WebhookSweepCounts;
}

export interface RotationOptions {
  ring: EncKeyring;
  dryRun?: boolean;
  batchSize?: number;
  actor?: string;
}

const zero = (): RotationCounts => ({ scanned: 0, reencrypted: 0, alreadyCurrent: 0, failed: 0, skippedConcurrent: 0 });

interface Row {
  id: string;
  owner: string;
  box: string;
}

type Outcome = { kind: "current" } | { kind: "failed" } | { kind: "rewrite"; box: string };

function plan(row: Row, ring: EncKeyring): Outcome {
  try {
    const opened = openSecret(row.box, ring, row.owner);
    if (!needsReencryption(opened)) return { kind: "current" };
    return { kind: "rewrite", box: encryptSecret(opened.plain, ring.current, row.owner) };
  } catch {
    return { kind: "failed" };
  }
}

/** Process rows in id order, batch by batch; `write` performs the conditional update and returns rows changed. */
async function sweep(
  load: (afterId: string | null, take: number) => Promise<Row[]>,
  write: (tx: Parameters<Parameters<typeof authTx>[0]>[0], row: Row, box: string) => Promise<number>,
  opts: Required<Pick<RotationOptions, "ring" | "dryRun" | "batchSize">>,
): Promise<RotationCounts> {
  const counts = zero();
  let cursor: string | null = null;
  for (;;) {
    const rows = await load(cursor, opts.batchSize);
    if (rows.length === 0) break;
    cursor = rows[rows.length - 1].id;
    const planned = rows.map((row) => ({ row, outcome: plan(row, opts.ring) }));
    counts.scanned += rows.length;
    for (const { outcome } of planned) {
      if (outcome.kind === "current") counts.alreadyCurrent++;
      if (outcome.kind === "failed") counts.failed++;
    }
    const rewrites = planned.flatMap(({ row, outcome }) => (outcome.kind === "rewrite" ? [{ row, box: outcome.box }] : []));
    if (rewrites.length === 0) continue;
    if (opts.dryRun) {
      counts.reencrypted += rewrites.length;
      continue;
    }
    const changed = await authTx(async (tx) => {
      let n = 0;
      for (const r of rewrites) n += await write(tx, r.row, r.box);
      return n;
    });
    counts.reencrypted += changed;
    counts.skippedConcurrent += rewrites.length - changed;
  }
  return counts;
}

export async function rotateAuthEncKey(opts: RotationOptions): Promise<RotationReport> {
  const o = { ring: opts.ring, dryRun: opts.dryRun ?? false, batchSize: Math.max(1, Math.min(opts.batchSize ?? DEFAULT_BATCH_SIZE, 1000)) };
  const after = (id: string | null) => (id ? { id: { gt: id } } : {});

  const users = await sweep(
    async (cursor, take) =>
      (
        await prisma.user.findMany({
          where: { totpSecretEnc: { not: null }, ...after(cursor) },
          orderBy: { id: "asc" },
          take,
          select: { id: true, totpSecretEnc: true },
        })
      ).map((u) => ({ id: u.id, owner: u.id, box: u.totpSecretEnc ?? "" })),
    async (tx, row, box) => (await tx.user.updateMany({ where: { id: row.id, totpSecretEnc: row.box }, data: { totpSecretEnc: box } })).count,
    o,
  );

  const challenges = await sweep(
    async (cursor, take) =>
      (
        await prisma.authChallenge.findMany({
          where: { pendingSecretEnc: { not: null }, ...after(cursor) },
          orderBy: { id: "asc" },
          take,
          select: { id: true, userId: true, pendingSecretEnc: true },
        })
      ).map((c) => ({ id: c.id, owner: c.userId, box: c.pendingSecretEnc ?? "" })),
    async (tx, row, box) =>
      (await tx.authChallenge.updateMany({ where: { id: row.id, pendingSecretEnc: row.box }, data: { pendingSecretEnc: box } })).count,
    o,
  );

  const webhooks = await sweepWebhookSecrets({ ring: o.ring, dryRun: o.dryRun, batchSize: o.batchSize });

  const report: RotationReport = {
    dryRun: o.dryRun,
    currentKeyId: keyId(o.ring.current),
    previousKeyId: o.ring.previous ? keyId(o.ring.previous) : null,
    users,
    challenges,
    webhookSettings: webhooks.settings,
    webhookOutbox: webhooks.outbox,
  };
  if (!o.dryRun) {
    await authTx((tx) =>
      auditAuth(
        {
          actor: opts.actor ?? ROTATION_ACTOR,
          action: "auth.enc_key_rotated",
          entity: "AuthEncKey",
          entityId: report.currentKeyId,
          payload: {
            previousKeyId: report.previousKeyId,
            users: { ...users },
            challenges: { ...challenges },
            webhookSettings: { ...webhooks.settings },
            webhookOutbox: { ...webhooks.outbox },
          },
          tenantId: null,
        },
        tx,
      ),
    );
  }
  return report;
}
