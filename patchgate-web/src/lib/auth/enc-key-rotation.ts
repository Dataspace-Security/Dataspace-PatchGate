import "server-only";
import { auditAuth } from "./audit";
import { keyId, type EncKeyring } from "./secret-box";
import { authTx } from "./tx";
import { sweepWebhookSecrets, type WebhookSweepCounts } from "@/lib/notify/webhook-rotation";

/**
 * AUTH_ENC_KEY rotation (RUNBOOK §9.4): re-encrypt every notification webhook URL
 * (NotificationSetting.webhookUrlsEnc + legacy plaintext, WEBHOOK outbox targets) with the CURRENT key.
 * AUTH_ENC_KEY protects nothing else since local sign-in became password-only. Rows already under the
 * current key in the current format are left alone, so a second run changes nothing (idempotent).
 * Each batch is one transaction; a row is only rewritten if it still holds the ciphertext we decrypted.
 * Never returns or logs a secret — counts only.
 */

export const ROTATION_ACTOR = "cli:rotate-auth-enc-key";
export const DEFAULT_BATCH_SIZE = 100;

export interface RotationReport {
  dryRun: boolean;
  currentKeyId: string;
  previousKeyId: string | null;
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

export async function rotateAuthEncKey(opts: RotationOptions): Promise<RotationReport> {
  const o = { ring: opts.ring, dryRun: opts.dryRun ?? false, batchSize: Math.max(1, Math.min(opts.batchSize ?? DEFAULT_BATCH_SIZE, 1000)) };
  const webhooks = await sweepWebhookSecrets({ ring: o.ring, dryRun: o.dryRun, batchSize: o.batchSize });

  const report: RotationReport = {
    dryRun: o.dryRun,
    currentKeyId: keyId(o.ring.current),
    previousKeyId: o.ring.previous ? keyId(o.ring.previous) : null,
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
