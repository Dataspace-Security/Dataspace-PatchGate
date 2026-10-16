import "server-only";
import { env, type Env } from "@/lib/env";
import { log } from "@/lib/log";
import { withPlatform } from "@/lib/tenancy/db";
import { afterFailure } from "./backoff";
import { createSmtpMailer, type Mailer } from "./smtp";
import { webhookPayload } from "./templates";
import { parseAllowedHosts, postWebhook, type WebhookDeps } from "./webhook";
import { openOutboxTarget } from "./webhook-store";
import { optionalAuthKeyring } from "@/lib/auth/enc-keys";
import type { EncKeyring } from "@/lib/auth/secret-box";

/**
 * Worker step: deliver due outbox rows (at-least-once).
 *  1. claim a batch (FOR UPDATE SKIP LOCKED → two instances never take the same row) and mark it SENDING;
 *  2. deliver OUTSIDE the transaction (no pooled DB connection is held over SMTP / HTTP);
 *  3. record SENT, PENDING + backoff, DEAD (permanent error / attempts exhausted) or SKIPPED (channel not
 *     configured). A SENDING claim older than 10 min (crashed worker) is put back to PENDING.
 * Old SENT / SKIPPED rows are purged after 90 days; DEAD rows stay until retried or purged by hand.
 */

const BATCH = 50;
const CONCURRENCY = 5;
const STALE_CLAIM_MS = 10 * 60_000;
const RETENTION_DAYS = 90;
const DAY_MS = 86_400_000;

export interface DeliveryDeps {
  /** undefined = from SMTP_URL / SMTP_FROM; null = e-mail not configured */
  mailer?: Mailer | null;
  /** Webhook overrides (tests): fetch, DNS lookup, allow-list */
  webhook?: Partial<WebhookDeps>;
  batch?: number;
}

export interface DeliveryResult {
  claimed: number;
  sent: number;
  retrying: number;
  dead: number;
  skipped: number;
  recovered: number;
  purged: number;
}

let cachedMailer: { key: string; mailer: Mailer } | null = null;

/** SMTP mailer from the environment, or null when SMTP_URL / SMTP_FROM are not set. */
export function mailerFromEnv(e: Env = env()): Mailer | null {
  if (!e.SMTP_URL || !e.SMTP_FROM) return null;
  const key = `${e.SMTP_URL}\n${e.SMTP_FROM}`;
  if (cachedMailer?.key !== key) {
    cachedMailer = { key, mailer: createSmtpMailer({ url: e.SMTP_URL, from: e.SMTP_FROM, production: e.NODE_ENV === "production" }) };
  }
  return cachedMailer.mailer;
}

/** Readiness (report-only): can notifications be delivered by e-mail? */
export function notificationsConfigured(e: Env = env()): boolean {
  return !!e.SMTP_URL && !!e.SMTP_FROM;
}

interface Claimed {
  id: string;
  event: string;
  severity: string;
  channel: "EMAIL" | "WEBHOOK";
  target: string;
  subject: string;
  bodyText: string;
  bodyHtml: string;
  link: string | null;
  attempts: number;
  createdAt: Date;
}

type Outcome = { kind: "sent" } | { kind: "skipped"; error: string } | { kind: "failed"; permanent: boolean; error: string };

async function claim(now: Date, batch: number): Promise<{ rows: Claimed[]; recovered: number }> {
  return withPlatform(async (tx) => {
    const recovered = await tx.notification.updateMany({
      where: { status: "SENDING", OR: [{ claimedAt: null }, { claimedAt: { lt: new Date(now.getTime() - STALE_CLAIM_MS) } }] },
      data: { status: "PENDING", nextAttemptAt: now, lastError: "recovered after worker interruption" },
    });
    const due = await tx.$queryRaw<{ id: string }[]>`
      SELECT "id" FROM "Notification" WHERE "status" = 'PENDING' AND "nextAttemptAt" <= ${now}
       ORDER BY "nextAttemptAt" ASC LIMIT ${batch} FOR UPDATE SKIP LOCKED`;
    if (due.length === 0) return { rows: [], recovered: recovered.count };
    const ids = due.map((d) => d.id);
    await tx.notification.updateMany({ where: { id: { in: ids }, status: "PENDING" }, data: { status: "SENDING", claimedAt: now, attempts: { increment: 1 } } });
    const rows = await tx.notification.findMany({
      where: { id: { in: ids }, status: "SENDING" },
      select: { id: true, event: true, severity: true, channel: true, target: true, subject: true, bodyText: true, bodyHtml: true, link: true, attempts: true, createdAt: true },
    });
    return { rows, recovered: recovered.count };
  });
}

async function deliverOne(n: Claimed, mailer: Mailer | null, hook: WebhookDeps, ring: EncKeyring | null): Promise<Outcome> {
  if (n.channel === "EMAIL") {
    if (!mailer) return { kind: "skipped", error: "e-mail not configured (SMTP_URL / SMTP_FROM)" };
    const r = await mailer.send({ to: n.target, subject: n.subject, text: n.bodyText, html: n.bodyHtml, event: n.event });
    return r.ok ? { kind: "sent" } : { kind: "failed", permanent: r.permanent, error: r.error };
  }
  if (hook.allowedHosts.length === 0) return { kind: "skipped", error: "webhooks not configured (NOTIFY_WEBHOOK_ALLOWED_HOSTS)" };
  let url: string;
  try {
    url = openOutboxTarget(n.target, ring).url; // sealed outbox copy (legacy rows: plaintext)
  } catch {
    return { kind: "failed", permanent: true, error: "webhook target could not be decrypted (AUTH_ENC_KEY / AUTH_ENC_KEY_PREVIOUS)" };
  }
  const r = await postWebhook(url, webhookPayload(n), hook);
  return r.ok ? { kind: "sent" } : { kind: "failed", permanent: r.permanent, error: r.error };
}

async function inBatches<T, R>(items: readonly T[], size: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += size) out.push(...(await Promise.all(items.slice(i, i + size).map(fn))));
  return out;
}

export async function deliverNotifications(deps: DeliveryDeps = {}, now = new Date()): Promise<DeliveryResult> {
  const e = env();
  const mailer = deps.mailer !== undefined ? deps.mailer : mailerFromEnv(e);
  const hook: WebhookDeps = {
    allowedHosts: deps.webhook?.allowedHosts ?? parseAllowedHosts(e.NOTIFY_WEBHOOK_ALLOWED_HOSTS),
    timeoutMs: deps.webhook?.timeoutMs,
    fetchImpl: deps.webhook?.fetchImpl,
    lookup: deps.webhook?.lookup,
  };
  const ring = optionalAuthKeyring(e);
  const { rows, recovered } = await claim(now, deps.batch ?? BATCH);
  const result: DeliveryResult = { claimed: rows.length, sent: 0, retrying: 0, dead: 0, skipped: 0, recovered, purged: 0 };

  if (rows.length > 0) {
    const outcomes = await inBatches(rows, CONCURRENCY, async (n) => {
      try {
        return { n, o: await deliverOne(n, mailer, hook, ring) };
      } catch (err: unknown) {
        return { n, o: { kind: "failed", permanent: false, error: err instanceof Error ? err.message.slice(0, 200) : "unknown error" } as Outcome };
      }
    });
    const done = new Date();
    await withPlatform(async (tx) => {
      for (const { n, o } of outcomes) {
        const where = { id: n.id, status: "SENDING" as const };
        if (o.kind === "sent") {
          result.sent++;
          await tx.notification.updateMany({ where, data: { status: "SENT", sentAt: done, lastError: null, claimedAt: null } });
        } else if (o.kind === "skipped") {
          result.skipped++;
          await tx.notification.updateMany({ where, data: { status: "SKIPPED", lastError: o.error, claimedAt: null } });
        } else {
          const v = afterFailure(n.attempts, o.permanent, done);
          if (v.status === "DEAD") result.dead++;
          else result.retrying++;
          await tx.notification.updateMany({
            where,
            data: { status: v.status, lastError: o.error.slice(0, 500), claimedAt: null, ...(v.status === "PENDING" ? { nextAttemptAt: v.nextAttemptAt } : {}) },
          });
          if (v.status === "DEAD") log.warn("notify.dead_letter", { id: n.id, event: n.event, channel: n.channel, attempts: n.attempts, error: o.error });
        }
      }
    });
  }

  result.purged = await withPlatform(async (tx) =>
    (await tx.notification.deleteMany({ where: { status: { in: ["SENT", "SKIPPED"] }, createdAt: { lt: new Date(now.getTime() - RETENTION_DAYS * DAY_MS) } } })).count,
  );
  if (result.claimed > 0) log.info("notify.delivered", { ...result });
  return result;
}
