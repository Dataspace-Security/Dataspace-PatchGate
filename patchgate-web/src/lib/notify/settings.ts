import "server-only";
import { createHash } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import { AuthError, type SessionUser } from "@/lib/auth/session";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { DomainError } from "@/lib/errors";
import { isValidTenantId, withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { EVENT_INFO, isNotificationEvent, optOutableEvents, toggleableEvents, type NotificationEvent } from "./events";
import { maskWebhookUrl, parseAllowedHosts, validateWebhookUrl } from "./webhook";
import { optionalAuthKeyring } from "@/lib/auth/enc-keys";
import { openOutboxTarget, readSettingUrls, sealedColumns } from "./webhook-store";

/**
 * Notification settings, personal opt-outs and the outbox view.
 *  - Bank admin: own bank's webhooks + event switches.  Platform admin: platform settings + any bank.
 *  - Every user: personal opt-out of non-critical events.  Platform admins: outbox + retry.
 * Every change is audited (bank chain for bank settings, platform chain otherwise). Webhook URLs embed a
 * secret token: they are stored encrypted (AUTH_ENC_KEY, webhook-store.ts), shown masked and audited masked;
 * the full URL never leaves the server.
 */

export const PLATFORM_SCOPE = "platform";
const MAX_WEBHOOKS = 5;

export const settingsActionSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("add-webhook"), url: z.string().trim().min(10).max(2000) }),
  z.object({ action: z.literal("remove-webhook"), id: z.string().regex(/^[0-9a-f]{12}$/) }),
  z.object({ action: z.literal("set-events"), disabledEvents: z.array(z.string().max(64)).max(50) }),
]);
export type SettingsAction = z.infer<typeof settingsActionSchema>;

export const optOutSchema = z.object({ event: z.string().max(64), optedOut: z.boolean() });

export interface WebhookView {
  id: string;
  display: string;
}

export interface SettingsView {
  scope: string;
  scopeName: string;
  webhooks: WebhookView[];
  events: { event: NotificationEvent; label: string; severity: string; enabled: boolean }[];
  webhookHosts: string[];
  updatedAt: Date | null;
  updatedBy: string | null;
}

export function webhookId(url: string): string {
  return createHash("sha256").update(url).digest("hex").slice(0, 12);
}

/** Who may manage which scope: platform admins any; bank admins their own bank only. */
export function assertCanManage(actor: Pick<SessionUser, "role" | "tenantId">, scope: string): void {
  if (actor.role !== "ADMIN") throw new AuthError("Administrators only", 403);
  if (scope === PLATFORM_SCOPE) {
    if (actor.tenantId !== null) throw new AuthError("Platform administrators only", 403);
    return;
  }
  if (!isValidTenantId(scope)) throw new DomainError("Unknown bank", 404);
  if (actor.tenantId !== null && actor.tenantId !== scope) throw new DomainError("Unknown bank", 404);
}

function inScope<T>(scope: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return scope === PLATFORM_SCOPE ? withPlatform(fn) : withTenant(scope, fn);
}

async function scopeName(scope: string): Promise<string> {
  if (scope === PLATFORM_SCOPE) return "PatchGate platform";
  const t = await prisma.tenant.findUnique({ where: { id: scope }, select: { name: true } });
  if (!t) throw new DomainError("Unknown bank", 404);
  return t.name;
}

export async function getNotificationSettings(actor: SessionUser, scope: string): Promise<SettingsView> {
  assertCanManage(actor, scope);
  const name = await scopeName(scope);
  const row = await inScope(scope, (tx) => tx.notificationSetting.findUnique({ where: { scope } }));
  const disabled = new Set(row?.disabledEvents ?? []);
  const urls = row ? readSettingUrls(row, optionalAuthKeyring()).urls : [];
  return {
    scope,
    scopeName: name,
    webhooks: urls.map((u) => ({ id: webhookId(u), display: maskWebhookUrl(u) })),
    events: toggleableEvents(scope === PLATFORM_SCOPE ? "platform" : "bank").map((e) => ({ event: e, label: EVENT_INFO[e].label, severity: EVENT_INFO[e].severity, enabled: !disabled.has(e) })),
    webhookHosts: parseAllowedHosts(env().NOTIFY_WEBHOOK_ALLOWED_HOSTS),
    updatedAt: row?.updatedAt ?? null,
    updatedBy: row?.updatedBy ?? null,
  };
}

export async function updateNotificationSettings(actor: SessionUser, scope: string, action: SettingsAction): Promise<SettingsView> {
  assertCanManage(actor, scope);
  await scopeName(scope);
  const tenantId = scope === PLATFORM_SCOPE ? null : scope;
  await inScope(scope, async (tx) => {
    const row = await tx.notificationSetting.findUnique({ where: { scope } });
    const ring = optionalAuthKeyring();
    const stored = row ? readSettingUrls(row, ring) : { urls: [], undecryptable: [], stale: false };
    let webhookUrls = stored.urls;
    let disabledEvents = row?.disabledEvents ?? [];
    let payload: Record<string, string | string[]>;
    if (action.action === "add-webhook") {
      let url: string;
      try {
        url = validateWebhookUrl(action.url, parseAllowedHosts(env().NOTIFY_WEBHOOK_ALLOWED_HOSTS));
      } catch (err: unknown) {
        throw new DomainError(err instanceof Error ? err.message : "Invalid webhook URL", 400);
      }
      if (webhookUrls.includes(url)) throw new DomainError("This webhook is already configured", 409);
      if (webhookUrls.length >= MAX_WEBHOOKS) throw new DomainError(`At most ${MAX_WEBHOOKS} webhooks per scope`, 400);
      webhookUrls = [...webhookUrls, url];
      payload = { added: maskWebhookUrl(url), id: webhookId(url) };
    } else if (action.action === "remove-webhook") {
      const victim = webhookUrls.find((u) => webhookId(u) === action.id);
      if (!victim) throw new DomainError("Webhook not found", 404);
      webhookUrls = webhookUrls.filter((u) => u !== victim);
      payload = { removed: maskWebhookUrl(victim), id: action.id };
    } else {
      const allowed = new Set<string>(toggleableEvents(tenantId ? "bank" : "platform"));
      const bad = action.disabledEvents.filter((e) => !allowed.has(e));
      if (bad.length > 0) throw new DomainError(`These events cannot be switched off here: ${bad.slice(0, 5).join(", ")}`, 400);
      const before = new Set(disabledEvents);
      disabledEvents = [...new Set(action.disabledEvents)].sort();
      payload = { disabled: disabledEvents.filter((e) => !before.has(e)), enabled: [...before].filter((e) => !disabledEvents.includes(e)) };
    }
    const urlsChanged = action.action !== "set-events";
    if (urlsChanged && !ring) throw new DomainError("Webhook URLs are stored encrypted: configure AUTH_ENC_KEY first", 409);
    // Any write re-seals the URLs under the current key (drains legacy plaintext as a side effect).
    const sealed = ring && (urlsChanged || stored.stale) ? sealedColumns(scope, webhookUrls, stored.undecryptable, ring) : {};
    const data = { tenantId, ...sealed, disabledEvents, updatedBy: actor.upn };
    await tx.notificationSetting.upsert({ where: { scope }, create: { scope, ...data }, update: data });
    await appendAudit(
      { tenantId, actor: actor.upn, action: `notification_settings.${action.action}`, entity: "NotificationSetting", entityId: scope, payload: { ...payload, actorBank: actor.tenantId ?? "platform" } as Prisma.InputJsonValue },
      tx,
    );
  });
  return getNotificationSettings(actor, scope);
}

// ---------- Personal opt-outs ----------

export interface OptOutView {
  event: NotificationEvent;
  label: string;
  optedOut: boolean;
}

export async function getMyOptOuts(user: SessionUser): Promise<OptOutView[]> {
  const rows = await prisma.notificationOptOut.findMany({ where: { userId: user.id }, select: { event: true } });
  const out = new Set(rows.map((r) => r.event));
  return optOutableEvents(user.tenantId === null).map((e) => ({ event: e, label: EVENT_INFO[e].label, optedOut: out.has(e) }));
}

export async function setMyOptOut(user: SessionUser, raw: unknown): Promise<OptOutView[]> {
  const input = optOutSchema.parse(raw);
  if (!isNotificationEvent(input.event) || !optOutableEvents(user.tenantId === null).includes(input.event)) {
    throw new DomainError("This notification cannot be switched off", 400);
  }
  const event = input.event;
  await prisma.$transaction(async (tx) => {
    if (input.optedOut) {
      await tx.notificationOptOut.upsert({ where: { userId_event: { userId: user.id, event } }, create: { userId: user.id, event }, update: {} });
    } else {
      await tx.notificationOptOut.deleteMany({ where: { userId: user.id, event } });
    }
    await appendAudit({ tenantId: user.tenantId, actor: user.upn, action: input.optedOut ? "notification.opt_out" : "notification.opt_in", entity: "User", entityId: user.id, payload: { event } }, tx);
  });
  return getMyOptOuts(user);
}

// ---------- Outbox (platform admins) ----------

export interface OutboxRow {
  id: string;
  createdAt: Date;
  bank: string | null;
  event: string;
  severity: string;
  channel: string;
  target: string;
  subject: string;
  status: string;
  attempts: number;
  nextAttemptAt: Date;
  lastError: string | null;
  sentAt: Date | null;
}

export type OutboxFilter = "recent" | "failed";

function requirePlatformAdmin(actor: SessionUser): void {
  if (actor.tenantId !== null || actor.role !== "ADMIN") throw new AuthError("Platform administrators only", 403);
}

export async function listOutbox(actor: SessionUser, filter: OutboxFilter = "recent", take = 100): Promise<OutboxRow[]> {
  requirePlatformAdmin(actor);
  const rows = await withPlatform((tx) =>
    tx.notification.findMany({
      where: filter === "failed" ? { OR: [{ status: { in: ["DEAD", "SKIPPED"] } }, { status: "PENDING", attempts: { gt: 0 } }] } : {},
      orderBy: { createdAt: "desc" },
      take: Math.min(Math.max(take, 1), 500),
      select: { id: true, createdAt: true, tenantId: true, event: true, severity: true, channel: true, target: true, subject: true, status: true, attempts: true, nextAttemptAt: true, lastError: true, sentAt: true },
    }),
  );
  const ids = [...new Set(rows.map((r) => r.tenantId).filter((t): t is string => !!t))];
  const banks = new Map((await prisma.tenant.findMany({ where: { id: { in: ids } }, select: { id: true, name: true } })).map((t) => [t.id, t.name]));
  const ring = optionalAuthKeyring();
  const shown = (r: { channel: string; target: string }) => {
    if (r.channel !== "WEBHOOK") return r.target;
    try {
      return maskWebhookUrl(openOutboxTarget(r.target, ring).url);
    } catch {
      return "(encrypted webhook)";
    }
  };
  return rows.map(({ tenantId, ...r }) => ({ ...r, bank: tenantId ? (banks.get(tenantId) ?? tenantId) : null, target: shown(r) }));
}

export async function outboxCounts(actor: SessionUser): Promise<Record<string, number>> {
  requirePlatformAdmin(actor);
  const g = await withPlatform((tx) => tx.notification.groupBy({ by: ["status"], _count: { _all: true } }));
  return Object.fromEntries(g.map((x) => [x.status, x._count._all]));
}

/** Put a dead-lettered / skipped row back in the queue (fresh attempt budget). */
export async function retryNotification(actor: SessionUser, id: string): Promise<{ id: string; status: string }> {
  requirePlatformAdmin(actor);
  if (!/^[a-z0-9]{10,40}$/i.test(id)) throw new DomainError("Notification not found", 404);
  return withPlatform(async (tx) => {
    const { count } = await tx.notification.updateMany({
      where: { id, status: { in: ["DEAD", "SKIPPED"] } },
      data: { status: "PENDING", attempts: 0, nextAttemptAt: new Date(), lastError: null, claimedAt: null },
    });
    if (count !== 1) throw new DomainError("Only dead-lettered or skipped notifications can be retried", 409);
    const n = await tx.notification.findUniqueOrThrow({ where: { id }, select: { event: true, channel: true, tenantId: true } });
    await appendAudit({ actor: actor.upn, action: "notification.retry", entity: "Notification", entityId: id, payload: { event: n.event, channel: n.channel, bank: n.tenantId } }, tx);
    return { id, status: "PENDING" };
  });
}
