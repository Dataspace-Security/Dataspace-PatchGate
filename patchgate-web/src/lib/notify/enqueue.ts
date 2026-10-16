import "server-only";
import type { Prisma } from "@prisma/client";
import { env } from "@/lib/env";
import { log } from "@/lib/log";
import { RLS_ROLE, type Tx } from "@/lib/tenancy/db";
import { ACCOUNT_EVENTS, EVENT_INFO, type NotificationEvent } from "./events";
import { optOutKey, resolveRecipients, type AudienceSpec, type CandidateUser, type Role } from "./recipients";
import { renderMessage, type MessageFacts } from "./templates";
import { readSettingUrls, sealOutboxTarget } from "./webhook-store";
import { optionalAuthKeyring } from "@/lib/auth/enc-keys";

/**
 * Transactional outbox: `enqueueNotification(tx, …)` is called INSIDE the transaction of the state change
 * (approval, ring stop, lockout …). If that transaction rolls back, no notification exists; if it commits,
 * the notification is durable and the worker delivers it (deliver.ts). Recipients are resolved here, now.
 *
 * Scope: rows are tenant-owned (tenantId = the bank the event concerns, null = platform event). Like
 * appendAudit, an unscoped transaction (auth / fetcher code) is scoped to the row's chain first; a
 * transaction scoped to ANOTHER bank is a programming error — logged and skipped, never thrown, so a
 * notification problem cannot undo the business change.
 */

type CrEvent = "CR_SUBMITTED" | "CR_APPROVED" | "CR_REJECTED";
type AccountEvent = "ACCOUNT_LOCKED" | "PASSWORD_RESET" | "MFA_RESET";

export type NotifyInput =
  | { event: CrEvent; tenantId: string; crId: string; actor?: { id: string; upn: string } | null; reason?: string | null }
  | { event: "RING_STOPPED"; tenantId: string; crId: string; succeeded: number; failed: number; failureRatePct: number; stopped: number }
  | { event: "CR_FAILED"; tenantId: string; crId: string; status: string; succeeded: number; total: number }
  | { event: "CR_DEADLINE"; tenantId: string; crId: string; deadline: Date; timedOut: number }
  | { event: "CONNECTOR_OFFLINE"; tenantId: string; connectorId: string; lastSeenAt: Date | null }
  | { event: "CONNECTOR_ONLINE"; tenantId: string; connectorId: string; offlineMinutes: number }
  | { event: "PACKAGE_HELD"; appVersionId: string }
  | { event: "AUDIT_CHAIN_BROKEN"; chain: string; chainTenantId: string | null; problem: string | null }
  | { event: "SIEM_EXPORT_STALE"; chain: string; chainTenantId: string | null; pending: number; minutesSinceExport: number | null }
  | { event: AccountEvent; userId: string; actor?: string | null; until?: Date | null };

interface Prepared {
  tenantId: string | null;
  facts: MessageFacts;
  spec: AudienceSpec;
}

const NONE = { bank: false, platform: false } as const;
const APPROVED_OR_LATER: ReadonlySet<string> = new Set(["APPROVED", "DEPLOYING", "COMPLETED", "PARTIAL", "FAILED"]);

async function bankName(tx: Tx, tenantId: string | null): Promise<string | null> {
  if (!tenantId) return null;
  return (await tx.tenant.findUnique({ where: { id: tenantId }, select: { name: true } }))?.name ?? null;
}

async function loadCr(tx: Tx, tenantId: string, crId: string) {
  return tx.changeRequest.findFirst({
    where: { id: crId, tenantId },
    select: {
      status: true,
      title: true,
      ticketRef: true,
      emergency: true,
      targetCount: true,
      createdById: true,
      createdBy: { select: { upn: true, tenantId: true } },
      tenant: { select: { name: true, requireBankApproval: true } },
    },
  });
}

/** Facts + audience of one event (null = nothing to send, e.g. the object vanished). */
async function prepare(tx: Tx, input: NotifyInput): Promise<Prepared | null> {
  switch (input.event) {
    case "CR_SUBMITTED":
    case "CR_APPROVED":
    case "CR_REJECTED":
    case "RING_STOPPED":
    case "CR_FAILED":
    case "CR_DEADLINE": {
      const cr = await loadCr(tx, input.tenantId, input.crId);
      if (!cr) return null;
      const facts: MessageFacts = {
        bankName: cr.tenant.name,
        crId: input.crId,
        crTitle: cr.title,
        ticketRef: cr.ticketRef,
        emergency: cr.emergency,
        maker: cr.createdBy.upn,
        targets: cr.targetCount,
      };
      const makerIsPlatform = cr.createdBy.tenantId === null;
      // Multi-approver requests (emergency / large) stay PENDING_APPROVAL after the first approval: only the
      // decision that actually moves the request notifies the maker.
      if (input.event === "CR_SUBMITTED" && cr.status !== "PENDING_APPROVAL") return null;
      if (input.event === "CR_APPROVED" && !APPROVED_OR_LATER.has(cr.status)) return null;
      if (input.event === "CR_REJECTED" && cr.status !== "REJECTED") return null;
      if (input.event === "CR_SUBMITTED") {
        const platformToo = !cr.tenant.requireBankApproval;
        return {
          tenantId: input.tenantId,
          facts,
          spec: {
            bankRoles: ["APPROVER", "ADMIN"],
            platformRoles: platformToo ? ["APPROVER", "ADMIN"] : [],
            excludeUserIds: [cr.createdById],
            webhooks: { bank: true, platform: platformToo },
          },
        };
      }
      if (input.event === "CR_APPROVED" || input.event === "CR_REJECTED") {
        return {
          tenantId: input.tenantId,
          facts: { ...facts, actor: input.actor?.upn ?? null, reason: input.reason ?? null },
          spec: { userIds: [cr.createdById], webhooks: { bank: true, platform: makerIsPlatform } },
        };
      }
      const extra: MessageFacts =
        input.event === "RING_STOPPED"
          ? { succeeded: input.succeeded, failed: input.failed, failureRatePct: input.failureRatePct, stopped: input.stopped }
          : input.event === "CR_FAILED"
            ? { status: input.status, succeeded: input.succeeded, total: input.total }
            : input.event === "CR_DEADLINE"
              ? { deadline: input.deadline, timedOut: input.timedOut }
              : {};
      return {
        tenantId: input.tenantId,
        facts: { ...facts, ...extra },
        spec: { userIds: [cr.createdById], bankRoles: ["ADMIN"], platformRoles: ["OPERATOR"], webhooks: { bank: true, platform: true } },
      };
    }
    case "CONNECTOR_OFFLINE":
    case "CONNECTOR_ONLINE": {
      const c = await tx.connector.findFirst({ where: { id: input.connectorId, tenantId: input.tenantId }, select: { name: true } });
      if (!c) return null;
      return {
        tenantId: input.tenantId,
        facts: {
          bankName: await bankName(tx, input.tenantId),
          connectorId: input.connectorId,
          connectorName: c.name,
          ...(input.event === "CONNECTOR_OFFLINE" ? { lastSeenAt: input.lastSeenAt } : { offlineMinutes: input.offlineMinutes }),
        },
        spec: { bankRoles: ["ADMIN"], platformRoles: ["ADMIN"], webhooks: { bank: true, platform: true } },
      };
    }
    case "PACKAGE_HELD": {
      const v = await tx.appVersion.findUnique({
        where: { id: input.appVersionId },
        select: { version: true, holdReason: true, signerOrg: true, sha256: true, app: { select: { displayName: true, wingetId: true } } },
      });
      if (!v) return null;
      return {
        tenantId: null,
        facts: { appName: v.app.displayName, wingetId: v.app.wingetId, version: v.version, holdReason: v.holdReason, signerOrg: v.signerOrg, sha256: v.sha256 },
        spec: { platformRoles: ["ADMIN"], webhooks: { bank: false, platform: true } },
      };
    }
    case "AUDIT_CHAIN_BROKEN":
    case "SIEM_EXPORT_STALE": {
      const facts: MessageFacts = { chain: input.chain, bankName: await bankName(tx, input.chainTenantId) };
      return {
        tenantId: null,
        facts:
          input.event === "AUDIT_CHAIN_BROKEN"
            ? { ...facts, problem: input.problem }
            : { ...facts, pending: input.pending, minutesSinceExport: input.minutesSinceExport },
        spec: { platformRoles: ["ADMIN"], webhooks: { bank: false, platform: true } },
      };
    }
    case "ACCOUNT_LOCKED":
    case "PASSWORD_RESET":
    case "MFA_RESET": {
      const u = await tx.user.findUnique({ where: { id: input.userId }, select: { name: true, tenantId: true } });
      if (!u) return null;
      return {
        tenantId: u.tenantId,
        facts: { userName: u.name, actor: input.actor ?? null, until: input.until ?? null },
        spec: { userIds: [input.userId], webhooks: NONE },
      };
    }
  }
}

/** Same rule as appendAudit: scope an unscoped transaction; refuse (false) a transaction of another bank. */
async function ensureScope(tx: Tx, tenantId: string | null, event: NotificationEvent): Promise<boolean> {
  const [cur] = await tx.$queryRaw<{ scope: string | null; tid: string | null }[]>`
    SELECT current_setting('app.scope', true) AS scope, current_setting('app.tenant_id', true) AS tid`;
  if (cur?.scope === "platform") return true;
  if (cur?.scope === "tenant") {
    if (cur.tid === tenantId) return true;
    log.error("notify.scope_mismatch", { event, rowTenant: tenantId ?? "platform", txTenant: cur.tid });
    return false;
  }
  const scope = tenantId ? "tenant" : "platform";
  await tx.$executeRaw`SELECT set_config('app.scope', ${scope}, true), set_config('app.tenant_id', ${tenantId ?? ""}, true), set_config('role', ${RLS_ROLE}, true)`;
  return true;
}

async function candidates(tx: Tx, tenantId: string | null, spec: AudienceSpec): Promise<CandidateUser[]> {
  const or: Prisma.UserWhereInput[] = [];
  if (spec.userIds?.length) or.push({ id: { in: [...spec.userIds] } });
  if (spec.platformRoles?.length) or.push({ tenantId: null, role: { in: [...spec.platformRoles] } });
  if (tenantId && spec.bankRoles?.length) or.push({ tenantId, role: { in: [...spec.bankRoles] } });
  if (or.length === 0) return [];
  const rows = await tx.user.findMany({
    where: { OR: or, active: true },
    select: { id: true, upn: true, role: true, tenantId: true, active: true, tenant: { select: { active: true } } },
    take: 500,
  });
  return rows.filter((u) => u.tenant?.active !== false).map((u) => ({ id: u.id, upn: u.upn, role: u.role as Role, tenantId: u.tenantId, active: u.active }));
}

/**
 * Write the outbox rows for one event in the caller's transaction. Returns how many rows were written.
 * Call it right after the state change it reports (same `tx`).
 */
export async function enqueueNotification(tx: Tx, input: NotifyInput): Promise<number> {
  const event = input.event;
  const prepared = await prepare(tx, input);
  if (!prepared) return 0;
  const { tenantId, facts, spec } = prepared;
  if (!(await ensureScope(tx, tenantId, event))) return 0;

  const users = await candidates(tx, tenantId, spec);
  const settingScopes = [...(tenantId ? [tenantId] : []), "platform"];
  const [optOuts, settings] = await Promise.all([
    users.length > 0 ? tx.notificationOptOut.findMany({ where: { event, userId: { in: users.map((u) => u.id) } }, select: { userId: true, event: true } }) : [],
    tx.notificationSetting.findMany({ where: { scope: { in: settingScopes } }, select: { scope: true, webhookUrlsEnc: true, webhookUrlsLegacy: true, disabledEvents: true } }),
  ]);
  const bankSetting = tenantId ? settings.find((s) => s.scope === tenantId) : undefined;
  const platformSetting = settings.find((s) => s.scope === "platform");
  const resolution = resolveRecipients({
    event,
    tenantId,
    spec,
    users,
    optOuts: new Set(optOuts.map((o) => optOutKey(o.userId, o.event))),
    bankDisabled: new Set(bankSetting?.disabledEvents ?? []),
    platformDisabled: new Set(platformSetting?.disabledEvents ?? []),
  });

  const msg = renderMessage(event, facts, env().PUBLIC_BASE_URL ?? null);
  const severity = EVENT_INFO[event].severity;
  const base = { tenantId, event, severity, subject: msg.subject, bodyText: msg.text, bodyHtml: msg.html, link: msg.link };
  const rows: Prisma.NotificationCreateManyInput[] = resolution.emails.map((r) => ({ ...base, channel: "EMAIL", target: r.address, recipientUserId: r.userId }));
  if (!ACCOUNT_EVENTS.has(event)) {
    // Webhook URLs are stored sealed (webhook-store.ts); the outbox copy is sealed again (outbox AAD).
    // Without AUTH_ENC_KEY only legacy plaintext URLs can be read, and their outbox copy stays plaintext.
    const ring = optionalAuthKeyring();
    for (const scope of resolution.webhookScopes) {
      const setting = scope === "bank" ? bankSetting : platformSetting;
      const { urls, undecryptable } = setting ? readSettingUrls(setting, ring) : { urls: [], undecryptable: [] };
      if (undecryptable.length > 0) log.warn("notify.webhook_undecryptable", { scope: setting?.scope, count: undecryptable.length });
      for (const url of urls) rows.push({ ...base, channel: "WEBHOOK", target: ring ? sealOutboxTarget(url, ring) : url });
    }
  }
  if (rows.length === 0) return 0;
  await tx.notification.createMany({ data: rows });
  return rows.length;
}

/** Change-request lifecycle hook (approvals service): submit / approve / reject notify; other actions do not. */
export async function notifyChangeRequestAction(
  tx: Tx,
  tenantId: string,
  crId: string,
  action: string,
  actor: { id: string; upn: string },
  reason?: string | null,
): Promise<number> {
  const event: CrEvent | null = action === "submit" ? "CR_SUBMITTED" : action === "approve" ? "CR_APPROVED" : action === "reject" ? "CR_REJECTED" : null;
  if (!event) return 0;
  return enqueueNotification(tx, { event, tenantId, crId, actor, reason: reason ?? null });
}
