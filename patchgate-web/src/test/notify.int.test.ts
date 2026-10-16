/**
 * Notifications (outbox) end-to-end against PostgreSQL, running as a NON-owner, NOBYPASSRLS role (like
 * production): enqueue inside the triggering transaction, delivery to a local fake SMTP server and a fake
 * webhook endpoint, retries / dead-letter / manual retry, settings + RLS isolation between banks, and the
 * time-based watcher (connector offline / back online).
 */
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createTcpServer, type Server as TcpServer } from "node:net";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, asDbAttacker, asSessionUser, configureTestEnv, resetDb } from "./helpers";

const APP_ROLE = "patchgate_app_notify_test";
const APP_PASSWORD = "notify-role-test-only-0123456789";
const HOOK_HOST = "hooks.test.example";

configureTestEnv({ PUBLIC_BASE_URL: "https://patchgate.test.local", NOTIFY_WEBHOOK_ALLOWED_HOSTS: `${HOOK_HOST}, other.test.example` });
const adminUrl = process.env.DATABASE_URL!;
const { PrismaClient } = await import("@prisma/client");
const admin = new PrismaClient({ datasourceUrl: adminUrl });

await admin.$executeRawUnsafe(`DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
    CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$$`);
await admin.$executeRawUnsafe(`ALTER ROLE ${APP_ROLE} PASSWORD '${APP_PASSWORD}'`);
await admin.$executeRawUnsafe(`GRANT USAGE ON SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT patchgate_tenant TO ${APP_ROLE}`);
const appUrl = new URL(adminUrl);
appUrl.username = APP_ROLE;
appUrl.password = APP_PASSWORD;
process.env.DATABASE_URL = appUrl.toString();

const { prisma } = await import("@/lib/db");
const { withTenant, withPlatform } = await import("@/lib/tenancy");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { enqueueNotification } = await import("@/lib/notify/enqueue");
const { deliverNotifications } = await import("@/lib/notify/deliver");
const { createSmtpMailer } = await import("@/lib/notify/smtp");
const { MAX_ATTEMPTS } = await import("@/lib/notify/backoff");
const { retryNotification, updateNotificationSettings, getNotificationSettings, listOutbox, setMyOptOut } = await import("@/lib/notify/settings");
const { watchConnectors } = await import("@/lib/notify/watch");
const { userAction } = await import("@/lib/auth/admin-service");
const { verifyAuditChainsIncremental } = await import("@/lib/audit/verify-incremental");
const { appendAudit } = await import("@/lib/audit/service");

// ---------------------------------------------------------------------------------------------
// Fake SMTP server (plain, no TLS / AUTH) and fake webhook endpoint
// ---------------------------------------------------------------------------------------------

interface Mail {
  from: string;
  to: string[];
  data: string;
}
const mails: Mail[] = [];
const REJECT_RCPT = "bounce@a.example";

function startSmtp(): Promise<TcpServer> {
  const server = createTcpServer((sock) => {
    let buf = "";
    let inData = false;
    let cur: Mail = { from: "", to: [], data: "" };
    sock.write("220 fake.smtp ESMTP\r\n");
    sock.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      for (;;) {
        if (inData) {
          const end = buf.indexOf("\r\n.\r\n");
          if (end < 0) return;
          cur.data = buf.slice(0, end);
          buf = buf.slice(end + 5);
          inData = false;
          mails.push(cur);
          cur = { from: "", to: [], data: "" };
          sock.write("250 2.0.0 queued\r\n");
          continue;
        }
        const nl = buf.indexOf("\r\n");
        if (nl < 0) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === "EHLO" || cmd === "HELO") sock.write("250-fake.smtp\r\n250 8BITMIME\r\n");
        else if (cmd === "MAIL") {
          cur.from = line;
          sock.write("250 2.1.0 ok\r\n");
        } else if (cmd === "RCPT") {
          if (line.toLowerCase().includes(REJECT_RCPT)) sock.write("550 5.1.1 mailbox unavailable\r\n");
          else {
            cur.to.push(line);
            sock.write("250 2.1.5 ok\r\n");
          }
        } else if (cmd === "DATA") {
          inData = true;
          sock.write("354 go ahead\r\n");
        } else if (cmd === "QUIT") {
          sock.end("221 bye\r\n");
          return;
        } else if (cmd === "RSET" || cmd === "NOOP") sock.write("250 ok\r\n");
        else sock.write("502 not implemented\r\n");
      }
    });
    sock.on("error", () => undefined);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

const hooks: { path: string; body: unknown }[] = [];
let hookStatus = 200;
function startHook(): Promise<HttpServer> {
  const server = createHttpServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      hooks.push({ path: req.url ?? "", body: JSON.parse(body || "null") });
      res.statusCode = hookStatus;
      res.end("ok");
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

let smtp: TcpServer;
let hook: HttpServer;
let mailer: ReturnType<typeof createSmtpMailer>;
let webhookDeps: { fetchImpl: typeof fetch; lookup: () => Promise<{ address: string }[]>; allowedHosts: string[] };

beforeAll(async () => {
  smtp = await startSmtp();
  hook = await startHook();
  const smtpPort = (smtp.address() as AddressInfo).port;
  const hookPort = (hook.address() as AddressInfo).port;
  mailer = createSmtpMailer({ url: `smtp://127.0.0.1:${smtpPort}`, from: "PatchGate <patchgate@pg.example>", production: false, timeoutMs: 5_000 });
  // The guard runs on the real https URL; only the transport is redirected to the local fake.
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const u = new URL(String(input));
    return fetch(`http://127.0.0.1:${hookPort}${u.pathname}${u.search}`, init);
  }) as typeof fetch;
  webhookDeps = { fetchImpl, lookup: async () => [{ address: "93.184.216.34" }], allowedHosts: [HOOK_HOST] };
});

const MY_TABLES = ["Notification", "NotificationSetting", "NotificationOptOut", "NotificationAlert", "ConnectorOutage"];

beforeEach(async () => {
  await resetDb(admin);
  for (const t of MY_TABLES) await admin.$executeRawUnsafe(`DELETE FROM "${t}"`);
  mails.length = 0;
  hooks.length = 0;
  hookStatus = 200;
});

afterAll(async () => {
  await prisma.$disconnect();
  await admin.$disconnect();
  await new Promise((r) => smtp.close(r));
  await new Promise((r) => hook.close(r));
});

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

async function people() {
  const mk = (upn: string, role: import("@/lib/auth/roles").Role, tenantId: string | null, name = upn) =>
    admin.user.create({ data: { upn, name, role, tenantId } }).then(asSessionUser);
  return {
    // Bank A: three admins (maker, a checker, the admin) + an auditor; auditors get no action notifications.
    maker: await mk("maker@a.example", "ADMIN", TENANT_A),
    approver: await mk("approver@a.example", "ADMIN", TENANT_A),
    bankAdmin: await mk("admin@a.example", "ADMIN", TENANT_A),
    bankAuditor: await mk("auditor@a.example", "AUDITOR", TENANT_A),
    bankBAdmin: await mk("admin@b.example", "ADMIN", TENANT_B),
    bankBAuditor: await mk("approver@b.example", "AUDITOR", TENANT_B),
    platformAdmin: await mk("padmin@pg.example", "ADMIN", null),
    platformAuditor: await mk("pop@pg.example", "AUDITOR", null),
  };
}

async function draftCr(maker: ReturnType<typeof asSessionUser>, n = 1) {
  const ring = await admin.ring.create({ data: { tenantId: TENANT_A, name: `R${n}`, wsusGroup: `R${n}`, order: n } });
  await admin.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: `agentNotify${n}`, hostname: `PC${n}`, ringId: ring.id } });
  const patch = await admin.patch.create({ data: { kind: "WINDOWS", externalId: `4444444${n}-4444-4444-4444-444444444444`, kb: `KB${n}`, title: `KB${n}`, severity: "CRITICAL" } });
  return createChangeRequest(maker, TENANT_A, { title: `Oct patches ${n}`, ringId: ring.id, patchIds: [patch.id] });
}

const rows = (where: Record<string, unknown> = {}) => admin.notification.findMany({ where, orderBy: [{ channel: "asc" }, { target: "asc" }] });

// ---------------------------------------------------------------------------------------------

describe("enqueue in the triggering transaction", () => {
  it("submit → the bank's admins (not the maker, not auditors, not bank B); approve → the maker", async () => {
    const p = await people();
    const cr = await draftCr(p.maker);
    await applyAction(p.maker, TENANT_A, cr.id, "submit");
    const submitted = await rows({ event: "CR_SUBMITTED" });
    expect(submitted.map((r) => r.target)).toEqual(["admin@a.example", "approver@a.example"]);
    expect(submitted.every((r) => r.tenantId === TENANT_A && r.status === "PENDING" && r.channel === "EMAIL")).toBe(true);
    expect(submitted[0].link).toBe(`https://patchgate.test.local/change-requests/${cr.id}`);
    expect(submitted[0].subject).toContain("Oct patches 1");

    await applyAction(p.approver, TENANT_A, cr.id, "approve");
    expect((await rows({ event: "CR_APPROVED" })).map((r) => r.target)).toEqual(["maker@a.example"]);
  });

  it("a submitted request goes to the bank's approvers only (bank approval is always required)", async () => {
    const p = await people();
    await expect(admin.tenant.update({ where: { id: TENANT_A }, data: { requireBankApproval: false } })).rejects.toThrow();
    await admin.user.create({ data: { upn: "pappr@pg.example", name: "PA", role: "ADMIN", tenantId: null } });
    const cr = await draftCr(p.maker);
    await applyAction(p.maker, TENANT_A, cr.id, "submit");
    expect((await rows({ event: "CR_SUBMITTED" })).map((r) => r.target)).toEqual(["admin@a.example", "approver@a.example"]);
  });

  it("a rolled-back transaction leaves no notification; a committed one does", async () => {
    const p = await people();
    const cr = await draftCr(p.maker);
    await expect(
      withTenant(TENANT_A, async (tx) => {
        const n = await enqueueNotification(tx, { event: "CR_DEADLINE", tenantId: TENANT_A, crId: cr.id, deadline: new Date(), timedOut: 3 });
        expect(n).toBe(4); // the maker + the other bank admins + the platform admin (never auditors)
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(await admin.notification.count()).toBe(0);
    await withTenant(TENANT_A, (tx) => enqueueNotification(tx, { event: "CR_DEADLINE", tenantId: TENANT_A, crId: cr.id, deadline: new Date(), timedOut: 3 }));
    expect((await rows()).map((r) => r.target)).toEqual(["admin@a.example", "approver@a.example", "maker@a.example", "padmin@pg.example"]);
  });

  it("an unscoped transaction (fetcher / auth code) is scoped to the row; another bank's scope is refused", async () => {
    await people();
    const app = await admin.app.create({ data: { wingetId: "Vendor.App", displayName: "Vendor App", inventoryMatch: "Vendor" } });
    const v = await admin.appVersion.create({ data: { appId: app.id, version: "1.2.3", installerUrl: "-", sha256: "b".repeat(64), silentArgs: "", verification: "HELD", holdReason: "FIRST_SIGNER", signerOrg: "Vendor Ltd" } });
    await prisma.$transaction((tx) => enqueueNotification(tx, { event: "PACKAGE_HELD", appVersionId: v.id }));
    const held = await rows({ event: "PACKAGE_HELD" });
    expect(held.map((r) => [r.target, r.tenantId])).toEqual([["padmin@pg.example", null]]);
    expect(held[0].bodyText).toContain("b".repeat(64));

    // A platform event cannot be written from a bank-scoped transaction (logged + skipped, not thrown).
    expect(await withTenant(TENANT_B, (tx) => enqueueNotification(tx, { event: "PACKAGE_HELD", appVersionId: v.id }))).toBe(0);
  });

  it("credential resets notify the affected user only; personal opt-outs do not apply to them", async () => {
    const p = await people();
    const viewer = asSessionUser(await admin.user.create({ data: { upn: "viewer@a.example", name: "Viewer", role: "AUDITOR", tenantId: TENANT_A } }));
    await userAction(p.bankAdmin, viewer.id, "reset-password");
    await userAction(p.bankAdmin, viewer.id, "reset-mfa");
    const r = (await rows()).map((x) => [x.event, x.target, x.tenantId]).sort((a, b) => String(a[0]).localeCompare(String(b[0])));
    expect(r).toEqual([
      ["MFA_RESET", "viewer@a.example", TENANT_A],
      ["PASSWORD_RESET", "viewer@a.example", TENANT_A],
    ]);
    await expect(setMyOptOut(viewer, { event: "PASSWORD_RESET", optedOut: true })).rejects.toThrow(/cannot be switched off/);
  });

  it("a broken audit chain notifies platform admins (critical)", async () => {
    await people();
    await appendAudit({ tenantId: TENANT_A, actor: "x", action: "test.one", entity: "T", entityId: "1" });
    await verifyAuditChainsIncremental(new Date());
    await asDbAttacker(admin, `UPDATE "AuditEvent" SET "actor" = 'tampered' WHERE "action" = 'test.one'`);
    await verifyAuditChainsIncremental(new Date(Date.now() + 25 * 3_600_000)); // full re-verify due
    const r = await rows({ event: "AUDIT_CHAIN_BROKEN" });
    expect(r.map((x) => [x.target, x.severity, x.tenantId])).toEqual([["padmin@pg.example", "critical", null]]);
    expect(r[0].bodyText).toContain(TENANT_A);
  });
});

describe("delivery", () => {
  it("sends e-mails over SMTP and webhooks as Teams/Slack JSON, then marks them SENT", async () => {
    const p = await people();
    await updateNotificationSettings(p.bankAdmin, TENANT_A, { action: "add-webhook", url: `https://${HOOK_HOST}/services/T0/B0/secretA` });
    const cr = await draftCr(p.maker);
    await applyAction(p.maker, TENANT_A, cr.id, "submit");
    expect((await rows()).map((r) => r.channel).sort()).toEqual(["EMAIL", "EMAIL", "WEBHOOK"]);

    const r = await deliverNotifications({ mailer, webhook: webhookDeps });
    expect(r).toMatchObject({ claimed: 3, sent: 3, dead: 0 });
    expect((await rows()).every((x) => x.status === "SENT" && x.sentAt && x.attempts === 1)).toBe(true);
    expect(mails.map((m) => m.to.join()).sort().join("|")).toMatch(/admin@a\.example.*\|.*approver@a\.example/);
    expect(mails[0].data).toMatch(/^X-PatchGate-Event: CR_SUBMITTED$/im);
    expect(mails[0].data).toMatch(/^Auto-Submitted: auto-generated$/im);
    expect(mails[0].data).toMatch(/^Subject: /m);
    expect(hooks).toHaveLength(1);
    expect(hooks[0].path).toBe("/services/T0/B0/secretA");
    expect(hooks[0].body).toMatchObject({ text: expect.stringContaining("Oct patches 1"), patchgate: { event: "CR_SUBMITTED" } });

    // Nothing is sent twice.
    expect(await deliverNotifications({ mailer, webhook: webhookDeps })).toMatchObject({ claimed: 0 });
  });

  it("retries with backoff, dead-letters permanent failures and exhausted attempts, and can be retried by a platform admin", async () => {
    const p = await people();
    await updateNotificationSettings(p.platformAdmin, "platform", { action: "add-webhook", url: `https://${HOOK_HOST}/services/P/P/secretP` });
    await admin.user.create({ data: { upn: REJECT_RCPT, name: "Bounce", role: "ADMIN", tenantId: TENANT_A } });
    const c = await admin.connector.create({ data: { tenantId: TENANT_A, name: "DC", publicKey: "k" } });
    await withTenant(TENANT_A, (tx) => enqueueNotification(tx, { event: "CONNECTOR_OFFLINE", tenantId: TENANT_A, connectorId: c.id, lastSeenAt: null }));
    hookStatus = 503;

    const now = new Date();
    const r = await deliverNotifications({ mailer, webhook: webhookDeps }, now);
    expect(r).toMatchObject({ sent: 4, retrying: 1, dead: 1 }); // 3 bank admins + the platform admin; bounce; webhook
    const bounced = await admin.notification.findFirstOrThrow({ where: { target: REJECT_RCPT } });
    expect(bounced).toMatchObject({ status: "DEAD", attempts: 1 });
    expect(bounced.lastError).toMatch(/^SMTP 550/);
    const wh = await admin.notification.findFirstOrThrow({ where: { channel: "WEBHOOK" } });
    expect(wh.status).toBe("PENDING");
    expect(wh.nextAttemptAt.getTime() - now.getTime()).toBeGreaterThanOrEqual(55_000);
    expect(wh.lastError).toContain("HTTP 503");

    // Not due yet → untouched; last allowed attempt fails → DEAD.
    expect(await deliverNotifications({ mailer, webhook: webhookDeps }, now)).toMatchObject({ claimed: 0 });
    await admin.notification.update({ where: { id: wh.id }, data: { attempts: MAX_ATTEMPTS - 1, nextAttemptAt: new Date(now.getTime() - 1) } });
    expect(await deliverNotifications({ mailer, webhook: webhookDeps }, now)).toMatchObject({ dead: 1 });
    expect((await admin.notification.findUniqueOrThrow({ where: { id: wh.id } })).status).toBe("DEAD");

    // Visible in the outbox (masked), manual retry (audited) → delivered.
    const failed = await listOutbox(p.platformAdmin, "failed");
    expect(failed.find((x) => x.id === wh.id)?.target).toBe(`https://${HOOK_HOST}/…retP`);
    await expect(retryNotification(p.bankAdmin, wh.id)).rejects.toThrow(/Platform administrators/);
    await retryNotification(p.platformAdmin, wh.id);
    expect(await admin.auditEvent.count({ where: { action: "notification.retry", tenantId: null } })).toBe(1);
    hookStatus = 200;
    expect(await deliverNotifications({ mailer, webhook: webhookDeps })).toMatchObject({ sent: 1 });
    expect((await admin.notification.findUniqueOrThrow({ where: { id: wh.id } })).status).toBe("SENT");
    await expect(retryNotification(p.platformAdmin, wh.id)).rejects.toThrow(/Only dead-lettered/);
  });

  it("skips (log-and-skip) when e-mail / webhooks are not configured, and recovers stale claims", async () => {
    const p = await people();
    const cr = await draftCr(p.maker);
    await applyAction(p.maker, TENANT_A, cr.id, "submit");
    const first = (await rows())[0];
    await admin.notification.update({ where: { id: first.id }, data: { status: "SENDING", claimedAt: new Date(Date.now() - 3_600_000) } });
    const r = await deliverNotifications({ mailer: null, webhook: { allowedHosts: [] } });
    expect(r).toMatchObject({ recovered: 1, skipped: 2, sent: 0 });
    expect((await rows()).every((x) => x.status === "SKIPPED" && /not configured/.test(x.lastError ?? ""))).toBe(true);
  });
});

describe("settings, opt-outs and RLS isolation", () => {
  it("bank admins manage only their bank; platform admins any; changes are audited with masked URLs", async () => {
    const p = await people();
    await updateNotificationSettings(p.bankAdmin, TENANT_A, { action: "add-webhook", url: `https://${HOOK_HOST}/services/A/A/tokenAAAA` });
    await expect(updateNotificationSettings(p.bankAdmin, TENANT_B, { action: "set-events", disabledEvents: [] })).rejects.toThrow(/Unknown bank/);
    await expect(updateNotificationSettings(p.bankAdmin, "platform", { action: "set-events", disabledEvents: [] })).rejects.toThrow(/Platform administrators/);
    await expect(updateNotificationSettings(p.bankAuditor, TENANT_A, { action: "set-events", disabledEvents: [] })).rejects.toThrow(/Administrators only/);
    // auditors READ the settings (webhooks masked) but cannot change them
    expect((await getNotificationSettings(p.bankAuditor, TENANT_A)).webhooks[0]?.display).toBe(`https://${HOOK_HOST}/…AAAA`);
    await expect(getNotificationSettings(p.bankAuditor, TENANT_B)).rejects.toThrow(/Unknown bank/);
    await expect(updateNotificationSettings(p.bankAdmin, TENANT_A, { action: "add-webhook", url: "https://evil.example.com/x" })).rejects.toThrow(/not allowed/);
    await expect(updateNotificationSettings(p.bankAdmin, TENANT_A, { action: "set-events", disabledEvents: ["AUDIT_CHAIN_BROKEN"] })).rejects.toThrow(/cannot be switched off/);
    await updateNotificationSettings(p.platformAdmin, TENANT_B, { action: "set-events", disabledEvents: ["CR_SUBMITTED"] });

    const view = await getNotificationSettings(p.bankAdmin, TENANT_A);
    expect(view.webhooks).toEqual([{ id: expect.stringMatching(/^[0-9a-f]{12}$/), display: `https://${HOOK_HOST}/…AAAA` }]);
    const ev = await admin.auditEvent.findFirstOrThrow({ where: { action: "notification_settings.add-webhook" } });
    expect(ev.tenantId).toBe(TENANT_A);
    expect(JSON.stringify(ev.payload)).not.toContain("tokenAAAA");
    await updateNotificationSettings(p.bankAdmin, TENANT_A, { action: "remove-webhook", id: view.webhooks[0].id });
    expect((await getNotificationSettings(p.bankAdmin, TENANT_A)).webhooks).toEqual([]);
  });

  it("bank B cannot see bank A's notifications or settings; bank scopes can read only the platform settings row", async () => {
    const p = await people();
    await updateNotificationSettings(p.bankAdmin, TENANT_A, { action: "add-webhook", url: `https://${HOOK_HOST}/services/A/A/aaaa` });
    await updateNotificationSettings(p.platformAdmin, "platform", { action: "set-events", disabledEvents: ["CONNECTOR_ONLINE"] });
    const cr = await draftCr(p.maker);
    await applyAction(p.maker, TENANT_A, cr.id, "submit");
    expect(await admin.notification.count()).toBe(3);

    expect(await withTenant(TENANT_B, (tx) => tx.notification.count())).toBe(0);
    expect(await withTenant(TENANT_A, (tx) => tx.notification.count())).toBe(3);
    expect(await prisma.notification.count()).toBe(0); // forgotten scope: nothing
    expect((await withTenant(TENANT_B, (tx) => tx.notificationSetting.findMany({ select: { scope: true } }))).map((s) => s.scope)).toEqual(["platform"]);
    await expect(withTenant(TENANT_B, (tx) => tx.notification.create({ data: { tenantId: TENANT_A, event: "CR_SUBMITTED", severity: "info", channel: "EMAIL", target: "x@b.example", subject: "s", bodyText: "b", bodyHtml: "b" } }))).rejects.toThrow(/row-level security/);
    await expect(withTenant(TENANT_B, (tx) => tx.notificationSetting.update({ where: { scope: "platform" }, data: { webhookUrlsLegacy: ["https://x"] } }))).rejects.toThrow();
    expect(await withPlatform((tx) => tx.notification.count())).toBe(3);
  });

  it("personal opt-out drops a non-critical e-mail; a disabled bank event drops bank e-mails + webhooks", async () => {
    const p = await people();
    await setMyOptOut(p.approver, { event: "CR_SUBMITTED", optedOut: true });
    expect(await admin.auditEvent.count({ where: { action: "notification.opt_out", tenantId: TENANT_A } })).toBe(1);
    const cr1 = await draftCr(p.maker, 1);
    await applyAction(p.maker, TENANT_A, cr1.id, "submit");
    expect((await rows({ event: "CR_SUBMITTED" })).map((r) => r.target)).toEqual(["admin@a.example"]);

    await updateNotificationSettings(p.bankAdmin, TENANT_A, { action: "set-events", disabledEvents: ["CR_SUBMITTED"] });
    const cr2 = await draftCr(p.maker, 2);
    await applyAction(p.maker, TENANT_A, cr2.id, "submit");
    expect(await admin.notification.count({ where: { event: "CR_SUBMITTED" } })).toBe(1);
  });
});

describe("watcher: connector offline / back online", () => {
  it("opens one outage + notifies after 10 min silence, closes it + notifies on the next heartbeat", async () => {
    await people();
    const t0 = new Date("2026-10-16T08:00:00Z");
    const c = await admin.connector.create({ data: { tenantId: TENANT_A, name: "Head office DC", publicKey: "k", enrolledAt: new Date(t0.getTime() - 86_400_000), lastSeenAt: t0 } });
    expect(await watchConnectors(new Date(t0.getTime() + 5 * 60_000))).toEqual({ offline: 0, online: 0 });
    expect(await watchConnectors(new Date(t0.getTime() + 11 * 60_000))).toEqual({ offline: 1, online: 0 });
    expect(await watchConnectors(new Date(t0.getTime() + 20 * 60_000))).toEqual({ offline: 0, online: 0 }); // once per episode
    const offline = await rows({ event: "CONNECTOR_OFFLINE" });
    expect(offline.map((r) => r.target)).toEqual(["admin@a.example", "approver@a.example", "maker@a.example", "padmin@pg.example"]);
    expect(offline[0].subject).toContain("Head office DC");

    const back = new Date(t0.getTime() + 45 * 60_000);
    await admin.connector.update({ where: { id: c.id }, data: { lastSeenAt: back } });
    expect(await watchConnectors(new Date(back.getTime() + 30_000))).toEqual({ offline: 0, online: 1 });
    const outage = await admin.connectorOutage.findFirstOrThrow({ where: { connectorId: c.id } });
    expect(outage).toMatchObject({ startedAt: t0, endedAt: back, tenantId: TENANT_A });
    expect((await rows({ event: "CONNECTOR_ONLINE" }))[0].bodyText).toContain("45 min");
  });
});
