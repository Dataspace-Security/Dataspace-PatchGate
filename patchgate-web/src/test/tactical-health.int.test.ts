/**
 * Tactical health of a bank site (heartbeat.tacticalHealth) end-to-end against PostgreSQL, running as a NON-owner,
 * NOBYPASSRLS role (like production): heartbeats store it, the watcher raises ONE critical TACTICAL_UNHEALTHY +
 * `tactical.unhealthy` on the bank's chain after 5 minutes, coalesces repeated runs, sends TACTICAL_RECOVERED +
 * `tactical.recovered` when the site is ok again, and bank B sees none of bank A's alert rows.
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

const APP_ROLE = "patchgate_app_tactical_health_test";
const APP_PASSWORD = "tactical-health-role-test-only-0123";

configureTestEnv({ PUBLIC_BASE_URL: "https://patchgate.test.local" });
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
const { withTenant } = await import("@/lib/tenancy");
const { recordHeartbeat } = await import("@/lib/connector/heartbeat");
const { watchTacticalHealth } = await import("@/lib/connector/tactical-health");
const { runNotificationWatch } = await import("@/lib/notify/watch");
const { connectorHealth } = await import("@/lib/connector/admin");

const T0 = new Date("2026-10-17T08:00:00Z");
const min = (n: number) => new Date(T0.getTime() + n * 60_000);

beforeEach(async () => {
  await resetDb(admin);
});
afterAll(async () => {
  await prisma.$disconnect();
  await admin.$disconnect();
});

async function setup(tenantId = TENANT_A, name = "Head office") {
  await admin.user.create({ data: { upn: `admin@${tenantId}.example`, name: "Bank admin", role: "ADMIN", tenantId } });
  await admin.user.create({ data: { upn: `auditor@${tenantId}.example`, name: "Bank auditor", role: "AUDITOR", tenantId } });
  await admin.user.upsert({ where: { upn: "padmin@pg.example" }, update: {}, create: { upn: "padmin@pg.example", name: "Platform admin", role: "ADMIN", tenantId: null } });
  const c = await admin.connector.create({ data: { tenantId, name, publicKey: `k-${tenantId}`, enrolledAt: new Date(T0.getTime() - 86_400_000), lastSeenAt: T0 } });
  return { id: c.id, tenantId, name, maxConcurrentInstalls: c.maxConcurrentInstalls, bandwidthLimitMbps: c.bandwidthLimitMbps };
}

type Authed = Awaited<ReturnType<typeof setup>>;
const heartbeat = (c: Authed, at: Date, health: Record<string, unknown> | undefined) =>
  recordHeartbeat(c, { version: "1.0.0", cache: { files: 0, bytes: 0 }, tactical: { reachable: true, agents: 3 }, ...(health ? { tacticalHealth: health } : {}) }, at);
const natsdown = (since: Date, restarts = 2) => ({
  state: "natsdown",
  since: since.toISOString(),
  detail: "site watchdog: next restart in 60s (back-off)",
  watchdog: { nats: "down", checkedAt: since.toISOString(), restartsLastHour: restarts, lastRestartAt: since.toISOString() },
});
const notifications = (event: string) => admin.notification.findMany({ where: { event }, orderBy: { target: "asc" } });
const audits = (action: string) => admin.auditEvent.findMany({ where: { action }, orderBy: { seq: "asc" } });

describe("Tactical health alerts", () => {
  it("raises one critical alert after 5 min natsdown (coalesced), recovers once when ok again", async () => {
    const c = await setup();
    await heartbeat(c, min(0), natsdown(min(0)));
    expect(await watchTacticalHealth(min(3))).toEqual({ raised: 0, recovered: 0 }); // under the threshold

    await heartbeat(c, min(6), natsdown(min(0), 4));
    expect(await watchTacticalHealth(min(6))).toEqual({ raised: 1, recovered: 0 });
    await heartbeat(c, min(8), natsdown(min(0), 5));
    expect(await watchTacticalHealth(min(8))).toEqual({ raised: 0, recovered: 0 }); // same episode: no flood
    expect(await watchTacticalHealth(min(9))).toEqual({ raised: 0, recovered: 0 });

    const sent = await notifications("TACTICAL_UNHEALTHY");
    expect(sent.map((n) => n.target)).toEqual(["admin@tenant-default.example", "padmin@pg.example"]); // not the auditor
    expect(sent[0]).toMatchObject({ severity: "critical", tenantId: TENANT_A });
    expect(sent[0].subject).toContain("Tactical messaging down at Head office");
    expect(sent[0].bodyText).toContain("RUNBOOK");
    const [unhealthy] = await audits("tactical.unhealthy");
    expect(unhealthy).toMatchObject({ tenantId: TENANT_A, entity: "Connector", entityId: c.id, actor: "system" });
    expect(unhealthy.payload).toMatchObject({ state: "natsdown", since: min(0).toISOString(), watchdogRestartsLastHour: 4 });

    // the UI's health card sees it too
    const health = await connectorHealth(TENANT_A, min(8));
    expect(health.tacticalMessagingDown.map((x) => x.name)).toEqual(["Head office"]);
    expect(health.tacticalDown).toEqual([]);

    await heartbeat(c, min(10), { state: "ok", since: min(10).toISOString(), detail: null, watchdog: null });
    expect(await watchTacticalHealth(min(10))).toEqual({ raised: 0, recovered: 1 });
    expect(await watchTacticalHealth(min(11))).toEqual({ raised: 0, recovered: 0 });
    const back = await notifications("TACTICAL_RECOVERED");
    expect(back).toHaveLength(2);
    expect(back[0].bodyText).toContain("4 min"); // alerted at minute 6, ok at minute 10
    expect(await audits("tactical.recovered")).toHaveLength(1);
    expect(await admin.notificationAlert.count()).toBe(0);

    // a new episode is a new alert
    await heartbeat(c, min(30), natsdown(min(20)));
    expect(await watchTacticalHealth(min(30))).toEqual({ raised: 1, recovered: 0 });
    expect(await notifications("TACTICAL_UNHEALTHY")).toHaveLength(4);
  });

  it("short blips, older connectors without tacticalHealth and offline connectors raise nothing", async () => {
    const c = await setup();
    // blip fixed by the watchdog within the threshold
    await heartbeat(c, min(0), natsdown(min(0)));
    await heartbeat(c, min(2), { state: "ok", since: min(2).toISOString() });
    expect(await watchTacticalHealth(min(7))).toEqual({ raised: 0, recovered: 0 });
    // older connector: only tactical.reachable=false, outage cannot be timed → shown, not alerted
    await recordHeartbeat(c, { version: "0.9.0", cache: { files: 0, bytes: 0 }, tactical: { reachable: false, agents: null, error: "ECONNREFUSED" } }, min(8));
    expect(await watchTacticalHealth(min(14))).toEqual({ raised: 0, recovered: 0 });
    // connector itself offline (> 10 min without heartbeat): CONNECTOR_OFFLINE covers it, no Tactical alert
    await heartbeat(c, min(40), natsdown(min(40)));
    expect(await watchTacticalHealth(min(60))).toEqual({ raised: 0, recovered: 0 });
    expect(await notifications("TACTICAL_UNHEALTHY")).toHaveLength(0);
  });

  it("unreachable alerts too; runs inside the notification watch; RLS: bank B never sees bank A's alert", async () => {
    const a = await setup(TENANT_A, "Head office");
    const b = await setup(TENANT_B, "Branch B");
    await heartbeat(a, min(0), { state: "unreachable", since: min(0).toISOString(), detail: "Tactical unreachable (GET /agents/): ECONNREFUSED", watchdog: null });
    await heartbeat(b, min(0), { state: "ok", since: min(0).toISOString() });
    await heartbeat(a, min(7), { state: "unreachable", since: min(0).toISOString(), detail: "Tactical unreachable (GET /agents/): ECONNREFUSED", watchdog: null });
    await heartbeat(b, min(7), { state: "ok", since: min(0).toISOString() });
    const r = await runNotificationWatch(min(7));
    expect(r).toMatchObject({ tacticalUnhealthy: 1, tacticalRecovered: 0 });
    expect((await notifications("TACTICAL_UNHEALTHY"))[0].subject).toContain("Tactical unreachable at Head office");

    const seenByB = await withTenant(TENANT_B, (tx) => tx.notificationAlert.findMany({ where: { key: { startsWith: "tactical-health:" } } }));
    expect(seenByB).toEqual([]);
    const seenByA = await withTenant(TENANT_A, (tx) => tx.notificationAlert.findMany({ where: { key: { startsWith: "tactical-health:" } } }));
    expect(seenByA.map((x) => x.key)).toEqual([`tactical-health:${a.id}`]);
    // bank B cannot remove bank A's alert either
    const { count } = await withTenant(TENANT_B, (tx) => tx.notificationAlert.deleteMany({ where: { key: `tactical-health:${a.id}` } }));
    expect(count).toBe(0);
    expect(await audits("tactical.unhealthy")).toHaveLength(1);
    expect((await audits("tactical.unhealthy"))[0].tenantId).toBe(TENANT_A);

    // revoked connector: its open alert is dropped silently
    await admin.connector.update({ where: { id: a.id }, data: { status: "REVOKED" } });
    expect(await watchTacticalHealth(min(8))).toEqual({ raised: 0, recovered: 0 });
    expect(await admin.notificationAlert.count()).toBe(0);
    expect(await notifications("TACTICAL_RECOVERED")).toHaveLength(0);
  });
});
