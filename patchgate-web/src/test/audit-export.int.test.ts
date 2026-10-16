import { createServer, type AddressInfo } from "node:net";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, asDbAttacker, configureTestEnv, resetDb } from "./helpers";

// Local fake SIEM (plain TCP is allowed only outside production).
const received: string[] = [];
const siemServer = createServer((sock) => sock.on("data", (d) => received.push(d.toString("utf8"))));
await new Promise<void>((r) => siemServer.listen(0, "127.0.0.1", r));
const siemPort = (siemServer.address() as AddressInfo).port;

configureTestEnv({ SIEM_SYSLOG_URL: `tcp://127.0.0.1:${siemPort}`, SIEM_HOSTNAME: "patchgate-test" });

const { prisma } = await import("@/lib/db");
const { appendAudit, verifyAuditLog, verifySiemAnchor } = await import("@/lib/audit/service");
const { exportAuditToSiem, siemSenderFromEnv, auditExportStatus } = await import("@/lib/audit/export");
const { checkSiemStream } = await import("@/lib/siem/verify-stream");
type Rec = import("@/lib/siem/verify-stream").SiemRecord;

const sender = siemSenderFromEnv()!;
const event = (i: number) =>
  appendAudit({ actor: "tester", action: "test.event", entity: "Test", entityId: String(i), payload: { i } });

async function siemText(): Promise<string> {
  await new Promise((r) => setTimeout(r, 100));
  return received.join("");
}

beforeEach(async () => {
  received.length = 0;
  await resetDb(prisma);
});
afterAll(async () => {
  await prisma.$disconnect();
  await new Promise<void>((r) => siemServer.close(() => r()));
});

describe("SIEM audit export", () => {
  it("ships every event plus an ANCHOR, then reports zero lag", async () => {
    for (let i = 1; i <= 3; i++) await event(i);
    expect((await auditExportStatus()).pending).toBe(3);

    const r = await exportAuditToSiem(sender);
    expect(r.exported).toBe(3);

    const text = await siemText();
    expect(text.match(/ AUDIT \[/g)).toHaveLength(3);
    expect(text).toMatch(/ ANCHOR \[patchgate@32473 seq="\d+" hash="[a-f0-9]{64}" count="3" mac="[a-f0-9]{64}" chain="platform"\]/);
    expect((await auditExportStatus()).pending).toBe(0);

    // Nothing new → no re-send of events
    received.length = 0;
    const again = await exportAuditToSiem(sender);
    expect(again.exported).toBe(0);
    expect(await siemText()).not.toContain(" AUDIT [");
  });

  it("sends a HEARTBEAT when idle so the SIEM can alert if PatchGate goes silent", async () => {
    const r = await exportAuditToSiem(sender);
    expect(r.heartbeat).toBe(true);
    expect(await siemText()).toContain(" HEARTBEAT [");
  });

  it("does not record an anchor when the SIEM is down (events are resent later)", async () => {
    await event(1);
    const { createSyslogSender } = await import("@/lib/siem/syslog");
    const dead = createSyslogSender({ protocol: "tcp", host: "127.0.0.1", port: 1 }, { timeoutMs: 1000 });
    await expect(exportAuditToSiem(dead)).rejects.toThrow();
    expect(await prisma.auditAnchor.count()).toBe(0);
    expect((await exportAuditToSiem(sender)).exported).toBe(1);
  });
});

describe("tamper detection with SIEM anchors", () => {
  it("passes on an untouched log", async () => {
    for (let i = 1; i <= 3; i++) await event(i);
    await exportAuditToSiem(sender);
    const v = await verifyAuditLog();
    expect(v).toMatchObject({ valid: true, count: 3, anchorsChecked: 1 });
  });

  it("detects deletion of the NEWEST events after export (tail truncation)", async () => {
    for (let i = 1; i <= 3; i++) await event(i);
    await exportAuditToSiem(sender);
    await asDbAttacker(prisma, `DELETE FROM "AuditEvent" WHERE seq = (SELECT max(seq) FROM "AuditEvent")`);

    const v = await verifyAuditLog();
    expect(v.valid).toBe(false);
    expect(v.problem).toMatch(/truncated after export/);
  });

  it("detects a rewritten event even if the attacker recomputes nothing else", async () => {
    for (let i = 1; i <= 2; i++) await event(i);
    await exportAuditToSiem(sender);
    await asDbAttacker(prisma, `UPDATE "AuditEvent" SET actor = 'someone-else' WHERE seq = (SELECT min(seq) FROM "AuditEvent")`);
    expect((await verifyAuditLog()).valid).toBe(false);
  });

  it("verifies an anchor copied from the SIEM, and flags it after truncation", async () => {
    for (let i = 1; i <= 2; i++) await event(i);
    await exportAuditToSiem(sender);
    const m = /ANCHOR \[patchgate@32473 seq="(\d+)" hash="([a-f0-9]{64})"/.exec(await siemText());
    expect(m).not.toBeNull();
    const [, seq, hash] = m!;

    expect(await verifySiemAnchor(null, BigInt(seq), hash)).toEqual({ match: true, reason: null });
    // The same anchor is NOT valid for a bank's chain (chains are checked independently).
    expect((await verifySiemAnchor(TENANT_A, BigInt(seq), hash)).match).toBe(false);
    await asDbAttacker(prisma, `DELETE FROM "AuditEvent" WHERE seq = ${seq}`);
    expect((await verifySiemAnchor(null, BigInt(seq), hash)).match).toBe(false);
  });

  it("anchor table itself is append-only", async () => {
    await event(1);
    await exportAuditToSiem(sender);
    await expect(prisma.$executeRawUnsafe(`DELETE FROM "AuditAnchor"`)).rejects.toThrow(/append-only/);
  });
});

describe("SIEM-side detection (attacker deletes tail events AND their DB anchors)", () => {

  function parseSiem(text: string): Rec[] {
    // Every record carries its chain (bank id or "platform"); the SIEM rules run per chain.
    const re = / (AUDIT|ANCHOR|HEARTBEAT) \[patchgate@32473 seq="(\d+)" hash="([^"]+)"(?: prevHash="([^"]+)")?[^\]]* chain="([^"]+)"\]/g;
    return [...text.matchAll(re)].map((m) => ({ msgId: m[1] as Rec["msgId"], seq: Number(m[2]), hash: m[3], prevHash: m[4], chain: m[5] }));
  }

  it("is clean on an honest stream", async () => {
    for (let i = 1; i <= 3; i++) await event(i);
    await exportAuditToSiem(sender);
    for (let i = 4; i <= 5; i++) await event(i);
    await exportAuditToSiem(sender);
    expect(checkSiemStream(parseSiem(await siemText()))).toEqual([]);
  });

  it("flags a chain-break when the DB tail + anchors are deleted and new events follow", async () => {
    for (let i = 1; i <= 3; i++) await event(i);
    await exportAuditToSiem(sender);
    // attacker: drop the last two events and every anchor, so the DB-only check passes
    await asDbAttacker(prisma, `DELETE FROM "AuditEvent" WHERE seq > (SELECT min(seq) FROM "AuditEvent")`);
    await prisma.$executeRawUnsafe(`ALTER TABLE "AuditAnchor" DISABLE TRIGGER ALL`);
    await prisma.$executeRawUnsafe(`DELETE FROM "AuditAnchor"`);
    await prisma.$executeRawUnsafe(`ALTER TABLE "AuditAnchor" ENABLE TRIGGER ALL`);
    expect((await verifyAuditLog()).valid).toBe(true); // DB alone can no longer tell

    await event(99);
    await exportAuditToSiem(sender);
    const issues = checkSiemStream(parseSiem(await siemText()));
    expect(issues.map((i) => i.kind)).toContain("chain-break");
  });
});

describe("one audit chain per bank plus the platform chain", () => {
  const bankEvent = (tenantId: string, i: number) =>
    appendAudit({ tenantId, actor: "tester", action: "test.bank_event", entity: "Test", entityId: String(i), payload: { i } });

  it("chains are independent: each starts at genesis and verifies on its own", async () => {
    await bankEvent(TENANT_A, 1);
    await event(2);
    await bankEvent(TENANT_B, 3);
    await bankEvent(TENANT_A, 4);

    for (const [chain, count] of [[TENANT_A, 2], [TENANT_B, 1], [null, 1]] as const) {
      const rows = await prisma.auditEvent.findMany({ where: { tenantId: chain }, orderBy: { seq: "asc" } });
      expect(rows[0].prevHash).toBe("0".repeat(64));
      expect(await verifyAuditLog(chain)).toMatchObject({ valid: true, count, tenantId: chain });
    }
    expect((await auditExportStatus(TENANT_A)).pending).toBe(2);
    expect((await auditExportStatus(TENANT_B)).pending).toBe(1);
  });

  it("concurrent appends to different banks never fork either chain", async () => {
    await Promise.all(Array.from({ length: 8 }, (_, i) => bankEvent(i % 2 === 0 ? TENANT_A : TENANT_B, i)));
    expect((await verifyAuditLog(TENANT_A)).valid).toBe(true);
    expect((await verifyAuditLog(TENANT_B)).valid).toBe(true);
  });

  it("tampering in one bank's chain is reported for that bank only", async () => {
    await bankEvent(TENANT_A, 1);
    await bankEvent(TENANT_B, 2);
    await event(3);
    await asDbAttacker(prisma, `UPDATE "AuditEvent" SET actor = 'evil' WHERE "tenantId" = '${TENANT_B}'`);
    expect((await verifyAuditLog(TENANT_B)).valid).toBe(false);
    expect((await verifyAuditLog(TENANT_A)).valid).toBe(true);
    expect((await verifyAuditLog(null)).valid).toBe(true);
  });

  it("moving an event into another bank's chain is detected (tenantId is hashed)", async () => {
    await bankEvent(TENANT_A, 1);
    await asDbAttacker(prisma, `UPDATE "AuditEvent" SET "tenantId" = '${TENANT_B}'`);
    expect((await verifyAuditLog(TENANT_B)).valid).toBe(false);
  });

  it("exports every chain with its own anchors; the SIEM rules see clean per-chain streams", async () => {
    await bankEvent(TENANT_A, 1);
    await bankEvent(TENANT_B, 2);
    await event(3);
    await bankEvent(TENANT_A, 4);
    const r = await exportAuditToSiem(sender);
    expect(r.exported).toBe(4);
    expect(r.chains).toMatchObject({ platform: { exported: 1 }, [TENANT_A]: { exported: 2 }, [TENANT_B]: { exported: 1 } });
    for (const chain of [TENANT_A, TENANT_B, null]) {
      expect(await prisma.auditAnchor.count({ where: { tenantId: chain, eventCount: { gt: 0 } } })).toBe(1);
      expect((await auditExportStatus(chain)).pending).toBe(0);
      expect(await verifyAuditLog(chain)).toMatchObject({ valid: true, anchorsChecked: 1 });
    }
    const text = await siemText();
    expect(text).toContain(`chain="${TENANT_A}"`);
    expect(text).toContain(`chain="${TENANT_B}"`);
    const recs = [...text.matchAll(/ (AUDIT|ANCHOR|HEARTBEAT) \[patchgate@32473 seq="(\d+)" hash="([^"]+)"(?: prevHash="([^"]+)")?[^\]]* chain="([^"]+)"\]/g)].map(
      (m) => ({ msgId: m[1] as Rec["msgId"], seq: Number(m[2]), hash: m[3], prevHash: m[4], chain: m[5] }),
    );
    expect(checkSiemStream(recs)).toEqual([]);
  });
});
