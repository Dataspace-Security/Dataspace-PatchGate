import { describe, expect, it } from "vitest";
import { isEmailAddress, optOutKey, resolveRecipients, type CandidateUser } from "./recipients";
import { isCritical, optOutableEvents, toggleableEvents } from "./events";

const A = "bank-a";
const users: CandidateUser[] = [
  { id: "maker", upn: "maker@a.example", role: "ADMIN", tenantId: A, active: true },
  { id: "appr", upn: "Approver@A.example", role: "ADMIN", tenantId: A, active: true },
  { id: "adm", upn: "admin@a.example", role: "ADMIN", tenantId: A, active: true },
  { id: "aud", upn: "auditor@a.example", role: "AUDITOR", tenantId: A, active: true },
  { id: "other", upn: "appr@b.example", role: "ADMIN", tenantId: "bank-b", active: true },
  { id: "pAdm", upn: "padmin@pg.example", role: "ADMIN", tenantId: null, active: true },
  { id: "pAud", upn: "paud@pg.example", role: "AUDITOR", tenantId: null, active: true },
  { id: "off", upn: "off@a.example", role: "ADMIN", tenantId: A, active: false },
  { id: "noMail", upn: "localonly", role: "ADMIN", tenantId: A, active: true },
];
const empty = new Set<string>();

function emails(r: ReturnType<typeof resolveRecipients>): string[] {
  return r.emails.map((e) => e.address).sort();
}

describe("resolveRecipients", () => {
  it("CR submitted: the admins (checkers) of THIS bank, never the maker, auditors, inactive or non-mail users", () => {
    const r = resolveRecipients({
      event: "CR_SUBMITTED",
      tenantId: A,
      spec: { bankRoles: ["ADMIN"], platformRoles: [], excludeUserIds: ["maker"], webhooks: { bank: true, platform: false } },
      users,
      optOuts: empty,
      bankDisabled: empty,
      platformDisabled: empty,
    });
    expect(emails(r)).toEqual(["admin@a.example", "approver@a.example"]);
    expect(r.webhookScopes).toEqual(["bank"]);
  });

  it("platform admins are added when asked (never platform auditors)", () => {
    const r = resolveRecipients({
      event: "CR_SUBMITTED",
      tenantId: A,
      spec: { bankRoles: ["ADMIN"], platformRoles: ["ADMIN"], excludeUserIds: ["maker"], webhooks: { bank: true, platform: true } },
      users,
      optOuts: empty,
      bankDisabled: empty,
      platformDisabled: empty,
    });
    expect(emails(r)).toEqual(["admin@a.example", "approver@a.example", "padmin@pg.example"]);
    expect(r.webhookScopes).toEqual(["bank", "platform"]);
  });

  it("failed rollouts: the maker + bank admins + platform admins (auditors get no action notifications)", () => {
    const r = resolveRecipients({
      event: "RING_STOPPED",
      tenantId: A,
      spec: { userIds: ["maker"], bankRoles: ["ADMIN"], platformRoles: ["ADMIN"], webhooks: { bank: true, platform: true } },
      users,
      optOuts: empty,
      bankDisabled: empty,
      platformDisabled: empty,
    });
    expect(emails(r)).toEqual(["admin@a.example", "approver@a.example", "maker@a.example", "padmin@pg.example"]);
  });

  it("personal opt-outs and scope switches drop non-critical events", () => {
    const base = {
      event: "CONNECTOR_OFFLINE" as const,
      tenantId: A,
      spec: { bankRoles: ["ADMIN" as const], platformRoles: ["ADMIN" as const], webhooks: { bank: true, platform: true } },
      users,
    };
    const optedOut = resolveRecipients({ ...base, optOuts: new Set([optOutKey("adm", "CONNECTOR_OFFLINE")]), bankDisabled: empty, platformDisabled: empty });
    expect(emails(optedOut)).toEqual(["approver@a.example", "maker@a.example", "padmin@pg.example"]);
    const bankOff = resolveRecipients({ ...base, optOuts: empty, bankDisabled: new Set(["CONNECTOR_OFFLINE"]), platformDisabled: empty });
    expect(emails(bankOff)).toEqual(["padmin@pg.example"]);
    expect(bankOff.webhookScopes).toEqual(["platform"]);
  });

  it("critical events ignore opt-outs and switches", () => {
    const r = resolveRecipients({
      event: "AUDIT_CHAIN_BROKEN",
      tenantId: null,
      spec: { platformRoles: ["ADMIN"], webhooks: { bank: false, platform: true } },
      users,
      optOuts: new Set([optOutKey("pAdm", "AUDIT_CHAIN_BROKEN")]),
      bankDisabled: empty,
      platformDisabled: new Set(["AUDIT_CHAIN_BROKEN"]),
    });
    expect(emails(r)).toEqual(["padmin@pg.example"]);
    expect(r.webhookScopes).toEqual(["platform"]);
  });

  it("a platform event never selects bank users and never uses bank webhooks", () => {
    const r = resolveRecipients({
      event: "PACKAGE_HELD",
      tenantId: null,
      spec: { bankRoles: ["ADMIN"], platformRoles: ["ADMIN"], webhooks: { bank: true, platform: true } },
      users,
      optOuts: empty,
      bankDisabled: empty,
      platformDisabled: empty,
    });
    expect(emails(r)).toEqual(["padmin@pg.example"]);
    expect(r.webhookScopes).toEqual(["platform"]);
  });
});

describe("event catalogue", () => {
  it("critical events cannot be toggled or opted out of", () => {
    for (const e of [...toggleableEvents("bank"), ...toggleableEvents("platform"), ...optOutableEvents(true), ...optOutableEvents(false)]) {
      expect(isCritical(e)).toBe(false);
    }
    expect(toggleableEvents("bank")).not.toContain("PACKAGE_HELD");
    expect(toggleableEvents("platform")).toContain("PACKAGE_HELD");
  });

  it("isEmailAddress", () => {
    expect(isEmailAddress("a.b@bank.example")).toBe(true);
    expect(isEmailAddress("a@b")).toBe(false);
    expect(isEmailAddress("a <a@b.example>")).toBe(false);
    expect(isEmailAddress("x@y.example\r\nBcc: z@q.example")).toBe(false);
  });
});
