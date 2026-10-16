import { describe, expect, it } from "vitest";
import { escapeHtml, oneLine, publicLink, renderMessage, webhookPayload } from "./templates";
import { NOTIFICATION_EVENTS } from "./events";

describe("renderMessage", () => {
  it("renders every event with a subject, text and html", () => {
    for (const e of NOTIFICATION_EVENTS) {
      const m = renderMessage(e, { bankName: "Bank A", crTitle: "Oct patches", crId: "cr1", connectorName: "DC", chain: "platform", userName: "U" }, "https://pg.example.com");
      expect(m.subject.startsWith("[PatchGate] ")).toBe(true);
      expect(m.text.length).toBeGreaterThan(10);
      expect(m.html).toContain("<!doctype html>");
    }
  });

  it("escapes HTML in every value and strips control characters from the subject", () => {
    const m = renderMessage("CR_SUBMITTED", { crTitle: "<script>alert(1)</script>\r\nBcc: x@evil", bankName: "A&B", maker: "m@b.example" }, null);
    expect(m.html).not.toContain("<script>");
    expect(m.html).toContain("&lt;script&gt;");
    expect(m.html).toContain("A&amp;B");
    expect(m.subject).not.toMatch(/[\r\n]/);
  });

  it("links to PUBLIC_BASE_URL only, and omits the link without it", () => {
    expect(renderMessage("CR_APPROVED", { crId: "abc", crTitle: "t" }, "https://pg.example.com").link).toBe("https://pg.example.com/change-requests/abc");
    expect(renderMessage("CR_APPROVED", { crId: "abc", crTitle: "t" }, null).link).toBeNull();
    expect(publicLink("javascript:alert(1)", "/x")).toBeNull();
    expect(publicLink("https://pg.example.com/base/", "/audit")).toBe("https://pg.example.com/audit");
  });

  it("never carries a temporary password in reset notices", () => {
    const m = renderMessage("PASSWORD_RESET", { userName: "Ann", actor: "admin@bank.example" }, null);
    expect(m.text).toContain("admin@bank.example");
    expect(m.text).not.toMatch(/password:\s*\S/i);
  });

  it("skips empty fields and bounds long values", () => {
    const m = renderMessage("CR_REJECTED", { crTitle: "x".repeat(2000), reason: null }, null);
    expect(m.text).not.toContain("Reason:");
    expect(m.text.length).toBeLessThan(1200);
  });
});

describe("helpers", () => {
  it("oneLine collapses whitespace and control characters", () => {
    expect(oneLine("a\r\n\tb\u0000c")).toBe("a b c");
    expect(oneLine("abcdef", 4)).toBe("abc…");
  });

  it("escapeHtml escapes quotes", () => {
    expect(escapeHtml(`"'<>&`)).toBe("&quot;&#39;&lt;&gt;&amp;");
  });

  it("webhookPayload is Teams / Slack compatible ({ text })", () => {
    const p = webhookPayload({ event: "CR_FAILED", severity: "warning", subject: "S", bodyText: "line\n— PatchGate (automated message, do not reply)", link: null, createdAt: new Date(0) });
    expect(p.text).toBe("*S*\nline");
    expect(p.patchgate).toMatchObject({ event: "CR_FAILED", severity: "warning" });
  });
});
