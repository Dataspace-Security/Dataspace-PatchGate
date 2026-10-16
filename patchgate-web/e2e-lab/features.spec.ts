import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import {
  actFor,
  BANK_A_ADMIN,
  BANK_A_APPROVER,
  BANK_A_AUDITOR,
  expect,
  go,
  hydrated,
  LAB_DIR,
  labScript,
  newSession,
  pageFetch,
  PLATFORM_ADMIN,
  PLATFORM_AUDITOR,
  shot,
  shotThemes,
  signIn,
  submitLogin,
  test,
  until,
  waitForHydratedForm,
} from "./helpers";

/**
 * Production-readiness regression suite against the RUNNING hosted lab (lab/up-all.sh), following
 * docs/TEST-PLAN-VMWARE.md areas 2–13 adapted to the lab. There is no real Windows PC in the lab: the PC is
 * simulated in Tactical's database (lab/fixtures/sim-tactical-agent.sh, "LAB-SIM-PC01"), so everything a PC
 * itself does (install, reboot, WU registry lock) is out of scope here — see the VMware test plan.
 * Every test fails on a browser console error or any 5xx answer (helpers.ts). Screenshots: e2e-lab/screenshots/.
 */

const SIM_PC = "LAB-SIM-PC01";
const RUN = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
const strongPassword = (): string => `E2e-${randomBytes(12).toString("hex")}-Pg!`;

/** Accept the next confirm()/prompt() dialog (prompt answered with `answer`), and return its text. */
function acceptDialog(page: Page, answer?: string): { text: () => string } {
  let text = "";
  page.once("dialog", (d) => {
    text = d.message();
    void d.accept(answer);
  });
  return { text: () => text };
}

/** Read-only query against the lab database (patchgate_lab) — one value per row. */
function labSql(sql: string): string[] {
  return execFileSync("docker", ["exec", "patchgate-dev-db", "psql", "-U", "patchgate", "-d", "patchgate_lab", "-tA", "-c", sql], { encoding: "utf8" })
    .split(/\r?\n/)
    .filter(Boolean);
}

// =============================================================================================================
// 2. Sign-in and accounts (password only)
// =============================================================================================================
test.describe("2 accounts", () => {
  test.describe.configure({ mode: "serial" });
  const upn = `e2e-auditor-${RUN}@bank-a.lab`;
  let password = "";

  test("2.4 platform admin creates a bank auditor; the temporary password is shown once", async ({ page }) => {
    await signIn(page, PLATFORM_ADMIN);
    await go(page, "/admin/users");
    await hydrated(page, "main button");
    await page.getByRole("button", { name: "New user" }).click();
    const form = page.locator("form").filter({ hasText: "Sign-in name (UPN)" });
    await form.getByLabel("Sign-in name (UPN)").fill(upn);
    await form.getByLabel("Full name").fill("E2E Auditor");
    await form.locator("label").filter({ hasText: /^Role/ }).locator("select").selectOption({ label: "Auditor (read-only)" });
    await form.locator("label").filter({ hasText: /^Bank/ }).locator("select").selectOption({ label: "Bank A" });
    await form.getByRole("button", { name: "Create user" }).click();
    const box = page.getByRole("alert").filter({ hasText: `temporary password for ${upn}` });
    await expect(box).toBeVisible();
    password = ((await box.locator("code").textContent()) ?? "").trim();
    expect(password.length).toBeGreaterThanOrEqual(14);
    await box.getByRole("button", { name: "Dismiss" }).click(); // never in a screenshot
    await expect(box).toHaveCount(0);
    const row = page.getByRole("row").filter({ hasText: upn });
    await expect(row.getByText("temp password")).toBeVisible();
    await shotThemes(page, "f02-admin-users");
  });

  test("2.2 first sign-in with the temporary password forces a new password", async ({ page }) => {
    expect(password).not.toBe("");
    expect(await submitLogin(page, upn, password)).toBe("change-password");
    await expect(page.getByText(/You need a new password before you can continue/)).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Main" })).toHaveCount(0); // signed out: no app navigation
    await shot(page, "f03-forced-password-change");
    const next = strongPassword();
    await page.getByLabel("New password", { exact: true }).fill(next);
    await page.getByLabel("Confirm new password").fill(next);
    await page.getByRole("button", { name: "Set password and sign in" }).click();
    await page.waitForURL((u) => !u.pathname.startsWith("/login"));
    password = next;
    await expect(page.getByRole("link", { name: "My account" })).toBeVisible();
  });

  test("2.5 the auditor sees everything but has no write buttons, and the API refuses changes", async ({ page }) => {
    await signIn(page, upn, { password });
    await go(page, "/patches?needed=0");
    await expect(page.getByText("Read-only (auditor): only admins create change requests.")).toBeVisible();
    await expect(page.locator("tbody input[type=checkbox]:not([disabled])")).toHaveCount(0);
    await go(page, "/endpoints");
    await expect(page.getByRole("button", { name: "Sync agents now" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Request scan of all PCs" })).toHaveCount(0);
    await go(page, "/admin/users");
    await expect(page.getByRole("button", { name: "New user" })).toHaveCount(0);
    await go(page, "/settings/approvals");
    await expect(page.getByRole("button", { name: "Save policy" })).toHaveCount(0);
    await shotThemes(page, "f04-bank-auditor-approvals-read-only");
    const probes = {
      cr: await pageFetch(page, "/api/change-requests", { method: "POST", body: { title: "x", ringId: "x", patchIds: ["x"] } }),
      approvals: await pageFetch(page, "/api/settings/approvals", { method: "PATCH", body: { requireBankApproval: false } }),
      sync: await pageFetch(page, "/api/endpoints/sync", { method: "POST", body: {} }),
      scan: await pageFetch(page, "/api/endpoints/scan", { method: "POST", body: {} }),
      ring: await pageFetch(page, "/api/settings/rings", { method: "POST", body: { name: "nope" } }),
      ack: await pageFetch(page, "/api/tactical-activity/ack", { method: "POST", body: { reason: "nope" } }),
    };
    for (const [k, r] of Object.entries(probes)) expect(r.status, `${k}: ${r.text.slice(0, 120)}`).toBe(403);
  });

  test("2.6 /account: change own password; the other session is signed out", async ({ page, browser, baseURL }) => {
    const other = await newSession(browser, baseURL);
    await signIn(other, upn, { password });
    await signIn(page, upn, { password });
    await go(page, "/account");
    await waitForHydratedForm(page);
    const next = strongPassword();
    await page.getByLabel("Current password").fill(password);
    await page.getByLabel("New password", { exact: true }).fill(next);
    await page.getByLabel("Confirm new password").fill(next);
    await page.getByRole("button", { name: "Change password" }).click();
    await expect(page.getByText(/Password changed\. Signed out [1-9]\d* other sessions?\./)).toBeVisible();
    password = next;
    await shotThemes(page, "f05-account");
    await go(other, "/endpoints");
    await expect(other).toHaveURL(/\/login/);
    await other.context().close();
  });

  test("2.3 five wrong passwords lock the account; the platform admin unlocks it", async ({ page }) => {
    for (let i = 0; i < 5; i++) {
      await submitLogin(page, upn, "Wrong-password-0000");
      await expect(page.getByText("Invalid username or password.")).toBeVisible();
    }
    // Locked: even the right password is refused (same generic message).
    expect(await submitLogin(page, upn, password)).not.toBe("done");
    await expect(page.getByText("Invalid username or password.")).toBeVisible();
    await signIn(page, PLATFORM_ADMIN);
    await go(page, "/admin/users");
    const row = page.getByRole("row").filter({ hasText: upn });
    await expect(row.getByText("locked", { exact: true })).toBeVisible();
    await hydrated(page, "main button");
    await row.getByRole("button", { name: "Unlock" }).click();
    await expect(row.getByText("locked", { exact: true })).toHaveCount(0);
    await signIn(page, upn, { password });
  });

  test("2.4b a bank admin sees the user list read-only and cannot create accounts", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/admin/users");
    await expect(page.getByText("Accounts for your bank are created and managed by PatchGate")).toBeVisible();
    await expect(page.getByRole("button", { name: "New user" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Unlock" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Reset password" })).toHaveCount(0);
    const r = await pageFetch(page, "/api/admin/users", { method: "POST", body: { upn: `x-${RUN}@bank-a.lab`, name: "X", role: "AUDITOR" } });
    expect(r.status).toBe(403);
    await shotThemes(page, "f06-bank-admin-users-read-only");
  });

  test("cleanup: the platform admin deactivates the e2e account", async ({ page }) => {
    await signIn(page, PLATFORM_ADMIN);
    await go(page, "/admin/users");
    await hydrated(page, "main button");
    const row = page.getByRole("row").filter({ hasText: upn });
    acceptDialog(page);
    await row.getByRole("button", { name: "Deactivate" }).click();
    await expect(row.getByText("deactivated")).toBeVisible();
  });
});

// =============================================================================================================
// 3/5/12 Endpoints: sync, scan, live refresh, WU lock column, agent times, ring assignment
// =============================================================================================================
test.describe("3/5/12 endpoints", () => {
  test.describe.configure({ mode: "serial" });

  test.beforeAll(() => {
    labScript("fixtures/sim-tactical-agent.sh", "create"); // lab only: no real PC
  });

  test("3.3 Sync agents now: the (simulated) PC appears without a reload", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/endpoints");
    await hydrated(page, "main button");
    await page.getByRole("button", { name: "Sync agents now" }).click();
    await expect(page.getByRole("status").filter({ hasText: /Syncing PCs from Tactical|sync with Tactical is already in progress/ })).toBeVisible();
    await expect(page.getByRole("row").filter({ hasText: SIM_PC })).toBeVisible({ timeout: 150_000 });
    await expect(page.getByTestId("live-indicator")).toHaveText(/Live · (updated|updating)/);
  });

  test("3.4 OS / agent, seen / booted times (never negative) and the Windows Update column render", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/endpoints");
    for (const h of ["Hostname", "OS / agent", "Ring", "Missing", "Critical", "Windows Update", "Seen / scanned"]) {
      await expect(page.getByRole("columnheader", { name: h })).toBeVisible();
    }
    const row = page.getByRole("row").filter({ hasText: SIM_PC });
    await expect(row).toContainText("2.10.0");
    await expect(row).toContainText(/Windows 11/);
    await expect(row).toContainText(/seen (just now|\d+ min ago|\d+ h ago)/);
    await expect(row).toContainText(/booted (\d+ h ago|\d+ min ago)/);
    await expect(row).not.toContainText(/-\d+ (min|h|days?) ago|in \d+/);
    // No real PC → no offline WU scan result: the lock state is honestly "unknown" (VMware test: "locked").
    await expect(row.getByText(/^(locked|NOT locked|unknown)$/)).toBeVisible();
  });

  test("3.5 assign the PC to Ring0-Test", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/endpoints");
    const ring = page.getByRole("row").filter({ hasText: SIM_PC }).getByLabel("Ring");
    await hydrated(page, "select[aria-label=Ring]");
    if ((await ring.locator("option:checked").textContent())?.trim() !== "Ring0-Test") {
      const saved = page.waitForResponse((r) => /\/api\/endpoints\/[^/]+$/.test(r.url()) && r.request().method() === "PATCH");
      await ring.selectOption({ label: "Ring0-Test" });
      expect((await saved).status()).toBe(200);
    }
    await page.reload();
    await expect(page.getByRole("row").filter({ hasText: SIM_PC }).getByLabel("Ring").locator("option:checked")).toHaveText("Ring0-Test");
    await shotThemes(page, "f07-endpoints");
  });

  test("5.1 Request scan of all PCs: confirm, message, jobs SYNC_AGENTS → SCAN → WU_SCAN", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/endpoints");
    await hydrated(page, "main button");
    const dlg = acceptDialog(page);
    const clickedAt = new Date(Date.now() - 2000);
    const posted = page.waitForResponse((r) => r.url().endsWith("/api/endpoints/scan") && r.request().method() === "POST");
    await page.getByRole("button", { name: "Request scan of all PCs" }).click();
    expect((await posted).status()).toBe(200);
    expect(dlg.text()).toContain("rescan for updates");
    await expect(page.getByRole("status").filter({ hasText: "Syncing PCs from Tactical, then scanning" })).toBeVisible();
    // While jobs are in flight the page refreshes every 5 s by itself.
    await expect(page.getByTestId("live-indicator")).toHaveText(/Live · /);
    await shot(page, "f08-endpoints-scan-requested");
    // Order of the signed connector jobs: the PC list first, then the scans (WU_SCAN after the sync result).
    const order = await until(
      "SYNC_AGENTS → SCAN → WU_SCAN",
      async () => {
        const types = labSql(
          `select type from "ConnectorJob" where "createdAt" >= '${clickedAt.toISOString()}' and type in ('SYNC_AGENTS','SCAN','WU_SCAN') order by "createdAt", type`,
        );
        return types.includes("WU_SCAN") && types.includes("SCAN") ? types : undefined;
      },
      180_000,
    );
    expect(order[0]).toBe("SYNC_AGENTS");
    expect(order.indexOf("WU_SCAN")).toBeGreaterThan(order.indexOf("SYNC_AGENTS"));
  });

  test("12.1 live refresh: the indicator ages and refreshes by itself", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/endpoints");
    const live = page.getByTestId("live-indicator");
    await expect(live).toHaveText(/Live · updated \d+s ago/, { timeout: 30_000 });
    await expect(live).toHaveText(/Live · (updated just now|updating…)/, { timeout: 45_000 });
  });

  test("5.3 a Windows update found only by Tactical is not selectable: \"Needs PatchGate scan\"", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/patches?kind=WINDOWS&needed=0");
    const row = page.getByRole("row").filter({ hasText: "KB5034441" }).first();
    await expect(row).toBeVisible({ timeout: 120_000 });
    await expect(row.getByText(/Needs PatchGate scan/)).toBeVisible();
    await expect(row.locator("input[type=checkbox]")).toBeDisabled();
    await shotThemes(page, "f09-patches-windows-needs-scan");
  });
});

// =============================================================================================================
// 6 Change request → maker ≠ checker → approve → deploy → progress → audit
// =============================================================================================================
test.describe("6 change request", () => {
  test.describe.configure({ mode: "serial" });
  let crPath = "";

  test("6.1 bank admin (maker) creates + submits a Ring0-Test request with a catalogue app", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/patches?kind=THIRD_PARTY&needed=0");
    await hydrated(page, "tbody input[type=checkbox]:not([disabled])");
    const box = page.locator("tbody input[type=checkbox]:not([disabled])").first();
    const title = ((await box.getAttribute("aria-label")) ?? "").replace(/^Select /, "");
    await box.check();
    await page.getByLabel("Title").fill(`E2E ${title} ${RUN}`);
    await page.getByLabel("Target ring").selectOption({ label: "Ring0-Test" });
    await page.getByRole("button", { name: "Create draft" }).click();
    await page.waitForURL(/\/change-requests\/[^/]+$/);
    crPath = new URL(page.url()).pathname;
    await hydrated(page, "main button");
    await page.getByRole("button", { name: /^Submit/ }).click();
    await expect(page.getByText(/^Pending approval$/i)).toBeVisible();
  });

  test("6.2 the maker cannot approve their own request (UI and API)", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, crPath);
    await expect(page.getByRole("button", { name: /^Approve/ })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Cancel" })).toBeVisible(); // the maker may withdraw it, nothing else
    const r = await pageFetch(page, `/api${crPath}/approve`, { method: "POST", body: {} });
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(r.text).toMatch(/Maker-checker violation/);
    await shotThemes(page, "f10-maker-pending");
  });

  test("6.3/6.4 a second admin approves; deploy shows the progress bar with stages and notes", async ({ page }) => {
    await signIn(page, BANK_A_APPROVER);
    await go(page, crPath);
    await hydrated(page, "main button");
    acceptDialog(page);
    await page.getByRole("button", { name: /^Approve/ }).click();
    await expect(page.getByText(/^Approved$/i)).toBeVisible();
    const dlg = acceptDialog(page);
    await page.getByRole("button", { name: "Queue deployment" }).click();
    const progress = page.getByTestId("deployment-progress");
    await expect(progress).toBeVisible({ timeout: 120_000 });
    expect(dlg.text()).toMatch(/Queue deployment to the approved endpoints/);
    await expect(page.getByRole("progressbar", { name: "Deployment progress" })).toBeVisible();
    await expect(progress).toContainText(/\d+% finished · \d+ of \d+ endpoints?/);
    const stage = page.getByTestId("deployment-stage").first();
    await expect(stage).toHaveText(/Queued|Files downloading \/ verifying|Caching at site|Installing|Reboot pending|Succeeded|Failed/);
    await shotThemes(page, "f11-deployment-progress");
  });

  test("6.7 audit: create / submit / approve / deploy on the Bank A chain, chain valid, anchor check matches", async ({ page }) => {
    await signIn(page, BANK_A_AUDITOR);
    await go(page, "/audit");
    await expect(page.getByText("Valid", { exact: true })).toBeVisible();
    for (const a of [/^Change Request.Create$/i, /^Change Request.Submit$/i, /^Change Request.Approve$/i, /^Change Request.Deploy$/i]) {
      await expect(page.getByRole("cell", { name: a }).first()).toBeVisible();
    }
    // The bank's copy: the newest ANCHOR record Bank A's connector relayed to the bank SIEM (lab/siem/received.log).
    const siem = readFileSync(join(LAB_DIR, "siem", "received.log"), "utf8").split("\n");
    const anchor = siem.reverse().find((l) => / bank-a-connector-hq patchgate - ANCHOR /.test(l)) ?? "";
    const seq = / seq="(\d+)"/.exec(anchor)?.[1];
    const hash = / hash="([0-9a-f]{64})"/.exec(anchor)?.[1];
    expect(seq && hash, "an ANCHOR record from bank-a-connector-hq in the lab SIEM").toBeTruthy();
    await waitForHydratedForm(page);
    await page.getByLabel("seq").fill(seq!);
    await page.getByLabel("hash").fill(hash!);
    await page.getByRole("button", { name: "Check against PatchGate DB" }).click();
    await expect(page.getByText("Matches — no tampering up to this point.")).toBeVisible();
    // Export: the bank's chain of this month as CSV (re-checkable: payload, prev_hash, hash), audited.
    const href = await page.getByRole("link", { name: "This month" }).getAttribute("href");
    const csv = await pageFetch(page, href!);
    expect(csv.status).toBe(200);
    expect(csv.headers["content-disposition"]).toMatch(/attachment; filename="patchgate-bank-a-audit-log-\d{4}-\d{2}-01\.csv"/);
    expect(csv.text.split("\r\n")[0]).toBe("seq,time_utc,actor,action,entity,entity_id,payload_json,prev_hash,hash");
    expect(csv.text).toContain("change_request.approve");
    await shotThemes(page, "f12-audit");
  });
});

// =============================================================================================================
// 7 Tactical sealed: login blocked, break-glass alerts, real-time approval guard, acknowledge, auto-update off
// =============================================================================================================

/** Tactical's own dashboard credential check, retried on transport errors (the lab ingress is a plain socat). */
async function tacticalCheckCreds(): Promise<{ status: number; body: string }> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await tacticalCheckCredsOnce();
    } catch (err) {
      if (attempt >= 4) throw err;
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}

/** POST /v2/checkcreds/ with the lab admin from lab/tactical/.env (never logged). */
function tacticalCheckCredsOnce(): Promise<{ status: number; body: string }> {
  const env = readFileSync(join(LAB_DIR, "tactical", ".env"), "utf8");
  const val = (k: string): string => new RegExp(`^${k}=(.*)$`, "m").exec(env)?.[1]?.trim() ?? "";
  const body = JSON.stringify({ username: val("TRMM_USER"), password: val("TRMM_PASS") });
  const ca = readFileSync(join(LAB_DIR, "certs", "out", "ca.crt"));
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      { host: val("API_HOST"), port: 443, path: "/v2/checkcreds/", method: "POST", ca, headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } },
      (res) => {
        let text = "";
        res.on("data", (c: Buffer) => (text += c.toString()));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text.slice(0, 200) }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** bank-a-connector log lines (JSON) since `t`. */
const connectorLogSince = (t: Date): string[] =>
  execFileSync("docker", ["logs", "--since", t.toISOString(), "bank-a-connector"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).split("\n");

const simUpdates = (): { kb: string; action: string }[] =>
  (JSON.parse(labScript("fixtures/sim-tactical-agent.sh", "status")) as { updates: { kb: string; action: string }[] }).updates;

test.describe("7 Tactical sealed", () => {
  test.describe.configure({ mode: "serial" });

  test.afterAll(() => {
    labScript("tactical/break-glass.sh", "off"); // never leave the lab unsealed
  });

  test("7.1/7.5 sealed: dashboard login refused, agent auto-update off, no other API keys", async () => {
    const seal = JSON.parse(labScript("tactical/break-glass.sh", "check").replace(/^SEAL_CHECK=/, "")) as Record<string, unknown>;
    expect(seal).toMatchObject({ openDashboardUsers: "", otherValidApiKeys: 0, nonManualPatchPolicies: 0, agentAutoUpdate: "off", svcBlocked: "yes" });
    const r = await tacticalCheckCreds();
    expect(r.status).toBe(400);
    expect(r.body).toContain("Bad credentials");
  });

  test("7.2/7.3 break-glass on → alert; an approval made in Tactical is reset by the guard and reported", async ({ page }) => {
    test.setTimeout(420_000);
    labScript("tactical/break-glass.sh", "on");
    expect((await tacticalCheckCreds()).status).toBe(200); // the break-glass account may sign in now
    const approvedAt = new Date();
    labScript("fixtures/sim-tactical-agent.sh", "approve", "KB890830"); // what a person in the Tactical dashboard does
    // The connector guard (every ~30 s) resets what PatchGate never approved (often before we can even look).
    await until(
      "guard reset of KB890830",
      async () =>
        simUpdates().find((u) => u.kb === "KB890830")?.action === "nothing" &&
        connectorLogSince(approvedAt).some((l) => l.includes("approval set outside PatchGate reset") && l.includes('"kb":"KB890830"')),
      150_000,
    );

    await signIn(page, BANK_A_ADMIN);
    await go(page, "/connectors");
    const card = page.locator("main"); // the "Tactical activity" card lives in the page body
    await until(
      "PatchGate shows the reset + break-glass",
      async () => {
        await page.reload();
        const t = (await card.textContent()) ?? "";
        return /KB890830/.test(t) && /reset automatically/.test(t) && /BREAK-GLASS ON/.test(t);
      },
      180_000,
      10_000,
    );
    await expect(page.getByText(/action\(s\) in a site's Tactical outside PatchGate/)).toBeVisible();
    await expect(card.getByText(/\d+ unacknowledged/i)).toBeVisible();
    await expect(card.getByText("approval guard (real time)").first()).toBeVisible();
    await shotThemes(page, "f13-tactical-activity-open");
  });

  test("7.4 break-glass off → alert; an admin acknowledges (audited); a notification was queued", async ({ page }) => {
    test.setTimeout(300_000);
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/connectors");
    const card = page.locator("main");
    const offRows = async (): Promise<number> => ((await card.textContent()) ?? "").split("BREAK-GLASS OFF").length - 1;
    const before = await offRows();
    labScript("tactical/break-glass.sh", "off");
    expect((await tacticalCheckCreds()).status).toBe(400);
    await until("a new BREAK-GLASS OFF row", async () => {
      await page.reload();
      return (await offRows()) > before;
    }, 180_000, 10_000);
    await hydrated(page, "main button");
    const dlg = acceptDialog(page, `e2e ${RUN}: lab break-glass test`);
    const acked = page.waitForResponse((r) => r.url().endsWith("/api/tactical-activity/ack") && r.request().method() === "POST");
    await card.getByRole("button", { name: /^Acknowledge all/ }).click();
    expect((await acked).status()).toBe(200);
    expect(dlg.text()).toContain("Acknowledge all");
    await expect(card.getByText("nothing open")).toBeVisible();
    await expect(card.getByText(/^acknowledged /).first()).toBeVisible();
    await shotThemes(page, "f14-tactical-activity-acknowledged");

    await go(page, "/audit");
    await expect(page.getByRole("cell", { name: /^Tactical.Out Of Band Action$/i }).first()).toBeVisible();

    await signIn(page, PLATFORM_ADMIN);
    await go(page, "/settings/notifications");
    await expect(page.getByRole("heading", { name: "Outbox" })).toBeVisible();
    await expect(page.getByText(/TACTICAL_OUT_OF_BAND|Tactical outside PatchGate/).first()).toBeVisible();
    await shotThemes(page, "f15-notifications-outbox");
  });
});

// =============================================================================================================
// 8 Approval switch (admin only)
// =============================================================================================================
async function setApprovalRequired(page: Page, on: boolean): Promise<void> {
  await go(page, "/settings/approvals");
  await hydrated(page, "[data-testid=approval-required]");
  const box = page.getByTestId("approval-required");
  if ((await box.isChecked()) === on) return;
  await box.setChecked(on);
  if (!on) await expect(page.getByText("Approval is OFF for this bank — requests deploy without a second person.").first()).toBeVisible();
  acceptDialog(page);
  await page.getByRole("button", { name: "Save policy" }).click();
  await expect(page.getByText("Policy saved and recorded in the bank's audit log.")).toBeVisible();
}

test.describe("8 approval switch", () => {
  test.describe.configure({ mode: "serial" });

  test.afterAll(async ({ browser, baseURL }) => {
    const page = await newSession(browser, baseURL); // never leave Bank A with approval off
    await signIn(page, BANK_A_ADMIN);
    await setApprovalRequired(page, true);
    await page.context().close();
  });

  test("8.1 auditors cannot switch approval (no button, API 403)", async ({ page }) => {
    await signIn(page, BANK_A_AUDITOR);
    await go(page, "/settings/approvals");
    await expect(page.getByRole("button", { name: "Save policy" })).toHaveCount(0);
    await expect(page.getByTestId("approval-required")).toBeDisabled();
    const r = await pageFetch(page, "/api/settings/approvals", { method: "PATCH", body: { requireBankApproval: false } });
    expect(r.status).toBe(403);
    await signIn(page, PLATFORM_AUDITOR);
    await go(page, "/settings/security");
    await expect(page.getByLabel("Password max age (days)")).toBeDisabled();
    await expect(page.getByRole("button", { name: "Save policy" })).toHaveCount(0);
    expect((await pageFetch(page, "/api/settings/security", { method: "PATCH", body: { maxSessionsPerUser: 9 } })).status).toBe(403);
  });

  test("8.2/8.3 admin switches approval OFF: amber note, a submitted request is auto-approved", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await setApprovalRequired(page, false);
    await shotThemes(page, "f16-approval-off");
    await go(page, "/");
    await expect(page.getByTestId("approval-off-note")).toBeVisible();
    await go(page, "/change-requests");
    await expect(page.getByTestId("approval-off-note")).toBeVisible();

    await go(page, "/patches?kind=THIRD_PARTY&needed=0");
    await hydrated(page, "tbody input[type=checkbox]:not([disabled])");
    await page.locator("tbody input[type=checkbox]:not([disabled])").first().check();
    await page.getByLabel("Title").fill(`E2E approval-off ${RUN}`);
    await page.getByLabel("Target ring").selectOption({ label: "Ring0-Test" });
    await page.getByRole("button", { name: "Create draft" }).click();
    await page.waitForURL(/\/change-requests\/[^/]+$/);
    await hydrated(page, "main button");
    const dlg = acceptDialog(page);
    await page.getByRole("button", { name: "Submit (approval is off)" }).click();
    await expect(page.getByText(/^Approved$/i)).toBeVisible();
    expect(dlg.text()).toContain("Approval is OFF for this bank");
    await expect(page.getByText("Auto-approved (approval off)")).toBeVisible();
    await expect(page.getByRole("button", { name: "Queue deployment" })).toBeVisible();
    await shotThemes(page, "f17-auto-approved");
    // Not deployed: cancel it (9.3 covers cancel).
    acceptDialog(page);
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByText(/^Cancelled$/i)).toBeVisible();
  });

  test("8.4 switch back ON: the note is gone and submit needs a checker again", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await setApprovalRequired(page, true);
    await go(page, "/change-requests");
    await expect(page.getByTestId("approval-off-note")).toHaveCount(0);
  });
});

// =============================================================================================================
// 9 Rollout safety: rings, maintenance windows, emergency (two admins), cancel
// =============================================================================================================
test.describe("9 rollout safety", () => {
  const ringName = `E2E-Ring-${RUN}`;
  const windowName = `E2E window ${RUN}`;

  test("9.1 rings: create and delete a ring", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/settings/rings");
    for (const r of ["Ring0-Test", "Ring1-Pilot", "Ring2-Prod"]) await expect(page.getByText(r, { exact: true }).first()).toBeVisible();
    await hydrated(page, "main button");
    await page.getByRole("button", { name: "New ring" }).click();
    await page.getByLabel("Name", { exact: true }).fill(ringName);
    await page.getByRole("button", { name: "Create ring" }).click();
    await expect(page.getByText(ringName, { exact: true }).first()).toBeVisible();
    await shotThemes(page, "f18-rings");
    acceptDialog(page);
    await page.getByRole("button", { name: `Delete ${ringName}` }).click();
    await expect(page.getByText(ringName, { exact: true })).toHaveCount(0);
  });

  test("9.1 maintenance windows: preview the next occurrences, create and delete", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/settings/windows");
    await hydrated(page, "main button");
    await page.getByRole("button", { name: "New window" }).click();
    await page.getByLabel("Name", { exact: true }).fill(windowName);
    await page.getByLabel("Ring").selectOption({ label: "Ring1-Pilot" });
    await expect(page.getByText(/Next 5 occurrences/)).toBeVisible();
    await shotThemes(page, "f19-window-new");
    await page.getByRole("button", { name: "Create window" }).click();
    await expect(page.getByText(windowName).first()).toBeVisible();
    acceptDialog(page);
    await page.getByRole("button", { name: `Delete ${windowName}` }).click();
    await expect(page.getByText(windowName)).toHaveCount(0);
  });

  test("9.2/9.3 emergency request needs two different admins; a queued deployment can be cancelled", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/patches?kind=THIRD_PARTY&needed=0");
    await hydrated(page, "tbody input[type=checkbox]:not([disabled])");
    await page.locator("tbody input[type=checkbox]:not([disabled])").first().check();
    await page.getByLabel("Title").fill(`E2E emergency ${RUN}`);
    await page.getByLabel("Target ring").selectOption({ label: "Ring0-Test" });
    await page.getByTestId("cr-form-advanced").click();
    await page.getByLabel("Emergency change").check();
    await page.getByLabel("Emergency reason").fill("E2E lab: actively exploited vulnerability drill");
    await page.getByRole("button", { name: "Create draft" }).click();
    await page.waitForURL(/\/change-requests\/[^/]+$/);
    const path = new URL(page.url()).pathname;
    await hydrated(page, "main button");
    await page.getByRole("button", { name: /^Submit/ }).click();
    await expect(page.getByText(/Needs 2 different approvers/)).toBeVisible();

    await signIn(page, BANK_A_APPROVER);
    await go(page, path);
    await hydrated(page, "main button");
    acceptDialog(page);
    await page.getByRole("button", { name: /^Approve \(1 of 2\)/ }).click();
    await expect(page.getByText(/1 so far/)).toBeVisible();
    await expect(page.getByText(/^Pending approval$/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /^Approve/ })).toHaveCount(0); // same person cannot approve twice
    await shotThemes(page, "f20-emergency-one-of-two");

    await signIn(page, PLATFORM_ADMIN); // the second approver may be PatchGate staff (one approver is from the bank)
    await actFor(page, "Bank A");
    await go(page, path);
    await hydrated(page, "main button");
    acceptDialog(page);
    await page.getByRole("button", { name: /^Approve/ }).first().click();
    await expect(page.getByText(/^Approved$/i)).toBeVisible();

    // Approved but not deployed: the maker's organisation can still withdraw it.
    acceptDialog(page);
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByText(/^Cancelled$/i)).toBeVisible();
    await shotThemes(page, "f21-emergency-cancelled");
  });

  test("9.1/9.3 outside its maintenance window a deployment waits (note says why); Stop rollout skips it", async ({ page }) => {
    const closed = "E2E closed window (1 Jan 03:00)";
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/settings/windows");
    if ((await page.getByText(closed).count()) === 0) {
      await hydrated(page, "main button");
      await page.getByRole("button", { name: "New window" }).click();
      await page.getByLabel("Name", { exact: true }).fill(closed);
      await page.getByLabel("Ring").selectOption({ label: "Ring0-Test" });
      await page.getByLabel(/^Start \(cron/).fill("0 3 1 1 *");
      await page.getByRole("button", { name: "Create window" }).click();
      await expect(page.getByText(closed).first()).toBeVisible();
    }
    await go(page, "/patches?kind=THIRD_PARTY&needed=0");
    await hydrated(page, "tbody input[type=checkbox]:not([disabled])");
    await page.locator("tbody input[type=checkbox]:not([disabled])").first().check();
    await page.getByLabel("Title").fill(`E2E window wait ${RUN}`);
    await page.getByLabel("Target ring").selectOption({ label: "Ring0-Test" });
    await page.locator("label").filter({ hasText: /^Maintenance window/ }).locator("select").selectOption({ label: closed });
    await page.getByRole("button", { name: "Create draft" }).click();
    await page.waitForURL(/\/change-requests\/[^/]+$/);
    const path = new URL(page.url()).pathname;
    await hydrated(page, "main button");
    await page.getByRole("button", { name: /^Submit/ }).click();
    await expect(page.getByText(/^Pending approval$/i)).toBeVisible();

    await signIn(page, BANK_A_APPROVER);
    await go(page, path);
    await hydrated(page, "main button");
    acceptDialog(page);
    await page.getByRole("button", { name: /^Approve/ }).click();
    await expect(page.getByText(/^Approved$/i)).toBeVisible();
    acceptDialog(page);
    await page.getByRole("button", { name: "Queue deployment" }).click();
    const row = page.getByRole("row").filter({ hasText: SIM_PC });
    await expect(row).toContainText(/window/i, { timeout: 150_000 }); // e.g. "waiting for the maintenance window …"
    await shotThemes(page, "f21b-deployment-waits-for-window");
    const dlg = acceptDialog(page);
    await page.getByRole("button", { name: "Stop rollout" }).click();
    await expect(row).toContainText(/rollout stopped by approver@bank-a\.lab; not started/);
    expect(dlg.text()).toContain("Stop this rollout?");
    await expect(page.getByRole("button", { name: "Stop rollout" })).toHaveCount(0);
    // Nothing in flight: the worker closes the request on its next tick (≤ ~1 min in the lab).
    await expect(page.getByRole("listitem").filter({ hasText: /^Deployment failed/ })).toBeVisible({ timeout: 150_000 });
    await shotThemes(page, "f21c-rollout-stopped");
  });
});

// =============================================================================================================
// 11 Reports, audit, operations · settings pages · bank switcher · error pages
// =============================================================================================================
test.describe("11 reports, operations and other pages", () => {
  test("11.1 compliance report: summary CSV and printable report with its SHA-256", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/reports");
    await expect(page.getByRole("heading", { name: "Compliance reports" })).toBeVisible();
    const csvHref = await page.getByRole("link", { name: "Summary CSV" }).getAttribute("href");
    const csv = await pageFetch(page, csvHref!);
    expect(csv.status).toBe(200);
    expect(csv.headers["content-type"]).toMatch(/text\/csv/);
    expect(csv.text.split("\n").length).toBeGreaterThan(1);
    const printHref = await page.getByRole("link", { name: "Printable report" }).getAttribute("href");
    const html = await pageFetch(page, printHref!);
    expect(html.status).toBe(200);
    expect(html.headers["x-report-sha256"]).toMatch(/^[0-9a-f]{64}$/);
    expect(html.text).toContain("Content SHA-256");
    await shotThemes(page, "f22-reports");
  });

  test("10.1 the Tactical agent version changes only through a change request (agent builds listed as patches)", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/patches?kind=AGENT_UPGRADE&needed=0");
    await expect(page.locator("tbody tr").filter({ hasText: /agent/i }).first()).toBeVisible();
    await shotThemes(page, "f22b-patches-agent-upgrade");
  });

  test("11.3 operations (platform staff only)", async ({ page }) => {
    await signIn(page, PLATFORM_ADMIN);
    await go(page, "/operations");
    await expect(page.getByRole("heading", { name: "Operations" })).toBeVisible();
    for (const t of ["Worker", "Audit chains", "Repository", "Held packages"]) await expect(page.getByText(t, { exact: true }).first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "Worker steps" })).toBeVisible();
    await shotThemes(page, "f23-operations");
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/operations");
    await expect(page.getByText("The operations view spans every bank and is for PatchGate platform staff only.")).toBeVisible();
  });

  test("advanced settings: every tab renders for an admin; security policy is platform-only", async ({ page }) => {
    await signIn(page, PLATFORM_ADMIN);
    await actFor(page, "Bank A");
    for (const [path, name] of [
      ["/settings/rings", "f24-settings-rings"],
      ["/settings/windows", "f25-settings-windows"],
      ["/settings/approvals", "f26-settings-approvals"],
      ["/settings/notifications", "f27-settings-notifications"],
      ["/settings/security", "f28-settings-security"],
    ] as const) {
      await go(page, path);
      await expect(page.getByTestId("advanced-settings-hint")).toBeVisible();
      await shotThemes(page, name);
    }
    await expect(page.getByLabel("Password max age (days)")).toBeVisible();
    await signIn(page, BANK_A_ADMIN);
    await go(page, "/settings/rings");
    await expect(page.getByRole("link", { name: "Account security" })).toHaveCount(0);
  });

  test("main pages render in light and dark (bank admin)", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    for (const [path, name] of [
      ["/", "f30-dashboard"],
      ["/patches", "f31-patches"],
      ["/change-requests", "f32-change-requests"],
      ["/endpoints", "f33-endpoints"],
      ["/discovery", "f34-discovery"],
      ["/apps", "f35-apps"],
      ["/connectors", "f36-connectors"],
      ["/audit", "f37-audit"],
    ] as const) {
      await go(page, path);
      await page.waitForLoadState("networkidle");
      await expect(page.locator("main")).toBeVisible();
      await shotThemes(page, name);
    }
  });

  test("bank switcher (platform staff) and /select-bank", async ({ page }) => {
    await signIn(page, PLATFORM_AUDITOR);
    await go(page, "/select-bank");
    await expect(page.getByRole("heading", { name: "Select a bank" })).toBeVisible();
    await expect(page.getByText("Every switch is recorded in the platform audit chain.")).toBeVisible();
    await actFor(page, "Bank A");
    await go(page, "/endpoints");
    await expect(page.getByRole("row").filter({ hasText: SIM_PC })).toBeVisible();
    await shotThemes(page, "f38-select-bank");
    await signIn(page, BANK_A_ADMIN);
    const r = await pageFetch(page, "/api/tenant/select", { method: "POST", body: { tenantId: null } });
    expect(r.status).toBe(403);
  });

  test("error pages: unknown page and unknown change request", async ({ page }) => {
    await signIn(page, BANK_A_ADMIN);
    const res = await page.goto("/this-page-does-not-exist");
    expect(res?.status()).toBe(404);
    await expect(page.getByText("This page or record does not exist")).toBeVisible();
    await shot(page, "f39-not-found");
    // A streamed page answers 200 before notFound() runs; what matters is that the user sees the not-found page.
    await page.goto("/change-requests/does-not-exist");
    await expect(page.getByText("This page or record does not exist")).toBeVisible();
    await expect(page.getByRole("link", { name: "Back to the dashboard" })).toBeVisible();
    await shot(page, "f40-cr-not-found");
  });
});
