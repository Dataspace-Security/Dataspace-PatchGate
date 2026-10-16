import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  actFor,
  bankSwitcher,
  BANK_A_APPROVER,
  expect,
  go,
  PLATFORM_ADMIN as ADMIN,
  PLATFORM_AUDITOR as AUDITOR,
  shot,
  shotThemes,
  signIn as signInAs,
  test,
  waitForHydratedForm,
} from "./helpers";
import type { Page } from "@playwright/test";

/**
 * Hosted-lab journey in a real browser against the running lab (no fakes):
 *   our staff sign in (password only) → onboard a bank + one-time connector code in the UI →
 *   Bank A's real connector is online → switch bank → endpoints / discovery → a bank user sees only
 *   their own bank. Screenshots: e2e-lab/screenshots/. Every test also fails on browser console errors and 5xx.
 */
test.describe.configure({ mode: "serial" });

const BANK_B = { name: "Bank B", slug: "bank-b" };
const ENROLL_CODE_RE = /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){4}$/;

/** The site connector's row in the connectors table (Tactical-activity rows name the site too). */
const connectorRow = (page: Page, site: string) => page.getByRole("row").filter({ hasText: site }).filter({ hasText: /version \d/ });

const signIn = (page: Page, upn: string, shotPrefix?: string): Promise<void> =>
  signInAs(page, upn, { shotName: shotPrefix ? `${shotPrefix}-password` : undefined });

test("platform admin signs in with username + password only (no code step)", async ({ page }) => {
  await go(page, "/login");
  await waitForHydratedForm(page);
  await expect(page.getByLabel("Username")).toBeVisible();
  await expect(page.getByLabel("Verification code")).toHaveCount(0);
  await shot(page, "01-login");
  await signIn(page, ADMIN, "02-admin");
  await expect(bankSwitcher(page)).toBeVisible(); // bank switcher = PatchGate staff
  await shot(page, "03-admin-home");
});

test("a wrong password is refused with the generic message", async ({ page }) => {
  await go(page, "/login");
  await waitForHydratedForm(page);
  await page.getByLabel("Username").fill(ADMIN);
  await page.getByLabel("Password").fill("definitely-not-the-password");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByText("Invalid username or password.")).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});

test("platform auditor: reads every bank, has no write buttons, and the API refuses changes", async ({ page }) => {
  await signIn(page, AUDITOR, "04-auditor");
  await expect(bankSwitcher(page)).toBeVisible(); // platform staff: may switch the bank it reads
  await go(page, "/admin/banks");
  await expect(page.getByText("Read-only view (auditor).")).toBeVisible();
  await expect(page.getByRole("cell", { name: "bank-a", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "New bank" })).toHaveCount(0);
  await go(page, "/connectors");
  await expect(page.getByRole("button", { name: "Enrol a site connector" })).toHaveCount(0);
  const r = await page.evaluate(async () => {
    const res = await fetch("/api/admin/tenants", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ slug: "x-auditor", name: "Nope" }) });
    return res.status;
  });
  expect(r).toBe(403);
  await shot(page, "04-auditor-banks-read-only");
});

test("admin onboards a bank and creates a one-time connector enrolment code in the UI", async ({ page }) => {
  await signIn(page, ADMIN);
  await go(page, "/admin/banks");
  if (!(await page.getByRole("cell", { name: BANK_B.slug, exact: true }).isVisible())) {
    await page.getByRole("button", { name: "New bank" }).click();
    await page.getByLabel("Bank name").fill(BANK_B.name);
    await page.getByLabel("Short code").fill(BANK_B.slug);
    await page.getByRole("button", { name: "Create bank" }).click();
  }
  await expect(page.getByText(BANK_B.slug, { exact: true }).first()).toBeVisible();
  await shot(page, "05-banks");

  await go(page, "/connectors");
  await page.getByRole("button", { name: "Enrol a site connector" }).click();
  await page.locator("form").filter({ hasText: "Site name" }).locator("select").selectOption({ label: BANK_B.name });
  await page.getByLabel("Site name").fill("Bank B Branch 01");
  await page.getByRole("button", { name: "Create code" }).click();
  const code = page.locator("code").filter({ hasText: ENROLL_CODE_RE }).first();
  await expect(code).toBeVisible();
  expect((await code.textContent())?.trim()).toMatch(ENROLL_CODE_RE);
  // The manual connector init command sits in the collapsed "Offline / USB alternative" block (rc3 UI).
  await page.getByText("Offline / USB alternative and manual connector init").click();
  // The init command names OUR public URL (PUBLIC_BASE_URL), never the code in the process list.
  await expect(page.getByText(/PATCHGATE_ENROLL_CODE=/).first()).toBeVisible();
  await expect(page.getByText(/--server https:\/\/patchgate\.patchgate-lab\.internal:3443/).first()).toBeVisible();
  await page.locator("code").filter({ hasText: ENROLL_CODE_RE }).first().evaluate((el) => (el.textContent = "XXXX-XXXX-XXXX-XXXX-XXXX"));
  await page.getByText(/PATCHGATE_ENROLL_CODE=/).first().evaluate((el) => (el.textContent = (el.textContent ?? "").replace(/PATCHGATE_ENROLL_CODE=\S+/, "PATCHGATE_ENROLL_CODE=XXXX-…")));
  await shot(page, "06-enrolment-code-redacted");
});

test("Bank A's real site connector is online", async ({ page }) => {
  await signIn(page, ADMIN);
  await go(page, "/connectors");
  const row = connectorRow(page, "Bank A HQ");
  await expect(row).toBeVisible();
  await expect(row.getByText("online", { exact: true })).toBeVisible();
  await expect(row.getByText(/pg-cache\.patchgate-lab\.internal:8443/)).toBeVisible();
  await shot(page, "07-connectors-bank-a-online");
});

test("staff switch to Bank A and view endpoints + discovery", async ({ page }) => {
  await signIn(page, ADMIN);
  const selected = page.waitForResponse((r) => r.url().endsWith("/api/tenant/select") && r.request().method() === "POST");
  await bankSwitcher(page).selectOption({ label: "Bank A" });
  expect((await selected).status()).toBe(200); // the bank cookie is set server-side before we navigate
  await go(page, "/endpoints");
  await expect(page.getByRole("heading", { name: "Endpoints" })).toBeVisible();
  await shot(page, "08-bank-a-endpoints");
  await go(page, "/discovery");
  await expect(page.getByRole("heading", { name: "Discovery" })).toBeVisible();
  await shot(page, "09-bank-a-discovery");
});

test("a Bank A user sees only Bank A", async ({ page }) => {
  await signIn(page, BANK_A_APPROVER, "10-bank-a-approver");
  await expect(page.getByLabel("Acting for bank")).toHaveCount(0); // bank users cannot switch banks
  await go(page, "/connectors");
  await expect(connectorRow(page, "Bank A HQ")).toBeVisible();
  await expect(page.getByText("Bank B Branch 01")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Enrol a site connector" })).toHaveCount(0);
  await shot(page, "11-bank-a-approver-connectors");
});

// ---------------------------------------------------------------------------------------------------------
// Extended journeys: default rings, enrolment fingerprint, connectors layout, maker-checker, viewer, audit
// ---------------------------------------------------------------------------------------------------------

const BANK_A_VIEWER = "viewer@bank-a.lab"; // historic UPN of the Bank A AUDITOR
const BANK_C = { name: "Bank C", slug: "bank-c" };
const DEFAULT_RINGS = ["Ring0-Test", "Ring1-Pilot", "Ring2-Prod"];
const JOB_KEY_FILE = join(__dirname, "..", "..", "lab", "patchgate", "secrets", "job-signing-key.pem");

/** The out-of-band fingerprint, computed like lab/connector/enroll.sh: SHA-256 of the raw 32-byte Ed25519 key. */
function labJobKeyFingerprint(): string {
  const spki = createPublicKey(createPrivateKey(readFileSync(JOB_KEY_FILE))).export({ format: "der", type: "spki" });
  return createHash("sha256").update(spki.subarray(spki.length - 32)).digest("hex");
}

/** Path of the change request created by the maker test, used by the checker tests (serial suite). */
let crPath = "";

test("a new bank starts with the 3 default rollout rings", async ({ page }) => {
  await signIn(page, ADMIN);
  await go(page, "/admin/banks");
  if (!(await page.getByRole("cell", { name: BANK_C.slug, exact: true }).isVisible())) {
    await page.getByRole("button", { name: "New bank" }).click();
    await page.getByLabel("Bank name").fill(BANK_C.name);
    await page.getByLabel("Short code").fill(BANK_C.slug);
    await page.getByRole("button", { name: "Create bank" }).click();
  }
  await expect(page.getByRole("cell", { name: BANK_C.slug, exact: true })).toBeVisible();
  await shotThemes(page, "12-banks-bank-c");
  await go(page, "/");
  await actFor(page, BANK_C.name);
  await go(page, "/patches?needed=0");
  const ring = page.getByLabel("Target ring");
  await expect(ring).toBeVisible();
  expect(await ring.locator("option").allTextContents()).toEqual(DEFAULT_RINGS);
  await shot(page, "13-bank-c-patches-default-rings");
});

test("connector enrolment panel shows the job-key fingerprint and the init command pins it", async ({ page }) => {
  const fpr = labJobKeyFingerprint();
  await signIn(page, ADMIN);
  await go(page, "/connectors");
  await page.getByRole("button", { name: "Enrol a site connector" }).click();
  await page.locator("form").filter({ hasText: "Site name" }).locator("select").selectOption({ label: BANK_B.name });
  await page.getByLabel("Site name").fill("Bank B Branch 02");
  await page.getByRole("button", { name: "Create code" }).click();
  await expect(page.getByText(/Confirm the fingerprint by phone \(job-signing key, SHA-256\)/)).toBeVisible();
  await page.getByText("Offline / USB alternative and manual connector init").click();
  await expect(page.locator("code").filter({ hasText: /^[0-9a-f]{64}$/ })).toHaveText(fpr);
  const init = page.locator("pre").filter({ hasText: "init" }).first();
  await expect(init).toContainText(`--job-key-fingerprint ${fpr}`);
  await expect(init).toContainText("--server https://patchgate.patchgate-lab.internal:3443");
  // Redact the one-time code before the screenshot (the fingerprint is public by design).
  await page.locator("code").filter({ hasText: ENROLL_CODE_RE }).first().evaluate((el) => (el.textContent = "XXXX-XXXX-XXXX-XXXX-XXXX"));
  await init.evaluate((el) => (el.textContent = (el.textContent ?? "").replace(/PATCHGATE_ENROLL_CODE=\S+/, "PATCHGATE_ENROLL_CODE=XXXX-…")));
  await shotThemes(page, "14-enrolment-fingerprint");
});

test("connectors table fits 1440x900 with Revoke visible", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, ADMIN);
  await go(page, "/connectors");
  const row = connectorRow(page, "Bank A HQ");
  await expect(row).toBeVisible();
  const revoke = row.getByRole("button", { name: "Revoke" });
  await expect(revoke).toBeVisible();
  const box = await revoke.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.x + box!.width).toBeLessThanOrEqual(1440);
  // No horizontal scrolling: neither the table wrapper nor the page overflows.
  const overflow = await row.locator("xpath=ancestor::table[1]").evaluate((t) => {
    const wrap = t.parentElement as HTMLElement;
    return { wrap: wrap.scrollWidth - wrap.clientWidth, page: document.documentElement.scrollWidth - document.documentElement.clientWidth };
  });
  expect(overflow.wrap).toBeLessThanOrEqual(1);
  expect(overflow.page).toBeLessThanOrEqual(1);
  await shotThemes(page, "15-connectors-1440");
});

test("maker (platform admin) creates a Bank A Ring0 change request with a third-party app", async ({ page }) => {
  await signIn(page, ADMIN);
  await actFor(page, "Bank A");
  await go(page, "/patches?kind=THIRD_PARTY&needed=0");
  const box = page.locator("tbody input[type=checkbox]:not([disabled])").first();
  await expect(box).toBeVisible();
  const patchTitle = ((await box.getAttribute("aria-label")) ?? "").replace(/^Select /, "");
  await box.check();
  await page.getByLabel("Title").fill(`Lab e2e ${patchTitle} ${new Date().toISOString().slice(0, 16)}`);
  await page.getByLabel("Target ring").selectOption({ label: "Ring0-Test" });
  await shotThemes(page, "16-operator-new-change-request");
  await page.getByRole("button", { name: "Create draft" }).click();
  await page.waitForURL(/\/change-requests\/[^/]+$/);
  crPath = new URL(page.url()).pathname;
  await expect(page.getByRole("cell", { name: patchTitle })).toBeVisible();
  await expect(page.getByText("Ring0-Test").first()).toBeVisible();
  await page.getByRole("button", { name: "Submit for approval" }).click();
  await expect(page.getByText(/^Pending approval$/i)).toBeVisible();
  // The maker never gets Approve on their own request.
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);
  await shotThemes(page, "17-operator-submitted");
});

test("platform staff cannot approve: the checker must be a Bank A admin (auditor: no buttons, API 403)", async ({ page }) => {
  expect(crPath).not.toBe("");
  await signIn(page, AUDITOR);
  await actFor(page, "Bank A");
  await go(page, crPath);
  await expect(page.getByText(/^Pending approval$/i)).toBeVisible();
  await expect(page.getByText(/The checker must be an admin of Bank A/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);
  // Server-side too, not just a hidden button. In-page fetch: the browser holds the session cookies.
  const r = await page.evaluate(async (u) => {
    const res = await fetch(u, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    return { status: res.status, body: await res.text() };
  }, `/api${crPath}/approve`);
  expect(r.status).toBe(403);
  expect(r.body).toMatch(/auditors cannot change anything/);
});

test("a different person (Bank A approver) approves; the frozen target count is shown", async ({ page }) => {
  expect(crPath).not.toBe("");
  await signIn(page, BANK_A_APPROVER);
  await go(page, crPath);
  const header = page.locator("p").filter({ hasText: "Target endpoints" }).first();
  await expect(header).toBeVisible();
  // Header: Ring · Window · Ticket · Target endpoints · Reboot (rc3) — the 4th bold value is the target count.
  const frozen = ((await header.locator("b").nth(3).textContent()) ?? "").trim();
  expect(frozen).toMatch(/^\d+$/); // fixed at submission (not "fixed on submit")
  await shotThemes(page, "18-approver-pending");
  let dialogText = "";
  page.once("dialog", (d) => {
    dialogText = d.message();
    void d.accept();
  });
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText(/^Approved$/i)).toBeVisible();
  expect(dialogText).toContain(`(${frozen} endpoint${frozen === "1" ? "" : "s"}, fixed when it was submitted)`);
  await expect(page.getByRole("listitem").filter({ hasText: "Approved (checker)" })).not.toContainText("—");
  await shotThemes(page, "19-approver-approved");
});

test("a Bank A auditor reads its own bank's admin pages but cannot change anything", async ({ page }) => {
  await signIn(page, BANK_A_VIEWER, "20-bank-a-auditor");
  await go(page, "/admin/users");
  await expect(page.getByText("Accounts for your bank are created and managed by PatchGate")).toBeVisible(); // bank users: read-only list
  await expect(page.getByRole("button", { name: "New user" })).toHaveCount(0);
  await expect(page.getByText("admin@bank-a.lab")).toBeVisible();
  await expect(page.getByText("lab-admin@patchgate.lab")).toHaveCount(0); // never platform users
  await go(page, "/admin/banks");
  await expect(page.getByText("Only PatchGate platform staff see the list of banks.")).toBeVisible();
  const status = await page.evaluate(async () => {
    const list = await fetch("/api/admin/tenants");
    const create = await fetch("/api/admin/users", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ upn: "x@bank-a.lab", name: "X", role: "ADMIN" }) });
    return { list: list.status, create: create.status, body: await create.text() };
  });
  expect(status.list).toBe(200); // own bank only
  expect(status.create).toBe(403);
  expect(status.body).not.toMatch(/temporaryPassword/);
  await go(page, "/admin/users");
  await shotThemes(page, "21-bank-auditor-read-only");
});

test("audit page shows the change-request events on the Bank A chain", async ({ page }) => {
  await signIn(page, BANK_A_APPROVER);
  await go(page, "/audit");
  await expect(page.getByText("Chain integrity")).toBeVisible();
  await expect(page.getByText("Valid", { exact: true })).toBeVisible();
  // The action badges are humanised: change_request.approve → "Change Request.Approve".
  for (const action of [/^Change Request.Approve$/i, /^Change Request.Submit$/i, /^Change Request.Create$/i, /^Auth.Login$/i]) {
    await expect(page.getByRole("cell", { name: action }).first()).toBeVisible();
  }
  await shotThemes(page, "22-audit-bank-a");
});
