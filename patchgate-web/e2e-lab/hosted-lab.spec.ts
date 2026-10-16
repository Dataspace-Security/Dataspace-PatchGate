import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { freshTotp, labUser, recordTotpSecret } from "./lab-users";

/**
 * Hosted-lab journey in a real browser against the running lab (no fakes):
 *   our staff sign in with password + TOTP → onboard a bank + one-time connector code in the UI →
 *   Bank A's real connector is online → switch bank → endpoints / discovery → a bank user sees only
 *   their own bank. Screenshots: e2e-lab/screenshots/.
 */
test.describe.configure({ mode: "serial" });

const SHOTS = "e2e-lab/screenshots";
const ADMIN = "lab-admin@patchgate.lab";
const OPERATOR = "lab-operator@patchgate.lab";
const BANK_A_APPROVER = "approver@bank-a.lab";
const BANK_B = { name: "Bank B", slug: "bank-b" };
const ENROLL_CODE_RE = /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){4}$/;

/** The bank switcher (sidebar, mobile bar and /select-bank each render one): the first visible one. */
const bankSwitcher = (page: Page) => page.getByLabel("Acting for bank").filter({ visible: true }).first();

async function shot(page: Page, name: string): Promise<void> {
  await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true });
}

/**
 * Wait until React has hydrated the sign-in form. Before that, a click submits the bare <form> natively
 * (GET /login?username=…&password=… — see the lab report finding), so never type before this.
 */
async function waitForHydratedForm(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    const form = document.querySelector("form");
    return !!form && Object.keys(form).some((k) => k.startsWith("__reactProps"));
  });
}

/**
 * Submit one sign-in step (POST /api/auth/{step}) and retry it on HTTP 500.
 * LAB FINDING: under host load (`next dev` + a long worker tick in the same process) a step can return 500
 * "Sign-in is temporarily unavailable" — Prisma P2028, the 5 s interactive-transaction timeout in
 * src/lib/auth/local-login.ts. The page says "Please try again", so retry like a user, and record it.
 */
async function submitStep(page: Page, upn: string, step: "password" | "totp", submit: () => Promise<void>): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    const res = page.waitForResponse((r) => r.url().endsWith(`/api/auth/${step}`) && r.request().method() === "POST");
    await submit();
    if ((await res).status() !== 500) return;
    test.info().annotations.push({ type: "lab-finding", description: `${upn}: ${step} step HTTP 500 "temporarily unavailable" (attempt ${attempt})` });
    if (attempt >= 5) throw new Error(`sign-in for ${upn} kept failing at the ${step} step`);
  }
}

/** The real local sign-in form: password → authenticator (enrol on first use, secret read off the page). */
async function signIn(page: Page, upn: string, shotPrefix?: string): Promise<void> {
  await page.context().clearCookies();
  await page.goto("/login");
  await waitForHydratedForm(page);
  await page.getByLabel("Username").fill(upn);
  await page.getByLabel("Password").fill(labUser(upn).password);
  const code = page.getByLabel("Verification code");
  await submitStep(page, upn, "password", async () => page.getByRole("button", { name: "Continue" }).click());
  await expect(code).toBeVisible();
  const enrolKey = page.locator("code.select-all");
  if (await enrolKey.isVisible()) {
    // First sign-in: mandatory authenticator enrolment. The key shown for manual entry is the TOTP secret.
    if (shotPrefix) await shot(page, `${shotPrefix}-totp-enrol`);
    recordTotpSecret(upn, (await enrolKey.textContent()) ?? "");
  } else if (shotPrefix) {
    await shot(page, `${shotPrefix}-totp-verify`);
  }
  await submitStep(page, upn, "totp", async () => {
    await code.fill(await freshTotp(upn)); // a fresh 30-s step per attempt (each step is accepted once)
    await page.getByRole("button", { name: /Verify/ }).click();
  });
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  // The landing page may redirect again (e.g. staff without a bank → /select-bank): let it settle first.
  await page.waitForLoadState("networkidle");
}

test("platform admin: password + TOTP sign-in", async ({ page }) => {
  await page.goto("/login");
  await waitForHydratedForm(page);
  await expect(page.getByLabel("Username")).toBeVisible();
  await shot(page, "01-login");
  await signIn(page, ADMIN, "02-admin");
  await expect(bankSwitcher(page)).toBeVisible(); // bank switcher = PatchGate staff
  await shot(page, "03-admin-home");
});

test("wrong TOTP code is refused", async ({ page }) => {
  await page.goto("/login");
  await waitForHydratedForm(page);
  await page.getByLabel("Username").fill(ADMIN);
  await page.getByLabel("Password").fill(labUser(ADMIN).password);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Verification code").fill("000000");
  await page.getByRole("button", { name: /Verify/ }).click();
  await expect(page.getByText(/code|incorrect|invalid/i).first()).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});

test("platform operator: first sign-in enrols the authenticator", async ({ page }) => {
  await signIn(page, OPERATOR, "04-operator");
  await expect(bankSwitcher(page)).toBeVisible();
});

test("admin onboards a bank and creates a one-time connector enrolment code in the UI", async ({ page }) => {
  await signIn(page, ADMIN);
  await page.goto("/admin/banks");
  if (!(await page.getByRole("cell", { name: BANK_B.slug, exact: true }).isVisible())) {
    await page.getByRole("button", { name: "New bank" }).click();
    await page.getByLabel("Bank name").fill(BANK_B.name);
    await page.getByLabel("Short code").fill(BANK_B.slug);
    await page.getByRole("button", { name: "Create bank" }).click();
  }
  await expect(page.getByText(BANK_B.slug, { exact: true }).first()).toBeVisible();
  await shot(page, "05-banks");

  await page.goto("/connectors");
  await page.getByRole("button", { name: "Enrol a site connector" }).click();
  await page.locator("form").filter({ hasText: "Site name" }).locator("select").selectOption({ label: BANK_B.name });
  await page.getByLabel("Site name").fill("Bank B Branch 01");
  await page.getByRole("button", { name: "Create code" }).click();
  const code = page.locator("code").filter({ hasText: ENROLL_CODE_RE }).first();
  await expect(code).toBeVisible();
  expect((await code.textContent())?.trim()).toMatch(ENROLL_CODE_RE);
  // The init command names OUR public URL (PUBLIC_BASE_URL), never the code in the process list.
  await expect(page.getByText(/PATCHGATE_ENROLL_CODE=/).first()).toBeVisible();
  await expect(page.getByText(/--server https:\/\/patchgate\.patchgate-lab\.internal:3443/).first()).toBeVisible();
  await page.locator("code").filter({ hasText: ENROLL_CODE_RE }).first().evaluate((el) => (el.textContent = "XXXX-XXXX-XXXX-XXXX-XXXX"));
  await page.getByText(/PATCHGATE_ENROLL_CODE=/).first().evaluate((el) => (el.textContent = (el.textContent ?? "").replace(/PATCHGATE_ENROLL_CODE=\S+/, "PATCHGATE_ENROLL_CODE=XXXX-…")));
  await shot(page, "06-enrolment-code-redacted");
});

test("Bank A's real site connector is online", async ({ page }) => {
  await signIn(page, ADMIN);
  await page.goto("/connectors");
  const row = page.getByRole("row").filter({ hasText: "Bank A HQ" });
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
  await page.goto("/endpoints");
  await expect(page.getByRole("heading", { name: "Endpoints" })).toBeVisible();
  await shot(page, "08-bank-a-endpoints");
  await page.goto("/discovery");
  await expect(page.getByRole("heading", { name: "Discovery" })).toBeVisible();
  await shot(page, "09-bank-a-discovery");
});

test("a Bank A user sees only Bank A", async ({ page }) => {
  await signIn(page, BANK_A_APPROVER, "10-bank-a-approver");
  await expect(page.getByLabel("Acting for bank")).toHaveCount(0); // bank users cannot switch banks
  await page.goto("/connectors");
  await expect(page.getByRole("row").filter({ hasText: "Bank A HQ" })).toBeVisible();
  await expect(page.getByText("Bank B Branch 01")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Enrol a site connector" })).toHaveCount(0);
  await shot(page, "11-bank-a-approver-connectors");
});

// ---------------------------------------------------------------------------------------------------------
// Extended journeys: default rings, enrolment fingerprint, connectors layout, maker-checker, viewer, audit
// ---------------------------------------------------------------------------------------------------------

const BANK_A_VIEWER = "viewer@bank-a.lab";
const BANK_C = { name: "Bank C", slug: "bank-c" };
const DEFAULT_RINGS = ["Ring0-Test", "Ring1-Pilot", "Ring2-Prod"];
const JOB_KEY_FILE = join(__dirname, "..", "..", "lab", "patchgate", "secrets", "job-signing-key.pem");

/** The out-of-band fingerprint, computed like lab/connector/enroll.sh: SHA-256 of the raw 32-byte Ed25519 key. */
function labJobKeyFingerprint(): string {
  const spki = createPublicKey(createPrivateKey(readFileSync(JOB_KEY_FILE))).export({ format: "der", type: "spki" });
  return createHash("sha256").update(spki.subarray(spki.length - 32)).digest("hex");
}

/** Screenshot in the light AND the dark theme (the theme toggle only flips <html data-theme>). */
async function shotThemes(page: Page, name: string): Promise<void> {
  for (const theme of ["light", "dark"] as const) {
    await page.evaluate((t) => (document.documentElement.dataset.theme = t), theme);
    await shot(page, `${name}-${theme}`);
  }
  await page.evaluate(() => (document.documentElement.dataset.theme = "light"));
}

async function actFor(page: Page, bank: string): Promise<void> {
  await page.waitForLoadState("networkidle");
  // Only a hydrated <select> posts the switch (onChange); wait for React to attach its props first.
  await bankSwitcher(page).evaluate((el) =>
    new Promise<void>((done) => {
      const ready = () => Object.keys(el).some((k) => k.startsWith("__reactProps"));
      const tick = () => (ready() ? done() : setTimeout(tick, 100));
      tick();
    }),
  );
  const selected = page.waitForResponse((r) => r.url().endsWith("/api/tenant/select") && r.request().method() === "POST");
  await bankSwitcher(page).selectOption({ label: bank });
  expect((await selected).status()).toBe(200);
}

/** Path of the change request created by the maker test, used by the checker tests (serial suite). */
let crPath = "";

test("a new bank starts with the 3 default rollout rings", async ({ page }) => {
  await signIn(page, ADMIN);
  await page.goto("/admin/banks");
  if (!(await page.getByRole("cell", { name: BANK_C.slug, exact: true }).isVisible())) {
    await page.getByRole("button", { name: "New bank" }).click();
    await page.getByLabel("Bank name").fill(BANK_C.name);
    await page.getByLabel("Short code").fill(BANK_C.slug);
    await page.getByRole("button", { name: "Create bank" }).click();
  }
  await expect(page.getByRole("cell", { name: BANK_C.slug, exact: true })).toBeVisible();
  await shotThemes(page, "12-banks-bank-c");
  await page.goto("/");
  await actFor(page, BANK_C.name);
  await page.goto("/patches?needed=0");
  const ring = page.getByLabel("Target ring");
  await expect(ring).toBeVisible();
  expect(await ring.locator("option").allTextContents()).toEqual(DEFAULT_RINGS);
  await shot(page, "13-bank-c-patches-default-rings");
});

test("connector enrolment panel shows the job-key fingerprint and the init command pins it", async ({ page }) => {
  const fpr = labJobKeyFingerprint();
  await signIn(page, ADMIN);
  await page.goto("/connectors");
  await page.getByRole("button", { name: "Enrol a site connector" }).click();
  await page.locator("form").filter({ hasText: "Site name" }).locator("select").selectOption({ label: BANK_B.name });
  await page.getByLabel("Site name").fill("Bank B Branch 02");
  await page.getByRole("button", { name: "Create code" }).click();
  await expect(page.getByText("Job-signing key fingerprint (SHA-256) for this bank")).toBeVisible();
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
  await page.goto("/connectors");
  const row = page.getByRole("row").filter({ hasText: "Bank A HQ" });
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

test("maker (platform operator) creates a Bank A Ring0 change request with a third-party app", async ({ page }) => {
  await signIn(page, OPERATOR);
  await actFor(page, "Bank A");
  await page.goto("/patches?kind=THIRD_PARTY&needed=0");
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

test("platform admin cannot approve when Bank A requires a bank approver", async ({ page }) => {
  expect(crPath).not.toBe("");
  await signIn(page, ADMIN);
  await actFor(page, "Bank A");
  await page.goto(crPath);
  await expect(page.getByText(/^Pending approval$/i)).toBeVisible();
  await expect(page.getByText(/requires the checker to be one of its own approvers/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);
  // Server-side too: the API refuses (state machine), not just a hidden button.
  // In-page fetch: the browser holds the session cookies and the pinned lab certificate.
  const r = await page.evaluate(async (u) => {
    const res = await fetch(u, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    return { status: res.status, body: await res.text() };
  }, `/api${crPath}/approve`);
  expect(r.status).toBe(409);
  expect(r.body).toMatch(/Bank approval required/);
});

test("a different person (Bank A approver) approves; the frozen target count is shown", async ({ page }) => {
  expect(crPath).not.toBe("");
  await signIn(page, BANK_A_APPROVER);
  await page.goto(crPath);
  const header = page.locator("p").filter({ hasText: "Target endpoints" }).first();
  await expect(header).toBeVisible();
  const frozen = ((await header.locator("b").last().textContent()) ?? "").trim();
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

test("a Bank A viewer cannot see admin pages", async ({ page }) => {
  await signIn(page, BANK_A_VIEWER, "20-bank-a-viewer");
  for (const path of ["/admin", "/admin/users", "/admin/banks"]) {
    await page.goto(path);
    await expect(page.getByText("Administrators only.")).toBeVisible();
    await expect(page.getByRole("button", { name: "New bank" })).toHaveCount(0);
  }
  const apiStatus = await page.evaluate(async () => (await fetch("/api/admin/tenants")).status);
  expect([401, 403]).toContain(apiStatus);
  await page.goto("/admin/users");
  await shotThemes(page, "21-viewer-admin-denied");
});

test("audit page shows the change-request events on the Bank A chain", async ({ page }) => {
  await signIn(page, BANK_A_APPROVER);
  await page.goto("/audit");
  await expect(page.getByText("Chain integrity")).toBeVisible();
  await expect(page.getByText("Valid", { exact: true })).toBeVisible();
  // The action badges are humanised: change_request.approve → "Change Request.Approve".
  for (const action of [/^Change Request.Approve$/i, /^Change Request.Submit$/i, /^Change Request.Create$/i, /^Auth.Login$/i]) {
    await expect(page.getByRole("cell", { name: action }).first()).toBeVisible();
  }
  await shotThemes(page, "22-audit-bank-a");
});
