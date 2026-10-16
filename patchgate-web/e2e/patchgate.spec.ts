import { expect, test, type Page } from "@playwright/test";

/**
 * Real-browser UI tests. Run order matters (serial): maker creates → checker approves → deploy.
 * Screenshots of every screen (light + dark) are written to e2e/screenshots/ for visual review.
 */
test.describe.configure({ mode: "serial" });

const SHOTS = "e2e/screenshots";

const BASE = "http://localhost:3200";
const DEFAULT_BANK = "tenant-default";
const BANK_B = "tenant-bank-b";

/**
 * Sign in via the dev cookie (the login form itself is rate-limited and has its own test).
 * `bank` = the bank-switcher cookie for PatchGate staff (ignored by the server for bank users); null = none.
 */
async function actAs(page: Page, upn: string, bank: string | null = DEFAULT_BANK) {
  await page.context().clearCookies();
  const cookies = [{ name: "pg_dev_user", value: upn, url: BASE }];
  if (bank) cookies.push({ name: "pg_tenant", value: bank, url: BASE });
  await page.context().addCookies(cookies);
  await page.goto("/");
}

async function setTheme(page: Page, theme: "light" | "dark") {
  await page.evaluate((t) => {
    localStorage.setItem("patchgate-theme", t);
    document.documentElement.dataset.theme = t;
  }, theme);
}

async function shoot(page: Page, name: string) {
  for (const theme of ["light", "dark"] as const) {
    await setTheme(page, theme);
    await page.screenshot({ path: `${SHOTS}/${name}-${theme}.png`, fullPage: true });
  }
  await setTheme(page, "light");
}

test.beforeEach(async ({ page }) => {
  page.on("dialog", (d) => d.accept("e2e reason"));
});

test("dev login screen switches the acting user", async ({ page }) => {
  await page.goto("/dev-login");
  await shoot(page, "00-dev-login");
  await page.locator("li", { hasText: "approver@dev.local" }).getByRole("button", { name: "Use this user" }).click();
  await page.waitForURL("/");
  await expect(page.getByText("Dev Approver").first()).toBeVisible();
});

test("theme follows the toggle and survives reload (no flash)", async ({ page }) => {
  await actAs(page, "admin@dev.local");
  await setTheme(page, "light");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

  await page.getByRole("button", { name: /switch to dark theme/i }).first().click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(bg).toBe("rgb(10, 15, 28)"); // dark token --bg
  await setTheme(page, "light");
});

test("dashboard shows real compliance numbers and next steps", async ({ page }) => {
  await actAs(page, "admin@dev.local");
  await expect(page.getByRole("heading", { name: "Patch compliance" })).toBeVisible();
  await expect(page.getByText("Fully patched PCs")).toBeVisible();
  await expect(page.getByText(/Assign 1 PC\(s\) to a rollout ring/)).toBeVisible();
  await expect(page.locator("nav[aria-label=Main] a[aria-current=page]").first()).toHaveText(/Dashboard/);
  await shoot(page, "01-dashboard");
});

test("maker creates and submits a change request; cannot approve it", async ({ page }) => {
  await actAs(page, "operator@dev.local");
  await page.goto("/patches");
  await page.getByRole("checkbox", { name: /Select 2026-10 Cumulative Update/ }).check();
  await page.getByLabel("Title").fill("E2E — October cumulative update");
  await page.getByLabel(/Change ticket/).fill("CHG-E2E-1");
  await page.getByLabel("Target ring").selectOption({ label: "Ring0-Test" });
  await shoot(page, "02-patches-selected");
  await page.getByRole("button", { name: "Create draft" }).click();

  await page.waitForURL(/\/change-requests\/.+/);
  await expect(page.getByText("E2E — October cumulative update").first()).toBeVisible();
  await page.getByRole("button", { name: "Submit for approval" }).click();
  await expect(page.getByText("pending approval").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0); // maker-checker
  await shoot(page, "03-cr-pending");
});

test("checker approves and queues deployment; audit trail shows both people", async ({ page }) => {
  await actAs(page, "approver@dev.local");
  await page.goto("/change-requests");
  await shoot(page, "04-change-requests");
  await page.getByRole("link", { name: "E2E — October cumulative update" }).click();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("approved").first()).toBeVisible();
  await page.getByRole("button", { name: "Queue deployment" }).click();
  await expect(page.getByText("deploying").first()).toBeVisible();
  await expect(page.getByText("BR001-PC01")).toBeVisible();
  await expect(page.getByText(/change request approve\s*by approver@dev\.local/)).toBeVisible();
  await expect(page.getByText(/change request create\s*by operator@dev\.local/)).toBeVisible();
  await shoot(page, "05-cr-deploying");
});

test("viewer cannot create change requests", async ({ page }) => {
  await actAs(page, "viewer@dev.local");
  await page.goto("/patches");
  await expect(page.getByText("Your role cannot create change requests.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create draft" })).toBeDisabled();
});

test("endpoint ring assignment persists", async ({ page }) => {
  await actAs(page, "operator@dev.local");
  await page.goto("/endpoints");
  await expect(page.getByText(/not in any rollout ring/)).toBeVisible();
  const row = page.locator("tr", { hasText: "BR002-PC02" });
  await row.getByLabel("Ring").selectOption({ label: "Ring1-Pilot" });
  await expect(page.getByText(/not in any rollout ring/)).toHaveCount(0);
  await page.reload();
  await expect(page.locator("tr", { hasText: "BR002-PC02" }).getByLabel("Ring")).toHaveValue(/.+/);
  await shoot(page, "06-endpoints");
});

test("sync with Tactical down shows a clear message, not 'Internal error'", async ({ page }) => {
  await actAs(page, "operator@dev.local");
  await page.goto("/endpoints");
  await page.getByRole("button", { name: "Sync agents from Tactical" }).click();
  await expect(page.getByRole("alert").filter({ hasText: /Tactical RMM is unreachable|Tactical RMM rejected/ })).toBeVisible();
  await expect(page.getByText("Internal error")).toHaveCount(0);
});

test("admin allow-list form rejects internal hosts and accepts a public one", async ({ page }) => {
  await actAs(page, "admin@dev.local");
  await page.goto("/apps");
  await page.getByLabel("winget ID").fill("7zip.7zip");
  await page.getByLabel("Display name").fill("7-Zip");
  await page.getByLabel(/Inventory match/).fill("^7-Zip");
  await page.getByLabel(/Pinned publisher/).fill("O=Igor Pavlov");
  await page.getByLabel(/Allowed download hosts/).fill("intranet.bank.local");
  await page.getByRole("button", { name: "Add to allow-list" }).click();
  await expect(page.getByRole("alert")).toBeVisible();

  await page.getByLabel(/Allowed download hosts/).fill("www.7-zip.org");
  await page.getByRole("button", { name: "Add to allow-list" }).click();
  await expect(page.getByRole("cell", { name: /7-Zip/ }).first()).toBeVisible();
  await shoot(page, "07-apps");
});

test("audit page: chain valid, SIEM anchor check reports a mismatch for a fake hash", async ({ page }) => {
  await actAs(page, "approver@dev.local");
  await page.goto("/audit");
  await expect(page.getByText("Valid", { exact: true })).toBeVisible();
  await page.getByLabel("seq").fill("1");
  await page.getByLabel("hash").fill("f".repeat(64));
  await page.getByRole("button", { name: "Check against PatchGate DB" }).click();
  await expect(page.getByRole("status")).toContainText(/differs|not found/);
  await shoot(page, "08-audit");
});

test("mobile layout: top navigation, no horizontal overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await actAs(page, "admin@dev.local");
  await expect(page.locator("header nav[aria-label=Main]")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await shoot(page, "09-mobile-dashboard");
});

test("rate limiting returns 429 with Retry-After on login brute force", async ({ request }) => {
  const statuses: number[] = [];
  for (let i = 0; i < 8; i++) {
    const r = await request.post("/api/dev-login", {
      headers: { Origin: "http://localhost:3200" },
      data: { upn: "nobody@dev.local" },
    });
    statuses.push(r.status());
    if (r.status() === 429) expect(r.headers()["retry-after"]).toBeTruthy();
  }
  expect(statuses).toContain(429);
});

test.describe("multi-bank", () => {
  test("PatchGate staff without a selected bank are sent to the bank picker, then switch", async ({ page }) => {
    await actAs(page, "operator@dev.local", null);
    await page.waitForURL(/\/select-bank/);
    await page.getByLabel("Acting for bank").last().selectOption({ label: "Default bank" });
    await page.waitForURL("/");
    await expect(page.getByRole("heading", { name: "Patch compliance" })).toBeVisible();
  });

  test("a bank user sees only their own bank and has no switcher", async ({ page }) => {
    await actAs(page, "approver@bankb.local", DEFAULT_BANK); // forged cookie is ignored
    await page.goto("/endpoints");
    await expect(page.getByText("BNKB-HQ-PC01")).toBeVisible();
    await expect(page.getByText("BR001-PC01")).toHaveCount(0);
    await expect(page.getByLabel("Acting for bank")).toHaveCount(0);
    await page.goto("/change-requests");
    await expect(page.getByText("E2E — October cumulative update")).toHaveCount(0);
  });

  test("bank switch moves PatchGate staff between banks", async ({ page }) => {
    await actAs(page, "admin@dev.local", BANK_B);
    await page.goto("/endpoints");
    await expect(page.getByText("BNKB-HQ-PC01")).toBeVisible();
    await page.getByLabel("Acting for bank").first().selectOption({ label: "Default bank" });
    await expect(page.getByText("BR001-PC01")).toBeVisible();
    await expect(page.getByText("BNKB-HQ-PC01")).toHaveCount(0);
  });

  test("bank approval policy: PatchGate admin gets no Approve button on a pending request", async ({ page }) => {
    await actAs(page, "operator@dev.local");
    await page.goto("/patches");
    await page.getByRole("checkbox", { name: /Select 2026-10 \.NET Framework/ }).check();
    await page.getByLabel("Title").fill("E2E — policy check");
    await page.getByLabel("Target ring").selectOption({ label: "Ring0-Test" });
    await page.getByRole("button", { name: "Create draft" }).click();
    await page.waitForURL(/\/change-requests\/.+/);
    await page.getByRole("button", { name: "Submit for approval" }).click();
    await expect(page.getByText("pending approval").first()).toBeVisible();
    const url = page.url();

    await actAs(page, "admin@dev.local");
    await page.goto(url);
    await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);
  });

  test("Admin link is in the navigation", async ({ page }) => {
    await actAs(page, "admin@dev.local");
    await expect(page.locator("nav[aria-label=Main]").first().getByRole("link", { name: "Admin" })).toBeVisible();
  });
});
