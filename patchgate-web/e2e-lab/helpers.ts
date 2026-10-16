import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { expect, test as base, type Browser, type Page } from "@playwright/test";
import { labUser } from "./lab-users";

/**
 * Shared helpers for the lab suites (hosted-lab.spec.ts, features.spec.ts). Never log or screenshot a password:
 * password inputs render as dots, temporary passwords are read from the DOM and the box is dismissed before
 * any screenshot.
 */
export const SHOTS = "e2e-lab/screenshots";
export const LAB_DIR = join(__dirname, "..", "..", "lab");
mkdirSync(SHOTS, { recursive: true });

export const PLATFORM_ADMIN = "lab-admin@patchgate.lab";
export const PLATFORM_AUDITOR = "lab-auditor@patchgate.lab";
export const BANK_A_ADMIN = "admin@bank-a.lab";
export const BANK_A_APPROVER = "approver@bank-a.lab"; // a second Bank A ADMIN — the bank's checker
export const BANK_A_AUDITOR = "viewer@bank-a.lab";

/**
 * Browser errors and server 5xx answers seen by a test. Every test that uses `test` from this file fails if a
 * page logged a console error or any response was a 5xx. Expected 4xx (a test probing a 403 on purpose)
 * makes Chromium log "Failed to load resource … 4xx" — that one is allowed.
 */
interface PageProblems {
  readonly console: string[];
  readonly server: string[];
}

const ALLOWED_CONSOLE = [/Failed to load resource: the server responded with a status of 4\d\d/];

export const test = base.extend<{ problems: PageProblems }>({
  problems: [
    async ({ context }, use) => {
      const problems: PageProblems = { console: [], server: [] };
      const watch = (page: Page): void => {
        page.on("console", (m) => {
          if (m.type() !== "error") return;
          const text = m.text();
          if (!ALLOWED_CONSOLE.some((re) => re.test(text))) problems.console.push(`${page.url()}: ${text.slice(0, /hydrat/i.test(text) ? 4000 : 300)}`);
        });
        page.on("pageerror", (e) => problems.console.push(`${page.url()}: pageerror ${e.message.slice(0, 300)}`));
        page.on("response", (r) => {
          if (r.status() >= 500) problems.server.push(`${r.request().method()} ${r.url()} -> ${r.status()}`);
        });
      };
      context.pages().forEach(watch);
      context.on("page", watch);
      await use(problems);
      expect(problems.server, "no 5xx responses").toEqual([]);
      expect(problems.console, "no browser console errors").toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };

export async function shot(page: Page, name: string): Promise<void> {
  // caret "initial": Playwright's caret-hiding style would otherwise touch inputs that are not hydrated yet.
  await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true, caret: "initial" });
}

/** Screenshot in the light AND the dark theme (the theme toggle only flips <html data-theme>). */
export async function shotThemes(page: Page, name: string): Promise<void> {
  // Never flip the theme before React hydrated the page (that would be a test-made hydration mismatch).
  await hydrated(page, 'button[aria-label^="Switch to"]');
  for (const theme of ["light", "dark"] as const) {
    await page.evaluate((t) => (document.documentElement.dataset.theme = t), theme);
    await shot(page, `${name}-${theme}`);
  }
  await page.evaluate(() => (document.documentElement.dataset.theme = "light"));
}

/**
 * page.goto that tolerates `next dev` aborting a navigation while it compiles a route for the first time and
 * triggers a full reload (net::ERR_ABORTED) — a dev-server artefact, not an app error.
 */
export async function go(page: Page, url: string): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await page.goto(url);
      return;
    } catch (err) {
      if (attempt >= 4 || !/ERR_ABORTED|interrupted by another navigation/.test(String(err))) throw err;
      await page.waitForTimeout(2000);
    }
  }
}

/** Wait until React has hydrated the first <form> (before that, a click submits the bare form natively). */
export async function waitForHydratedForm(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    const form = document.querySelector("form");
    return !!form && Object.keys(form).some((k) => k.startsWith("__reactProps"));
  });
}

/** Wait until React attached its props to an element (buttons/selects work only after hydration). */
export async function hydrated(page: Page, selector: string): Promise<void> {
  await page.waitForFunction((sel) => {
    const el = document.querySelector(sel);
    return !!el && Object.keys(el).some((k) => k.startsWith("__reactProps"));
  }, selector);
}

/**
 * Submit the password step (POST /api/auth/password) and retry on HTTP 500 like a user would ("Please try
 * again"). Returns the JSON step of the last answer.
 */
/**
 * Fill + submit the password step (POST /api/auth/password). `next dev` may still reload a freshly compiled page
 * after hydration (the form comes back empty and the click never posts), so the form is re-opened and re-filled
 * when no request leaves within 20 s. HTTP 500 is retried like a user would ("Please try again").
 * Returns the JSON step of the answer.
 */
async function fillAndSubmit(page: Page, upn: string, password: string, shotName?: string): Promise<string> {
  for (let attempt = 1; ; attempt++) {
    await go(page, "/login");
    await waitForHydratedForm(page);
    await page.getByLabel("Username").fill(upn);
    await page.getByLabel("Password").fill(password);
    if (shotName && attempt === 1) await shot(page, shotName);
    const res = page
      .waitForResponse((r) => r.url().endsWith("/api/auth/password") && r.request().method() === "POST", { timeout: 20_000 })
      .catch(() => null);
    if ((await page.getByLabel("Username").inputValue()) === upn) await page.getByRole("button", { name: "Continue" }).click();
    const r = await res;
    if (r && r.status() !== 500) {
      const body = (await r.json().catch(() => ({}))) as { data?: { step?: string } };
      if (body.data?.step) return body.data.step;
      if (r.status() !== 200) return `http-${r.status()}`;
      // "done" navigates away at once and the body is gone: read the outcome from the page instead.
      await Promise.race([
        page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 30_000 }),
        page.getByText("You need a new password before you can continue", { exact: false }).waitFor({ timeout: 30_000 }),
      ]).catch(() => undefined);
      return new URL(page.url()).pathname.startsWith("/login") ? "change-password" : "done";
    }
    test.info().annotations.push({ type: "lab-finding", description: `${upn}: sign-in attempt ${attempt} ${r ? "HTTP 500" : "form reloaded"}` });
    if (attempt >= 5) throw new Error(`sign-in for ${upn} kept failing`);
  }
}

/** Fill the real sign-in form. `password` defaults to the lab-users.json password. Returns the API step. */
export async function submitLogin(page: Page, upn: string, password?: string, shotName?: string): Promise<string> {
  await page.context().clearCookies();
  return fillAndSubmit(page, upn, password ?? labUser(upn).password, shotName);
}

/** Sign in (password only) and wait until the landing page settled. */
export async function signIn(page: Page, upn: string, opts: { password?: string; shotName?: string } = {}): Promise<void> {
  const step = await submitLogin(page, upn, opts.password, opts.shotName);
  expect(step, `sign-in step for ${upn}`).toBe("done");
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  await page.waitForLoadState("networkidle");
}

/** The bank switcher (sidebar, mobile bar and /select-bank each render one): the first visible one. */
export const bankSwitcher = (page: Page) => page.getByLabel("Acting for bank").filter({ visible: true }).first();

/** Platform staff: act for a bank (server-side cookie). */
export async function actFor(page: Page, bank: string): Promise<void> {
  await page.waitForLoadState("networkidle");
  await bankSwitcher(page).evaluate(
    (el) =>
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

/** fetch() inside the page (uses the page's session cookies). */
export async function pageFetch(
  page: Page,
  url: string,
  init: { method?: string; body?: unknown } = {},
): Promise<{ status: number; text: string; headers: Record<string, string> }> {
  return page.evaluate(
    async ({ url, method, body }) => {
      const res = await fetch(url, {
        method: method ?? "GET",
        headers: body === undefined ? {} : { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k] = v));
      return { status: res.status, text: await res.text(), headers };
    },
    { url, method: init.method, body: init.body },
  );
}

/** A second, isolated browser session (another person / another device). */
export async function newSession(browser: Browser, baseURL: string | undefined): Promise<Page> {
  const ctx = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 } });
  return ctx.newPage();
}

/** Run a lab bash script (Git Bash) and return its stdout. Scripts never print secrets. */
export function labScript(script: string, ...args: string[]): string {
  return execFileSync("bash", [join(LAB_DIR, script), ...args], {
    encoding: "utf8",
    env: { ...process.env, MSYS_NO_PATHCONV: "1" },
    timeout: 180_000,
  });
}

/** Poll `fn` until it returns a truthy value (or throw after timeoutMs). */
export async function until<T>(what: string, fn: () => Promise<T | undefined | null | false>, timeoutMs: number, everyMs = 5000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out after ${timeoutMs} ms waiting for ${what}`);
    await new Promise((r) => setTimeout(r, everyMs));
  }
}
