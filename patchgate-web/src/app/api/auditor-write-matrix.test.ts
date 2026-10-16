/**
 * AUDITOR is read-only: walks EVERY route handler under src/app/api and calls each non-GET export as a
 * platform auditor and as a bank auditor — every one must answer 403 before touching the database.
 * The only exceptions are listed (with the reason) in ALLOWED; a new mutating route is covered automatically.
 */
import { readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

type TestUser = { id: string; role: "ADMIN" | "AUDITOR"; upn: string; name: string; tenantId: string | null };
const ctx = vi.hoisted(() => ({ user: null as TestUser | null }));

vi.mock("next/headers", () => ({
  cookies: async () => ({ get: () => undefined, set: () => undefined, delete: () => undefined, has: () => false }),
  headers: async () => new Headers(),
}));

vi.mock("@/lib/auth/session", async (importOriginal) => {
  const orig = await importOriginal<typeof import("@/lib/auth/session")>();
  return {
    ...orig,
    getCurrentUser: async () => {
      if (!ctx.user) throw new orig.AuthError("Not signed in", 401);
      return ctx.user;
    },
  };
});

Object.assign(process.env, {
  NODE_ENV: "test",
  // Unreachable on purpose: a handler that got past its role check would fail with 500, not 403.
  DATABASE_URL: "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=1",
  AUDIT_HMAC_KEY: "h".repeat(40),
  WORKER_TOKEN: "w".repeat(40),
  AUTH_ENC_KEY: "cd".repeat(32),
  AUTH_MODE: "local",
});

const API_DIR = fileURLToPath(new URL(".", import.meta.url));
const METHODS = ["POST", "PUT", "PATCH", "DELETE"] as const;

/**
 * Mutations an auditor MAY make (everything else must be 403):
 * - own account / sign-in: password change, revoke own other sessions, sign-out, the local sign-in steps;
 * - tenant/select: platform auditors switch the bank they READ (audited "vendor access", changes no data);
 * - audit/verify: checking a SIEM anchor is a read-only verification (recorded, changes no data).
 * Machine endpoints (connector, worker, WSUS) are token-authenticated, never session users. dev-login: dev only.
 */
const ALLOWED = new Set([
  "account/password",
  "account/sessions/revoke-others",
  "auth/logout",
  "auth/password",
  "auth/password/change",
  "tenant/select",
  "audit/verify",
  "dev-login",
]);
const MACHINE = ["connector/v1/", "worker/", "wsus/"];

/** Valid dynamic segments so handlers get past their own 404 checks and reach the role check. */
const PARAMS: Record<string, Record<string, string>> = {
  "admin/users/[id]/[action]": { action: "reset-password" },
  "apps/[id]/[action]": { action: "enable" },
  "change-requests/[id]/[action]": { action: "approve" },
  "discovery/[id]/[action]": { action: "manage" },
  "mirror/[id]/[decision]": { decision: "approve" },
  "packages/[id]/[decision]": { decision: "approve" },
};

function routeFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return routeFiles(p);
    return name === "route.ts" ? [p] : [];
  });
}

function routeKey(file: string): string {
  return relative(API_DIR, file).split(sep).slice(0, -1).join("/");
}

function paramsFor(key: string): Record<string, string> {
  const base = Object.fromEntries([...key.matchAll(/\[(\w+)\]/g)].map((m) => [m[1], m[1] === "sha256" ? "a".repeat(64) : "cm0000000000000000000000x"]));
  return { ...base, ...(PARAMS[key] ?? {}) };
}

const ORIGIN = "https://patchgate.test";
function request(method: string, key: string): Request {
  return new Request(`${ORIGIN}/api/${key}`, {
    method,
    headers: { origin: ORIGIN, host: "patchgate.test", "content-type": "application/json" },
    body: JSON.stringify({ scope: "platform", action: "set-events", disabledEvents: [], title: "x", ringId: "r", patchIds: ["p"], name: "n", slug: "s", upn: "a@b.c", role: "ADMIN", event: "CR_SUBMITTED", optedOut: true, tenantId: null }),
  });
}

const files = routeFiles(API_DIR);
const mutating = files.flatMap((f) => {
  const key = routeKey(f);
  if (ALLOWED.has(key) || MACHINE.some((m) => key.startsWith(m))) return [];
  return [{ file: f, key }];
});

const auditors: TestUser[] = [
  { id: "u-platform-auditor", role: "AUDITOR", upn: "auditor@patchgate.test", name: "Platform auditor", tenantId: null },
  { id: "u-bank-auditor", role: "AUDITOR", upn: "auditor@bank-a.test", name: "Bank auditor", tenantId: "tenant-default" },
];

describe("AUDITOR can never change anything", () => {
  it("finds the route handlers (sanity)", () => {
    expect(files.length).toBeGreaterThan(40);
    expect(mutating.length).toBeGreaterThan(25);
  });

  for (const auditor of auditors) {
    it(`every mutating route answers 403 for a ${auditor.tenantId ? "bank" : "platform"} auditor`, async () => {
      ctx.user = auditor;
      const results: string[] = [];
      let checked = 0;
      for (const { file, key } of mutating) {
        const mod = (await import(/* @vite-ignore */ file)) as Record<string, unknown>;
        for (const method of METHODS) {
          const handler = mod[method];
          if (typeof handler !== "function") continue;
          checked++;
          const res = (await handler(request(method, key), { params: Promise.resolve(paramsFor(key)) })) as Response;
          if (res.status !== 403) results.push(`${method} /api/${key} → ${res.status}`);
        }
      }
      expect(checked).toBeGreaterThan(30);
      expect(results).toEqual([]);
    }, 60_000);
  }

  it("every user-admin mutation (create / edit / reset / unlock) answers 403 for a BANK admin", async () => {
    ctx.user = { id: "u-bank-admin", role: "ADMIN", upn: "admin@bank-a.test", name: "Bank admin", tenantId: "tenant-default" };
    const userRoutes = mutating.filter(({ key }) => key.startsWith("admin/users"));
    const results: string[] = [];
    let checked = 0;
    for (const { file, key } of userRoutes) {
      const mod = (await import(/* @vite-ignore */ file)) as Record<string, unknown>;
      for (const method of METHODS) {
        const handler = mod[method];
        if (typeof handler !== "function") continue;
        const actions = key.endsWith("[action]") ? ["reset-password", "unlock"] : [undefined];
        for (const action of actions) {
          checked++;
          const params = { ...paramsFor(key), ...(action ? { action } : {}) };
          const res = (await handler(request(method, key), { params: Promise.resolve(params) })) as Response;
          const body = (await res.json()) as { error?: string };
          if (res.status !== 403 || body.error !== "Accounts are managed by PatchGate platform administrators") {
            results.push(`${method} /api/${key}${action ? ` (${action})` : ""} → ${res.status} ${body.error ?? ""}`);
          }
        }
      }
    }
    expect(checked).toBe(4); // POST users, PATCH users/:id, POST users/:id/{reset-password,unlock}
    expect(results).toEqual([]);
  });

  it("the same routes are not blanket-denied: an admin gets past the role gate (no 403 from requireWriter)", async () => {
    ctx.user = { id: "u-admin", role: "ADMIN", upn: "admin@patchgate.test", name: "Admin", tenantId: null };
    const mod = (await import("./change-requests/route")) as { POST: (r: Request) => Promise<Response> };
    const res = await mod.POST(request("POST", "change-requests"));
    expect(res.status).not.toBe(403); // reaches tenant resolution (409: select a bank) — not the auditor gate
  });
});
