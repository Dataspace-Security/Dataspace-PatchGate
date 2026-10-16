/**
 * AUTH_MFA=off is visible: the warning banner (ADMIN users only) and /api/health `mfa`.
 * Pure env helpers are checked for both values; the rendered pieces run with AUTH_MFA=off.
 */
import { describe, expect, it, vi } from "vitest";

type TestUser = { id: string; role: "ADMIN" | "AUDITOR"; upn: string; name: string; tenantId: string | null };
const ctx = vi.hoisted(() => ({ user: null as TestUser | null }));

vi.mock("next/server", async (importOriginal) => ({ ...(await importOriginal<object>()), connection: async () => undefined }));
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
  DATABASE_URL: "postgresql://nobody:nothing@127.0.0.1:1/none",
  AUDIT_HMAC_KEY: "h".repeat(40),
  WORKER_TOKEN: "w".repeat(40),
  AUTH_ENC_KEY: "cd".repeat(32),
  AUTH_MODE: "local",
  AUTH_MFA: "off",
});

const { mfaDisabled, mfaRequired } = await import("@/lib/env");
const { MfaOffBanner } = await import("./mfa-banner");
const health = await import("@/app/api/health/route");

describe("AUTH_MFA helpers", () => {
  it("required is the default; off only switches local sign-in", () => {
    expect(mfaRequired({ AUTH_MFA: "required" })).toBe(true);
    expect(mfaRequired({ AUTH_MFA: "off" })).toBe(false);
    type Env = import("@/lib/env").Env;
    const base = { NODE_ENV: "production", AUTH_MODE: "local" } as Env;
    expect(mfaDisabled({ ...base, AUTH_MFA: "off" })).toBe(true);
    expect(mfaDisabled({ ...base, AUTH_MFA: "required" })).toBe(false);
    expect(mfaDisabled({ ...base, AUTH_MODE: "oidc" as const, AUTH_MFA: "off" })).toBe(false); // the IdP does MFA
  });
});

describe("with AUTH_MFA=off", () => {
  it("/api/health reports mfa: off", async () => {
    const body = (await (await health.GET()).json()) as { status: string; mfa: string };
    expect(body).toEqual({ status: "ok", mfa: "off" });
  });

  it("shows the warning banner to admins only", async () => {
    ctx.user = { id: "a", role: "ADMIN", upn: "a@pg.test", name: "A", tenantId: null };
    const banner = await MfaOffBanner();
    expect(banner).not.toBeNull();
    expect(JSON.stringify(banner)).toContain("Two-factor sign-in is OFF — turn AUTH_MFA=required on before go-live.");
    ctx.user = { id: "b", role: "AUDITOR", upn: "b@pg.test", name: "B", tenantId: null };
    expect(await MfaOffBanner()).toBeNull();
    ctx.user = null;
    expect(await MfaOffBanner()).toBeNull();
  });
});
