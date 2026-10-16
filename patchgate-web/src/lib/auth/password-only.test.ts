/**
 * Guard: local sign-in is password-only by design (TOTP removed). No TOTP route, column, env switch, admin action
 * or notification may come back unnoticed. Scans the app sources, the Prisma schema and the admin scripts
 * (historical SQL migrations are excluded: they legitimately created and then dropped the columns).
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(__dirname, "..", "..", "..");
const SELF = relative(ROOT, __filename).replace(/\\/g, "/");
/** Tests that assert the ABSENCE of these identifiers. */
const ALLOWED = new Set([SELF, "src/test/auth-password-only.int.test.ts"]);
const SCAN = ["src", "scripts", "prisma/schema.prisma", ".env.example"];
const EXT = /\.(ts|tsx|mjs|js|prisma)$|\.env\.example$/;

const FORBIDDEN: readonly RegExp[] = [
  /totpSecretEnc|totpEnabled|totpLastStep|pendingSecretEnc/, // User / AuthChallenge columns
  /verifyTotp|generateTotpSecret|otpauth/i, // TOTP code + enrolment
  /\/api\/auth\/totp|auth\/totp/, // the sign-in step route
  /AUTH_MFA|mfaRequired|mfaDisabled|MfaOffBanner|mfa-status|auth\.mfa_/, // the AUTH_MFA switch, banner, audit events
  /reset-mfa|MFA_RESET|user\.mfa_reset/, // admin action + notification
  /from "qrcode"/, // QR enrolment
];

function files(path: string): string[] {
  const abs = join(ROOT, path);
  if (!existsSync(abs)) return [];
  if (statSync(abs).isFile()) return [path];
  return readdirSync(abs).flatMap((name) => files(`${path}/${name}`));
}

describe("password-only local sign-in", () => {
  it("has no TOTP sign-in route", () => {
    expect(existsSync(join(ROOT, "src/app/api/auth/totp"))).toBe(false);
    expect(existsSync(join(ROOT, "src/lib/auth/totp.ts"))).toBe(false);
  });

  it("no TOTP / MFA-switch identifier remains in sources, schema or scripts", () => {
    const hits: string[] = [];
    for (const f of SCAN.flatMap(files)) {
      if (ALLOWED.has(f) || !EXT.test(f)) continue;
      readFileSync(join(ROOT, f), "utf8")
        .split("\n")
        .forEach((line, i) => {
          if (FORBIDDEN.some((re) => re.test(line))) hits.push(`${f}:${i + 1}: ${line.trim().slice(0, 120)}`);
        });
    }
    expect(hits).toEqual([]);
  });
});
