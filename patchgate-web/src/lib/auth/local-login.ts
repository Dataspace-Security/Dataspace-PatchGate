import { authTx } from "./tx";
import "server-only";
import { enqueueNotification } from "@/lib/notify/enqueue";
import { z } from "zod";
import QRCode from "qrcode";
import type { AuthChallenge, Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { describeError } from "@/lib/errors-describe";
import { auditAuth } from "./audit";
import { credentialResetSinceLastLogin, type CredentialReset } from "./reset-flag";
import { recordUnknownUserFailure } from "./unknown-login-summary";
import { safeReturnTo } from "./claims";
import { LOCKOUT_MINUTES, failureOutcome, isLocked } from "./lockout";
import { checkPasswordPolicy, dummyPasswordHash, hashPassword, verifyPassword, PASSWORD_MAX } from "./password";
import { authKeyring } from "./enc-keys";
import { encryptSecret, openSecret } from "./secret-box";
import { createSession, type ClientMeta } from "./session-store";
import { passwordExpired } from "@/lib/policies/account-policy";
import { getSecurityPolicy } from "@/lib/policies/security-store";
import { randomToken, sha256Hex } from "./tokens";
import { base32Encode, generateTotpSecret, groupSecret, otpauthUri, verifyTotp } from "./totp";

/**
 * Local sign-in (AUTH_MODE=local): password → TOTP (enrol on first use) → optional forced password
 * change → server-side session. Each step is bound to a short-lived, single-use AuthChallenge whose
 * token lives only in an HttpOnly cookie. Messages are deliberately generic; reasons go to the audit log.
 */

type Tx = Prisma.TransactionClient;

export const CHALLENGE_TTL_MS = 5 * 60_000;
export const MAX_CHALLENGE_ATTEMPTS = 5;
const TOTP_ISSUER = "PatchGate";

export const LOGIN_ERROR = "Invalid username or password.";
export const CODE_ERROR = "Invalid verification code.";
export const RESTART_ERROR = "Your sign-in attempt has expired or was cancelled. Please sign in again.";

type ChallengeKind = "VERIFY" | "ENROLL" | "PASSWORD";

export const passwordLoginSchema = z.object({
  upn: z.string().trim().toLowerCase().min(1).max(200),
  password: z.string().min(1).max(1024),
  returnTo: z.string().max(512).nullish(),
});
export const totpCodeSchema = z.object({ code: z.string().trim().regex(/^\d{6}$/, "enter the 6-digit code") });
export const changePasswordSchema = z.object({ newPassword: z.string().min(1).max(PASSWORD_MAX * 4) });

export type LoginStep =
  | { ok: false; error: string; restart: boolean; status: 400 | 401 }
  | { ok: true; step: "verify"; challengeToken: string }
  | { ok: true; step: "enroll"; challengeToken: string; secret: string; otpauthUri: string; qrSvgDataUrl: string }
  | { ok: true; step: "change-password"; challengeToken: string }
  | { ok: true; step: "done"; sessionToken: string; returnTo: string };

const failed = (error: string, restart = false, status: 400 | 401 = 401): LoginStep => ({ ok: false, error, restart, status });

/** A concurrent request consumed the challenge or the TOTP step first. */
class LoginRace extends Error {}

/** Encrypt with the current key only; decrypt also accepts AUTH_ENC_KEY_PREVIOUS (rotation, RUNBOOK §9.4). */
const encKey = (): string => authKeyring().current;

export interface UserRef {
  id: string;
  upn: string;
  tenantId: string | null;
}

/** Count a failed step (password or code); the 5th consecutive failure locks the account (audited). */
export async function registerFailure(user: UserRef, reason: string, meta: ClientMeta, now: Date): Promise<boolean> {
  return authTx(async (tx) => {
    const u = await tx.user.update({ where: { id: user.id }, data: { failedLogins: { increment: 1 } }, select: { failedLogins: true } });
    const o = failureOutcome(u.failedLogins, now);
    await auditAuth({ actor: user.upn, action: "auth.failed", entity: "User", entityId: user.id, payload: { reason, failedLogins: u.failedLogins, ip: meta.ip }, tenantId: user.tenantId }, tx);
    if (o.lockedNow) {
      await tx.user.update({ where: { id: user.id }, data: { failedLogins: o.failedLogins, lockedUntil: o.lockedUntil } });
      await tx.authChallenge.deleteMany({ where: { userId: user.id } });
      await auditAuth(
        { actor: user.upn, action: "auth.lockout", entity: "User", entityId: user.id, payload: { minutes: LOCKOUT_MINUTES, until: o.lockedUntil?.toISOString() ?? null, ip: meta.ip }, tenantId: user.tenantId },
        tx,
      );
      await enqueueNotification(tx, { event: "ACCOUNT_LOCKED", userId: user.id, until: o.lockedUntil });
    }
    return o.lockedNow;
  });
}

async function newChallenge(tx: Tx, userId: string, kind: ChallengeKind, returnTo: string, now: Date, pendingSecretEnc: string | null = null): Promise<string> {
  const token = randomToken();
  await tx.authChallenge.deleteMany({ where: { userId } }); // one sign-in in flight per user
  await tx.authChallenge.create({
    data: { id: sha256Hex(token), userId, kind, pendingSecretEnc, returnTo, expiresAt: new Date(now.getTime() + CHALLENGE_TTL_MS) },
  });
  return token;
}

/**
 * Final step: clear failure state, issue the session, audit the login. The first login after an administrator
 * reset this user's password or authenticator carries afterReset=true (+ who reset it) for SIEM alerting.
 */
async function completeLogin(tx: Tx, user: UserRef, method: string, meta: ClientMeta, now: Date, reset: CredentialReset | null): Promise<string> {
  await tx.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null, lastLoginAt: now } });
  const token = await createSession(tx, { userId: user.id, now, meta });
  const flag = reset ? { afterReset: true, resetAction: reset.action, resetBy: reset.actor, resetAt: reset.ts.toISOString() } : {};
  await auditAuth({ actor: user.upn, action: "auth.login", entity: "User", entityId: user.id, payload: { method, ip: meta.ip, ...flag }, tenantId: user.tenantId }, tx);
  return token;
}

/** Step 1: username + password. */
export async function beginPasswordLogin(input: z.infer<typeof passwordLoginSchema>, meta: ClientMeta, now = new Date()): Promise<LoginStep> {
  const user = await prisma.user.findUnique({ where: { upn: input.upn }, include: { tenant: { select: { active: true } } } });
  const deny = async (reason: string, ref: UserRef | null) => {
    // Unknown names are attacker-supplied: counted into a periodic summary, never audited one by one.
    if (ref === null) await recordUnknownUserFailure(meta.ip, now.getTime());
    else await auditAuth({ actor: ref.upn, action: "auth.failed", entity: "User", entityId: ref.id, payload: { reason, ip: meta.ip }, tenantId: ref.tenantId });
    return failed(LOGIN_ERROR);
  };

  // Unknown user / no local password / locked: still pay for one scrypt so timing reveals nothing.
  if (!user || !user.passwordHash) {
    await verifyPassword(input.password, await dummyPasswordHash());
    return deny(user ? "no local password set" : "unknown user", user);
  }
  if (isLocked(user.lockedUntil, now)) {
    await verifyPassword(input.password, await dummyPasswordHash());
    return deny("account locked", user);
  }
  const passwordOk = await verifyPassword(input.password, user.passwordHash);
  if (!user.active) return deny("account deactivated", user);
  if (user.tenant && !user.tenant.active) return deny("bank deactivated", user);
  if (!passwordOk) {
    await registerFailure(user, "wrong password", meta, now);
    return failed(LOGIN_ERROR);
  }

  const returnTo = safeReturnTo(input.returnTo);
  if (user.totpEnabled && user.totpSecretEnc) {
    const challengeToken = await authTx((tx) => newChallenge(tx, user.id, "VERIFY", returnTo, now));
    return { ok: true, step: "verify", challengeToken };
  }

  // First sign-in (or MFA reset by an admin): enrol a new authenticator.
  const secret = generateTotpSecret();
  const secretB32 = base32Encode(secret);
  const pending = encryptSecret(secret, encKey(), user.id);
  const challengeToken = await authTx((tx) => newChallenge(tx, user.id, "ENROLL", returnTo, now, pending));
  const uri = otpauthUri(TOTP_ISSUER, user.upn, secretB32);
  const svg = await QRCode.toString(uri, { type: "svg", errorCorrectionLevel: "M", margin: 1 });
  return {
    ok: true,
    step: "enroll",
    challengeToken,
    secret: groupSecret(secretB32),
    otpauthUri: uri,
    qrSvgDataUrl: `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`,
  };
}

interface LoadedChallenge {
  ch: AuthChallenge;
  user: NonNullable<Awaited<ReturnType<typeof loadUser>>>;
}

function loadUser(id: string) {
  return prisma.user.findUnique({ where: { id }, include: { tenant: { select: { active: true } } } });
}

/** Resolve the cookie to a live challenge of the expected kind for a user who may still sign in. */
async function loadChallenge(token: string | undefined, kinds: readonly ChallengeKind[], now: Date): Promise<LoadedChallenge | null> {
  if (!token) return null;
  const ch = await prisma.authChallenge.findUnique({ where: { id: sha256Hex(token) } });
  if (!ch) return null;
  const user = await loadUser(ch.userId);
  const usable =
    ch.expiresAt > now &&
    kinds.includes(ch.kind as ChallengeKind) &&
    user !== null &&
    user.active &&
    user.tenant?.active !== false &&
    !isLocked(user.lockedUntil, now);
  if (!usable) {
    await prisma.authChallenge.deleteMany({ where: { id: ch.id } });
    return null;
  }
  return { ch, user };
}

/** Count a wrong attempt on the challenge; it dies after MAX_CHALLENGE_ATTEMPTS. Returns true if it died. */
async function burnAttempt(ch: AuthChallenge): Promise<boolean> {
  const r = await prisma.authChallenge.updateMany({ where: { id: ch.id }, data: { attempts: { increment: 1 } } });
  if (r.count === 0) return true;
  if (ch.attempts + 1 >= MAX_CHALLENGE_ATTEMPTS) {
    await prisma.authChallenge.deleteMany({ where: { id: ch.id } });
    return true;
  }
  return false;
}

/** Step 2: TOTP code (verifies an enrolment or an existing authenticator). */
export async function verifyTotpStep(token: string | undefined, code: string, meta: ClientMeta, now = new Date()): Promise<LoginStep> {
  const loaded = await loadChallenge(token, ["VERIFY", "ENROLL"], now);
  if (!loaded) return failed(RESTART_ERROR, true);
  const { ch, user } = loaded;
  const enrolling = ch.kind === "ENROLL";
  const secretEnc = enrolling ? ch.pendingSecretEnc : user.totpEnabled ? user.totpSecretEnc : null;
  if (!secretEnc) {
    await prisma.authChallenge.deleteMany({ where: { id: ch.id } });
    return failed(RESTART_ERROR, true);
  }

  let key: Buffer;
  try {
    key = openSecret(secretEnc, authKeyring(), user.id).plain;
  } catch (err: unknown) {
    console.error("[patchgate] TOTP secret could not be decrypted (AUTH_ENC_KEY changed or data tampered):", describeError(err));
    await prisma.authChallenge.deleteMany({ where: { id: ch.id } });
    await auditAuth({ actor: user.upn, action: "auth.failed", entity: "User", entityId: user.id, payload: { reason: "TOTP secret undecryptable", ip: meta.ip }, tenantId: user.tenantId });
    return failed(RESTART_ERROR, true);
  }

  const step = verifyTotp(key, code, now.getTime(), user.totpLastStep);
  if (step === null) {
    const died = await burnAttempt(ch);
    const locked = await registerFailure(user, enrolling ? "invalid TOTP code (enrolment)" : "invalid TOTP code", meta, now);
    return died || locked ? failed(RESTART_ERROR, true) : failed(CODE_ERROR);
  }

  const reset = user.mustChangePassword ? null : await credentialResetSinceLastLogin(user);
  // Platform policy: a password older than passwordMaxAgeDays must be changed before the session is issued.
  const expired = !user.mustChangePassword && passwordExpired(user, await getSecurityPolicy(), now);
  try {
    return await authTx(async (tx): Promise<LoginStep> => {
      const consumed = await tx.authChallenge.deleteMany({ where: { id: ch.id } });
      if (consumed.count !== 1) throw new LoginRace();
      // Single use per step, enforced atomically: a concurrent request with the same code loses here.
      const marked = await tx.user.updateMany({
        where: { id: user.id, OR: [{ totpLastStep: null }, { totpLastStep: { lt: step } }] },
        data: { totpLastStep: step, ...(enrolling ? { totpSecretEnc: secretEnc, totpEnabled: true } : {}) },
      });
      if (marked.count !== 1) throw new LoginRace();
      if (enrolling) {
        await auditAuth({ actor: user.upn, action: "auth.mfa_enrolled", entity: "User", entityId: user.id, payload: { ip: meta.ip }, tenantId: user.tenantId }, tx);
      }
      if (user.mustChangePassword || expired) {
        if (expired) {
          await auditAuth({ actor: user.upn, action: "auth.password_expired", entity: "User", entityId: user.id, payload: { passwordChangedAt: (user.passwordChangedAt ?? user.createdAt).toISOString(), ip: meta.ip }, tenantId: user.tenantId }, tx);
        }
        const challengeToken = await newChallenge(tx, user.id, "PASSWORD", ch.returnTo, now);
        return { ok: true, step: "change-password", challengeToken };
      }
      const sessionToken = await completeLogin(tx, user, "password+totp", meta, now, reset);
      return { ok: true, step: "done", sessionToken, returnTo: safeReturnTo(ch.returnTo) };
    });
  } catch (err: unknown) {
    if (err instanceof LoginRace) return failed(RESTART_ERROR, true);
    throw err;
  }
}

/** Step 3 (only when an admin issued a temporary password): choose a new password, then sign in. */
export async function changePasswordStep(token: string | undefined, newPassword: string, meta: ClientMeta, now = new Date()): Promise<LoginStep> {
  const loaded = await loadChallenge(token, ["PASSWORD"], now);
  if (!loaded) return failed(RESTART_ERROR, true);
  const { ch, user } = loaded;

  const policy = checkPasswordPolicy(newPassword, user.upn);
  let problem: string | null = policy.ok ? null : policy.reason;
  if (!problem && user.passwordHash && (await verifyPassword(newPassword, user.passwordHash))) {
    problem = "Choose a password different from your current one.";
  }
  if (problem) {
    const died = await burnAttempt(ch);
    return died ? failed(RESTART_ERROR, true) : failed(problem, false, 400);
  }

  const passwordHash = await hashPassword(newPassword);
  const reset = await credentialResetSinceLastLogin(user);
  try {
    return await authTx(async (tx): Promise<LoginStep> => {
      const consumed = await tx.authChallenge.deleteMany({ where: { id: ch.id } });
      if (consumed.count !== 1) throw new LoginRace();
      await tx.user.update({ where: { id: user.id }, data: { passwordHash, passwordChangedAt: now, mustChangePassword: false } });
      await tx.session.deleteMany({ where: { userId: user.id } }); // any older session dies with the old password
      await auditAuth({ actor: user.upn, action: "auth.password_changed", entity: "User", entityId: user.id, payload: { forced: true, ip: meta.ip }, tenantId: user.tenantId }, tx);
      const sessionToken = await completeLogin(tx, user, "password+totp", meta, now, reset);
      return { ok: true, step: "done", sessionToken, returnTo: safeReturnTo(ch.returnTo) };
    });
  } catch (err: unknown) {
    if (err instanceof LoginRace) return failed(RESTART_ERROR, true);
    throw err;
  }
}
