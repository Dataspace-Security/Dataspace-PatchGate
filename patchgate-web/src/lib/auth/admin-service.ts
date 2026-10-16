import { authTx } from "./tx";
import "server-only";
import { enqueueNotification } from "@/lib/notify/enqueue";
import { z } from "zod";
import { Prisma, type UserRole } from "@prisma/client";
import { prisma } from "@/lib/db";
import { DomainError } from "@/lib/errors";
import { appendAudit } from "@/lib/audit/service";
import { withTenant } from "@/lib/tenancy/db";
import { auditAuth } from "./audit";
import { PROMOTION_COOLDOWN_DAYS, recentBankAdminReset } from "./reset-flag";
import { generateTempPassword, hashPassword } from "./password";
import { revokeUserSessions } from "./session-store";
import { ACTIVE_ROLES, canRead } from "./roles";
import { AuthError, type SessionUser } from "./session";

/**
 * User and bank administration.
 * - Platform admin (role ADMIN, tenantId null): all banks, all users (bank users and our team).
 * - Bank admin (role ADMIN, tenantId set): users of their own bank only; never platform users,
 *   never another bank, never moves a user between banks (a user's bank is fixed at creation).
 * - Auditors (role AUDITOR) READ the same lists in their scope (platform: everything; bank: own bank) and
 *   change nothing. Roles: ADMIN / AUDITOR only (lib/auth/roles.ts; DB CHECK User_role_scope).
 * Guards: nobody deactivates or demotes themselves; at least one active platform admin remains.
 * Every change is audited (bank users on their bank's chain, platform users / banks on the platform chain).
 */

type Tx = Prisma.TransactionClient;

// Serialises admin changes that must keep "≥ 1 active platform admin" true under concurrency.
const ADMIN_LOCK_KEY = 4_242_017;

export type AdminScope = "platform" | "bank";

/** ADMIN role required; returns whether the actor administers the platform or one bank. */
export function requireAdmin(actor: SessionUser): AdminScope {
  if (actor.role !== "ADMIN") throw new AuthError("Administrator role required", 403);
  return actor.tenantId === null ? "platform" : "bank";
}

/** ADMIN or AUDITOR (read-only views of the user / bank lists); returns the scope that is visible. */
export function requireAdminReader(actor: SessionUser): AdminScope {
  if (!canRead(actor)) throw new AuthError("Administrator or auditor role required", 403);
  return actor.tenantId === null ? "platform" : "bank";
}

export function requirePlatformAdmin(actor: SessionUser): void {
  if (requireAdmin(actor) !== "platform") throw new AuthError("Platform administrator role required", 403);
}

/** Can `actor` manage a user that belongs to `targetTenantId` (null = our team)? */
export function canManageTenantUsers(actor: Pick<SessionUser, "role" | "tenantId">, targetTenantId: string | null): boolean {
  if (actor.role !== "ADMIN") return false;
  return actor.tenantId === null || actor.tenantId === targetTenantId;
}

// ---------- Schemas ----------

const upnSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(200)
  .regex(/^[^\s@]+@[^\s@]+$/, "use the sign-in name in name@domain form");
const nameSchema = z.string().trim().min(1).max(120);
// Only the two active roles can be granted; the retired VIEWER / OPERATOR / APPROVER are refused here and by the DB.
const roleSchema = z.enum(ACTIVE_ROLES);

export const createUserSchema = z.object({
  upn: upnSchema,
  name: nameSchema,
  role: roleSchema,
  /** null = our team (platform staff). Bank admins may omit it (defaults to their bank). */
  tenantId: z.string().min(1).max(64).nullable().optional(),
});

export const updateUserSchema = z
  .object({ name: nameSchema.optional(), role: roleSchema.optional(), active: z.boolean().optional() })
  .refine((v) => v.name !== undefined || v.role !== undefined || v.active !== undefined, "nothing to change");

export const userActionSchema = z.object({ action: z.enum(["reset-password", "reset-mfa", "unlock"]) });

const slugSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/, "2–40 lower-case letters, digits or dashes");

export const createTenantSchema = z.object({
  slug: slugSchema,
  name: z.string().trim().min(2).max(120),
  active: z.boolean().default(true),
  requireBankApproval: z.literal(true, { error: "a bank approver is always required" }).default(true),
});

export const updateTenantSchema = z
  .object({
    slug: slugSchema.optional(),
    name: z.string().trim().min(2).max(120).optional(),
    active: z.boolean().optional(),
    requireBankApproval: z.literal(true, { error: "a bank approver is always required" }).optional(),
  })
  .refine((v) => Object.values(v).some((x) => x !== undefined), "nothing to change");

// ---------- Views ----------

export interface AdminUserView {
  id: string;
  upn: string;
  name: string;
  role: UserRole;
  tenantId: string | null;
  tenantName: string | null;
  active: boolean;
  totpEnabled: boolean;
  mustChangePassword: boolean;
  hasPassword: boolean;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  createdAt: Date;
}

const userSelect = {
  id: true,
  upn: true,
  name: true,
  role: true,
  tenantId: true,
  active: true,
  totpEnabled: true,
  mustChangePassword: true,
  passwordHash: true,
  lockedUntil: true,
  lastLoginAt: true,
  createdAt: true,
  tenant: { select: { name: true } },
} satisfies Prisma.UserSelect;

type UserRow = Prisma.UserGetPayload<{ select: typeof userSelect }>;

function toView(u: UserRow): AdminUserView {
  return {
    id: u.id,
    upn: u.upn,
    name: u.name,
    role: u.role,
    tenantId: u.tenantId,
    tenantName: u.tenant?.name ?? null,
    active: u.active,
    totpEnabled: u.totpEnabled,
    mustChangePassword: u.mustChangePassword,
    hasPassword: u.passwordHash !== null,
    lockedUntil: u.lockedUntil,
    lastLoginAt: u.lastLoginAt,
    createdAt: u.createdAt,
  };
}

/** Users the actor may see: everyone (platform admin / auditor) or their own bank's users (bank admin / auditor). */
export async function listUsers(actor: SessionUser): Promise<AdminUserView[]> {
  requireAdminReader(actor);
  const rows = await prisma.user.findMany({
    where: actor.tenantId === null ? {} : { tenantId: actor.tenantId },
    orderBy: [{ tenantId: { sort: "asc", nulls: "first" } }, { upn: "asc" }],
    take: 1000,
    select: userSelect,
  });
  return rows.map(toView);
}

export async function listTenants(actor: SessionUser) {
  requireAdminReader(actor);
  return prisma.tenant.findMany({
    where: actor.tenantId === null ? {} : { id: actor.tenantId },
    orderBy: { name: "asc" },
    include: { _count: { select: { users: true } } },
  });
}

// ---------- Users ----------

async function loadManagedUser(tx: Tx, actor: SessionUser, userId: string): Promise<UserRow> {
  const u = await tx.user.findUnique({ where: { id: userId }, select: userSelect });
  // A bank admin gets the same answer for "other bank" and "does not exist" (no cross-bank probing).
  if (!u || !canManageTenantUsers(actor, u.tenantId)) throw new DomainError("User not found", 404);
  return u;
}

async function lockAdmins(tx: Tx): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(${ADMIN_LOCK_KEY})`;
}

/** Throws if removing `target` from the active platform admins would leave none. */
async function assertNotLastPlatformAdmin(tx: Tx, target: UserRow): Promise<void> {
  if (target.tenantId !== null || target.role !== "ADMIN" || !target.active) return;
  const others = await tx.user.count({ where: { role: "ADMIN", tenantId: null, active: true, id: { not: target.id } } });
  if (others === 0) throw new DomainError("At least one active platform administrator must remain.", 409);
}

export interface CreatedUser {
  user: AdminUserView;
  /** Shown to the administrator exactly once; only its scrypt hash is stored. */
  temporaryPassword: string;
}

export async function createUser(actor: SessionUser, raw: z.input<typeof createUserSchema>): Promise<CreatedUser> {
  const scope = requireAdmin(actor);
  const input = createUserSchema.parse(raw); // idempotent; normalises the UPN for non-HTTP callers too
  let tenantId: string | null;
  if (scope === "bank") {
    if (input.tenantId !== undefined && input.tenantId !== actor.tenantId) {
      throw new AuthError("Bank administrators can only create users of their own bank", 403);
    }
    tenantId = actor.tenantId;
  } else {
    if (input.tenantId === undefined) throw new DomainError("Choose a bank, or our team", 400);
    tenantId = input.tenantId;
  }

  const temporaryPassword = generateTempPassword();
  const passwordHash = await hashPassword(temporaryPassword);
  try {
    const user = await authTx(async (tx) => {
      if (tenantId !== null) {
        const tenant = await tx.tenant.findUnique({ where: { id: tenantId } });
        if (!tenant) throw new DomainError("Bank not found", 404);
      }
      const created = await tx.user.create({
        data: { upn: input.upn, name: input.name, role: input.role, tenantId, passwordHash, passwordChangedAt: new Date(), mustChangePassword: true },
        select: userSelect,
      });
      await auditAuth(
        { actor: actor.upn, action: "user.created", entity: "User", entityId: created.id, payload: { upn: created.upn, role: created.role, tenantId }, tenantId },
        tx,
      );
      return created;
    });
    return { user: toView(user), temporaryPassword };
  } catch (err: unknown) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") throw new DomainError("A user with this sign-in name already exists", 409);
    throw err;
  }
}

export async function updateUser(actor: SessionUser, userId: string, input: z.infer<typeof updateUserSchema>): Promise<AdminUserView> {
  requireAdmin(actor);
  const self = userId === actor.id;
  if (self && input.active === false) throw new DomainError("You cannot deactivate your own account.", 409);
  if (self && input.role !== undefined && input.role !== "ADMIN") throw new DomainError("You cannot remove your own administrator role.", 409);
  if (requireAdmin(actor) === "bank" && input.role !== undefined && PRIVILEGED_ROLES.includes(input.role)) {
    const target = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, tenantId: true, role: true } });
    if (target && canManageTenantUsers(actor, target.tenantId) && !PRIVILEGED_ROLES.includes(target.role) && (await recentBankAdminReset(target))) {
      throw new AuthError(`This user's credentials were reset by a bank administrator in the last ${PROMOTION_COOLDOWN_DAYS} days; a PatchGate platform administrator must grant the admin role.`, 403);
    }
  }

  return authTx(async (tx) => {
    await lockAdmins(tx);
    const before = await loadManagedUser(tx, actor, userId);
    const deactivating = input.active === false && before.active;
    const demoting = input.role !== undefined && input.role !== "ADMIN" && before.role === "ADMIN";
    if (deactivating || demoting) await assertNotLastPlatformAdmin(tx, before);

    const after = await tx.user.update({
      where: { id: userId },
      data: { name: input.name, role: input.role, active: input.active },
      select: userSelect,
    });
    const killed = deactivating ? await revokeUserSessions(tx, userId) : 0;
    const changes: Record<string, { from: string | boolean; to: string | boolean }> = {};
    if (input.name !== undefined && input.name !== before.name) changes.name = { from: before.name, to: after.name };
    if (input.role !== undefined && input.role !== before.role) changes.role = { from: before.role, to: after.role };
    if (input.active !== undefined && input.active !== before.active) changes.active = { from: before.active, to: after.active };

    const action = changes.active ? (after.active ? "user.reactivated" : "user.deactivated") : "user.updated";
    await auditAuth(
      { actor: actor.upn, action, entity: "User", entityId: userId, payload: { upn: after.upn, changes, sessionsRevoked: killed }, tenantId: after.tenantId },
      tx,
    );
    return toView(after);
  });
}

export type UserAction = z.infer<typeof userActionSchema>["action"];

/** Roles whose credentials a BANK admin may not reset (maker-checker: the admin would learn them). */
export const PRIVILEGED_ROLES: readonly UserRole[] = ["ADMIN"];

/**
 * May `scope` reset the credentials (password / authenticator) of a user with role `targetRole`?
 * Bank admins are the bank's checkers: one who resets ANOTHER bank admin learns the temporary password,
 * enrols their own authenticator and can then act as maker AND checker. So bank admins reset only AUDITOR
 * credentials; resetting an admin needs a PatchGate platform administrator (audited on the bank's chain).
 * Unlock reveals nothing and stays with the bank admin.
 */
export function canResetCredentials(scope: AdminScope, action: UserAction, targetRole: UserRole): boolean {
  if (action === "unlock" || scope === "platform") return true;
  return !PRIVILEGED_ROLES.includes(targetRole);
}

/** Reset password (new one-time temporary password), reset MFA (re-enrol at next sign-in) or unlock. */
export async function userAction(actor: SessionUser, userId: string, action: UserAction): Promise<{ user: AdminUserView; temporaryPassword: string | null }> {
  const scope = requireAdmin(actor);
  const temporaryPassword = action === "reset-password" ? generateTempPassword() : null;
  const passwordHash = temporaryPassword ? await hashPassword(temporaryPassword) : null;

  const denied = await authTx(async (tx) => {
    const target = await loadManagedUser(tx, actor, userId);
    if (canResetCredentials(scope, action, target.role)) return null;
    // Audited on the bank's chain (the bank SIEM sees the attempt), then refused.
    await auditAuth(
      { actor: actor.upn, action: "user.reset_denied", entity: "User", entityId: userId, payload: { upn: target.upn, targetRole: target.role, requested: action, reason: "admin credentials need a platform administrator" }, tenantId: target.tenantId },
      tx,
    );
    return target.role;
  });
  if (denied) throw new AuthError(`Resetting the credentials of an ${denied.toLowerCase()} requires a PatchGate platform administrator.`, 403);

  return authTx(async (tx) => {
    const target = await loadManagedUser(tx, actor, userId);
    if (!canResetCredentials(scope, action, target.role)) throw new DomainError("Role changed concurrently; try again.", 409);
    const data: Prisma.UserUpdateInput =
      action === "reset-password"
        ? { passwordHash, passwordChangedAt: new Date(), mustChangePassword: true, failedLogins: 0, lockedUntil: null }
        : action === "reset-mfa"
          ? { totpSecretEnc: null, totpEnabled: false, totpLastStep: null }
          : { failedLogins: 0, lockedUntil: null };
    const after = await tx.user.update({ where: { id: userId }, data, select: userSelect });
    const killed = action === "unlock" ? 0 : await revokeUserSessions(tx, userId);
    const auditAction = { "reset-password": "user.password_reset", "reset-mfa": "user.mfa_reset", unlock: "user.unlocked" }[action];
    // Always the user's own chain (the bank's chain for bank users); the next sign-in is flagged afterReset.
    await auditAuth(
      {
        actor: actor.upn,
        action: auditAction,
        entity: "User",
        entityId: userId,
        payload: { upn: target.upn, targetRole: target.role, sessionsRevoked: killed, byPlatformAdmin: scope === "platform", nextLoginFlagged: action !== "unlock" },
        tenantId: target.tenantId,
      },
      tx,
    );
    if (action !== "unlock") await enqueueNotification(tx, { event: action === "reset-password" ? "PASSWORD_RESET" : "MFA_RESET", userId, actor: actor.upn });
    return { user: toView(after), temporaryPassword };
  });
}

// ---------- Banks (platform admins only) ----------

function uniqueSlug(err: unknown): never {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") throw new DomainError("A bank with this short code already exists", 409);
  throw err;
}

export async function createTenant(actor: SessionUser, input: z.infer<typeof createTenantSchema>) {
  requirePlatformAdmin(actor);
  try {
    const t = await authTx(async (tx) => {
      const created = await tx.tenant.create({ data: input });
      await auditAuth({ actor: actor.upn, action: "tenant.created", entity: "Tenant", entityId: created.id, payload: { ...input }, tenantId: null }, tx);
      return created;
    });
    // Every bank starts with the standard rollout rings (test → pilot → production) so change requests
    // can be created immediately. Rings are tenant data: created inside the bank's RLS scope.
    await withTenant(t.id, async (tx) => {
      await tx.ring.createMany({ data: DEFAULT_RINGS.map((r) => ({ ...r, tenantId: t.id })), skipDuplicates: true });
      await appendAudit({ actor: actor.upn, action: "ring.defaults_created", entity: "Tenant", entityId: t.id, payload: { rings: DEFAULT_RINGS.map((r) => r.name) }, tenantId: t.id }, tx);
    });
    return t;
  } catch (err: unknown) {
    return uniqueSlug(err);
  }
}

const DEFAULT_RINGS = [
  { name: "Ring0-Test", wsusGroup: "Ring0-Test", order: 0 },
  { name: "Ring1-Pilot", wsusGroup: "Ring1-Pilot", order: 1 },
  { name: "Ring2-Prod", wsusGroup: "Ring2-Prod", order: 2 },
] as const;

export async function updateTenant(actor: SessionUser, tenantId: string, input: z.infer<typeof updateTenantSchema>) {
  requirePlatformAdmin(actor);
  try {
    return await authTx(async (tx) => {
      const before = await tx.tenant.findUnique({ where: { id: tenantId } });
      if (!before) throw new DomainError("Bank not found", 404);
      const after = await tx.tenant.update({ where: { id: tenantId }, data: input });
      // Deactivating a bank signs all of its users out immediately (getCurrentUser also refuses them).
      let sessionsRevoked = 0;
      if (before.active && !after.active) {
        const r = await tx.session.deleteMany({ where: { user: { tenantId } } });
        await tx.authChallenge.deleteMany({ where: { userId: { in: (await tx.user.findMany({ where: { tenantId }, select: { id: true } })).map((u) => u.id) } } });
        sessionsRevoked = r.count;
      }
      const changes = Object.fromEntries(
        (Object.keys(input) as (keyof typeof input)[])
          .filter((k) => input[k] !== undefined && input[k] !== before[k])
          .map((k) => [k, { from: before[k], to: after[k] }]),
      );
      await auditAuth({ actor: actor.upn, action: "tenant.updated", entity: "Tenant", entityId: tenantId, payload: { slug: after.slug, changes, sessionsRevoked }, tenantId: null }, tx);
      return after;
    });
  } catch (err: unknown) {
    return uniqueSlug(err);
  }
}
