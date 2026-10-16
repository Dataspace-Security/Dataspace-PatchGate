/**
 * The PatchGate role model — ONE place for who may do what (pure: no I/O, safe in client components).
 *
 * Two roles, the same for our team (tenantId = null) and inside every bank:
 *  - ADMIN   does everything in its scope. Platform ADMIN: every bank, raises change requests (maker).
 *            Bank ADMIN: its bank's users and settings, raises requests AND approves them (the bank's checker).
 *  - AUDITOR read-only in its scope (platform AUDITOR: every bank; bank AUDITOR: its own bank). Never changes
 *            anything (only its own password / sessions) and never sees one-time secrets.
 * Maker ≠ checker always; every change request needs ≥ 1 approving ADMIN of the request's own bank
 * (state-machine.ts). VIEWER / OPERATOR / APPROVER are retired values the database refuses (User_role_scope).
 */

export const ACTIVE_ROLES = ["ADMIN", "AUDITOR"] as const;
export type ActiveRole = (typeof ACTIVE_ROLES)[number];

/** Retired enum values: kept only because Postgres cannot drop enum values; never granted, no rights. */
export type RetiredRole = "VIEWER" | "OPERATOR" | "APPROVER";

/** Every value the database enum knows (mirrors prisma UserRole). */
export type Role = ActiveRole | RetiredRole;

export type RoleScope = "platform" | "bank";

export interface RoleHolder {
  role: Role;
  /** null = our team (platform staff); otherwise the user's bank */
  tenantId: string | null;
}

export function scopeOf(user: Pick<RoleHolder, "tenantId">): RoleScope {
  return user.tenantId === null ? "platform" : "bank";
}

/** Roles that can be granted in a scope (the same two everywhere — kept as a function for one call site). */
export function rolesFor(scope: RoleScope): readonly ActiveRole[] {
  void scope;
  return ACTIVE_ROLES;
}

export function isActiveRole(role: unknown): role is ActiveRole {
  return typeof role === "string" && (ACTIVE_ROLES as readonly string[]).includes(role);
}

export function isAdmin(user: Pick<RoleHolder, "role">): boolean {
  return user.role === "ADMIN";
}

export function isAuditor(user: Pick<RoleHolder, "role">): boolean {
  return user.role === "AUDITOR";
}

/** May change anything at all (every POST/PATCH/PUT/DELETE except the user's own password / sessions). */
export function canWrite(user: Pick<RoleHolder, "role">): boolean {
  return isAdmin(user);
}

/** May read the pages / lists of its scope (admins and auditors; retired roles: nothing). */
export function canRead(user: Pick<RoleHolder, "role">): boolean {
  return isActiveRole(user.role);
}

/** May raise (make), submit and deploy change requests. */
export function canMake(user: Pick<RoleHolder, "role">): boolean {
  return isAdmin(user);
}

/**
 * May decide (approve / reject) a request of bank `tenantId` as its bank checker: an ADMIN of that bank.
 * (A platform ADMIN can only be the SECOND approver of a two-approver request — see state-machine.ts.)
 */
export function canCheck(user: RoleHolder, tenantId: string): boolean {
  return isAdmin(user) && user.tenantId === tenantId;
}

/** Platform staff reading across banks (operations, banks list, every bank's audit chain). */
export function isPlatformReader(user: RoleHolder): boolean {
  return user.tenantId === null && canRead(user);
}

export const ROLE_LABEL: Readonly<Record<Role, string>> = Object.freeze({
  ADMIN: "Admin",
  AUDITOR: "Auditor (read-only)",
  APPROVER: "Retired role (no access)",
  OPERATOR: "Retired role (no access)",
  VIEWER: "Retired role (no access)",
});

const DESCRIPTION: Readonly<Record<RoleScope, Readonly<Record<ActiveRole, string>>>> = Object.freeze({
  platform: Object.freeze({
    ADMIN: "Manages every bank: banks, users, connectors, apps and patches; raises change requests.",
    AUDITOR: "Read-only across every bank: lists, audit log, reports and operations. Cannot change anything.",
  }),
  bank: Object.freeze({
    ADMIN: "Manages this bank's users and settings, raises change requests and approves them (checker).",
    AUDITOR: "Read-only within this bank: endpoints, patches, requests, audit log and reports.",
  }),
});

/** One-line description of a role in a scope (role pickers, /account). */
export function roleDescription(role: Role, scope: RoleScope): string {
  return isActiveRole(role) ? DESCRIPTION[scope][role] : "This role was retired; ask an administrator to assign Admin or Auditor.";
}

/** Role picker options for a scope: value, label, one-line description. */
export function roleOptions(scope: RoleScope): { value: ActiveRole; label: string; description: string }[] {
  return rolesFor(scope).map((r) => ({ value: r, label: ROLE_LABEL[r], description: roleDescription(r, scope) }));
}
