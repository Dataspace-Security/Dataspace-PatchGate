/** Shared setup for *.int.test.ts — always targets a dedicated patchgate_test database. */

export function configureTestEnv(extra: Record<string, string> = {}): void {
  const db = process.env.TEST_DATABASE_URL ?? "";
  if (!/patchgate_test/.test(db)) {
    throw new Error("Refusing to run: TEST_DATABASE_URL must point at a *patchgate_test* database");
  }
  Object.assign(process.env, {
    DATABASE_URL: db,
    NODE_ENV: "test",
    TACTICAL_API_URL: "https://tactical.test.local",
    TACTICAL_API_KEY: "k".repeat(32),
    PATCH_REPO_URL: "https://patchgate.test.local/repo",
    AUDIT_HMAC_KEY: "h".repeat(40),
    WORKER_TOKEN: "w".repeat(40),
    // local mode (the production default) needs AUTH_ENC_KEY (encrypts notification webhook URLs at rest)
    AUTH_ENC_KEY: "cd".repeat(32),
    ...extra,
  });
}

/** Banks present after every resetDb(): A = the legacy bank on the direct Tactical link, B = a second bank. */
export const TENANT_A = "tenant-default";
export const TENANT_B = "tenant-bank-b";

// Children before parents (the delete runs with FK triggers off, but keep it readable).
const TABLES = [
  "TenantApp",
  "ConnectorJob",
  "ConnectorEnrollment",
  "ConnectorNonce",
  "Connector",
  "DiscoveredApp",
  "InstalledSoftware",
  "AuditEvent",
  "AuditAnchor",
  "AuditVerifyCheckpoint",
  "Deployment",
  "ChangeRequestApproval",
  "ChangeRequestTarget",
  "ChangeRequestPatch",
  "ChangeRequest",
  "EndpointPatchState",
  "Endpoint",
  "MaintenanceWindow",
  "Ring",
  "Patch",
  "AppVersion",
  "App",
  "Session",
  "AuthChallenge",
  "OidcLogin",
  "User",
  "MirroredRelease",
  "FetchRun",
  "WorkerLease",
  "WinUpdateFile",
  "WinUpdate",
  "WsusScanCab",
  "NotificationOptOut",
  "NotificationAlert",
  "NotificationSetting",
  "Notification",
  "ConnectorOutage",
  "TacticalActivity",
  "SecurityPolicy",
  "Tenant",
];

interface RawTx {
  $executeRawUnsafe(sql: string): Promise<number>;
}
interface RawDb extends RawTx {
  $transaction<T>(fn: (tx: RawTx) => Promise<T>, options?: { timeout?: number; maxWait?: number }): Promise<T>;
}

/**
 * Empty every table and recreate the two banks (TENANT_A, TENANT_B; bank approval required by default).
 * DELETE with session_replication_role = replica (transaction-local, superuser test DB) skips the
 * append-only triggers and FK checks — much faster than TRUNCATE, which fsyncs new files per table.
 */
export async function resetDb(db: RawDb): Promise<void> {
  await db.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SET LOCAL session_replication_role = replica`);
    for (const t of TABLES) await tx.$executeRawUnsafe(`DELETE FROM "${t}"`);
    await tx.$executeRawUnsafe(
      `INSERT INTO "Tenant" ("id", "slug", "name") VALUES ('${TENANT_A}', 'default', 'Default bank'), ('${TENANT_B}', 'bank-b', 'Demo Bank B')`,
    );
    // Generous limits: the shared dev Postgres is slow under a full sequential run (Prisma default 5 s).
  }, { timeout: 60_000, maxWait: 30_000 });
  // Self-heal: an aborted run may have left the append-only triggers disabled (see asDbAttacker).
  await db.$executeRawUnsafe(`ALTER TABLE "AuditEvent" ENABLE TRIGGER ALL`);
  await db.$executeRawUnsafe(`ALTER TABLE "AuditAnchor" ENABLE TRIGGER ALL`);
}

/** Session-user shape for service calls (tenantId null = PatchGate staff). */
export function asSessionUser(u: { id: string; role: import("@/lib/auth/roles").Role; upn: string; name: string; tenantId: string | null }) {
  return { id: u.id, role: u.role, upn: u.upn, name: u.name, tenantId: u.tenantId };
}

/** Simulate an attacker with DB superuser rights (bypasses append-only triggers). */
export async function asDbAttacker(db: RawDb, sql: string): Promise<void> {
  await db.$executeRawUnsafe(`ALTER TABLE "AuditEvent" DISABLE TRIGGER ALL`);
  try {
    await db.$executeRawUnsafe(sql);
  } finally {
    await db.$executeRawUnsafe(`ALTER TABLE "AuditEvent" ENABLE TRIGGER ALL`);
  }
}
