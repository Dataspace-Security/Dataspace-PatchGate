import { prisma } from "@/lib/db";
import { appendAudit } from "@/lib/audit/service";
import { createTenant, createTenantSchema } from "@/lib/auth/admin-service";
import type { SessionUser } from "@/lib/auth/session";
import { ENROLL_CODE_TTL_MS, enrollCodeHash, generateEnrollCode, siteNameSchema } from "@/lib/connector/enroll";
import { withPlatform } from "@/lib/tenancy";

/** The installer acts as platform staff (audited as "cli:bank-install"), like scripts/admin/create-user.ts. */
const INSTALLER: SessionUser = { id: "cli-bank-install", role: "ADMIN", upn: "cli:bank-install", name: "Bank installer", tenantId: null } as SessionUser;

const out = (s: string) => process.stdout.write(`${s}\n`);
const err = (s: string) => process.stderr.write(`${s}\n`);

async function tenant(slug: string, name: string): Promise<number> {
  const input = createTenantSchema.parse({ slug, name });
  const existing = await prisma.tenant.findUnique({ where: { slug: input.slug }, select: { id: true } });
  if (existing) {
    out(`BANKWIRE_TENANT=${existing.id}`);
    return 0;
  }
  const t = await createTenant(INSTALLER, input);
  out(`BANKWIRE_TENANT=${t.id}`);
  return 0;
}

async function enrol(tenantId: string, siteName: string): Promise<number> {
  const name = siteNameSchema.parse(siteName);
  const fingerprint = (process.env.FP ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) {
    err("env FP must be the 64-hex job-signing key fingerprint");
    return 2;
  }
  const now = new Date();
  const code = generateEnrollCode();
  const expiresAt = new Date(now.getTime() + ENROLL_CODE_TTL_MS);
  await withPlatform(async (tx) => {
    const t = await tx.tenant.findUnique({ where: { id: tenantId }, select: { active: true } });
    if (!t) throw new Error("bank not found");
    if (!t.active) throw new Error("bank is deactivated");
    // Same as Connectors -> Add site: older unused codes for this site are withdrawn.
    await tx.connectorEnrollment.updateMany({ where: { tenantId, name, usedAt: null, expiresAt: { gt: now } }, data: { expiresAt: now } });
    await tx.connectorEnrollment.create({ data: { id: enrollCodeHash(code), tenantId, name, createdBy: INSTALLER.upn, expiresAt } });
    await appendAudit(
      {
        tenantId,
        actor: INSTALLER.upn,
        action: "connector.enrollment_created",
        entity: "ConnectorEnrollment",
        entityId: enrollCodeHash(code).slice(0, 16),
        payload: { name, expiresAt: expiresAt.toISOString(), jobKeyFingerprint: fingerprint, via: "bank-install" },
      },
      tx,
    );
  });
  out(`BANKWIRE_ENROL=${JSON.stringify({ code, fingerprint })}`);
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  try {
    const [cmd, a, b] = argv;
    if (cmd === "tenant" && a && b) return await tenant(a, b);
    if (cmd === "enrol" && a && b) return await enrol(a, b);
    err('usage: bank-wire.ts tenant <slug> "<name>" | enrol <tenantId> "<site name>"');
    return 2;
  } finally {
    await prisma.$disconnect();
  }
}
