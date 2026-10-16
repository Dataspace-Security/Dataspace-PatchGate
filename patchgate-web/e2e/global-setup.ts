import { execFileSync } from "node:child_process";
import { PrismaClient } from "@prisma/client";
import { E2E_DB } from "../playwright.config";

/** Reset the dedicated E2E database and load the standard dev seed. */
export default async function globalSetup(): Promise<void> {
  if (!/patchgate_e2e/.test(E2E_DB)) throw new Error("Refusing to reset: E2E database must be patchgate_e2e");
  execFileSync("npx", ["prisma", "migrate", "deploy"], { env: { ...process.env, DATABASE_URL: E2E_DB }, stdio: "ignore", shell: true });

  const db = new PrismaClient({ datasources: { db: { url: E2E_DB } } });
  const tables = await db.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`;
  await db.$executeRawUnsafe(`ALTER TABLE "AuditEvent" DISABLE TRIGGER ALL`);
  await db.$executeRawUnsafe(`ALTER TABLE "AuditAnchor" DISABLE TRIGGER ALL`);
  await db.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(",")} CASCADE`);
  await db.$executeRawUnsafe(`ALTER TABLE "AuditEvent" ENABLE TRIGGER ALL`);
  await db.$executeRawUnsafe(`ALTER TABLE "AuditAnchor" ENABLE TRIGGER ALL`);
  await db.$disconnect();

  execFileSync("npx", ["tsx", "prisma/seed.ts"], {
    env: { ...process.env, DATABASE_URL: E2E_DB, NODE_ENV: "development" },
    stdio: "inherit",
    shell: true,
  });
}
