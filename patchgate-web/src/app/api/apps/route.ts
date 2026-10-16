import { z } from "zod";
import { prisma } from "@/lib/db";
import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { appendAudit } from "@/lib/audit/service";
import { DomainError } from "@/lib/errors";
import { PUBLISHER_PIN_RE } from "@/lib/fetch/dn";
import { WINGET_ID_RE } from "@/lib/fetch/winget";
import { safeRegexSchema } from "@/lib/safe-regex";
import { requirePlatformAdmin } from "@/lib/tenancy";

const HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
// Download hosts must be public vendor hosts — never names that point into the bank network.
// (The fetcher additionally refuses any host that resolves to a private/loopback address.)
const INTERNAL_SUFFIXES = [".local", ".localhost", ".internal", ".intranet", ".corp", ".lan", ".home", ".bank", ".test", ".invalid"];
const publicHost = z
  .string()
  .toLowerCase()
  .regex(HOST, "hostname only")
  .refine((h) => !INTERNAL_SUFFIXES.some((s) => h.endsWith(s)), "internal hostnames are not allowed");

const appSchema = z.object({
  wingetId: z.string().regex(WINGET_ID_RE, "winget id, e.g. Google.Chrome or Notepad++.Notepad++"),
  displayName: z.string().trim().min(2).max(100),
  // Runs against EVERY bank's inventory: must be a valid AND backtracking-safe regex (ReDoS guard).
  inventoryMatch: safeRegexSchema,
  // Optional: when empty, the first download's signer is HELD for an admin to approve (and then pinned).
  expectedPublisher: z
    .string()
    .trim()
    .regex(PUBLISHER_PIN_RE, 'exact organisation, e.g. "O=Google LLC"')
    .or(z.literal("").transform(() => null))
    .nullish()
    .transform((v) => v ?? null),
  // Optional: when empty, the first hop is the vendor host named in the winget manifest.
  allowedDomains: z.array(publicHost).max(10).default([]),
  strictHosts: z.boolean().default(false),
  allowHashDrift: z.boolean().default(false),
}).refine((a) => !a.strictHosts || a.allowedDomains.length > 0, {
  path: ["allowedDomains"],
  message: "strict host mode needs at least one allowed host",
});

/**
 * Add an app to the SHARED third-party allow-list (platform admins only; platform audit chain).
 * Banks then opt in per app (/api/apps/[id]/enable).
 */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    requirePlatformAdmin(user);
    const input = appSchema.parse(await req.json());
    if (await prisma.app.findUnique({ where: { wingetId: input.wingetId } })) {
      throw new DomainError("App already on the allow-list", 409);
    }
    const app = await prisma.$transaction(async (tx) => {
      const a = await tx.app.create({ data: input });
      await appendAudit({ actor: user.upn, action: "app.allowlist_add", entity: "App", entityId: a.id, payload: input }, tx);
      return a;
    });
    return ok(app, 201);
  });
}
