import { parseArgs } from "node:util";
import { z } from "zod";
import { ACTIVE_ROLES } from "@/lib/auth/roles";
import { prisma } from "@/lib/db";
import { auditAuth } from "@/lib/auth/audit";
import { checkPasswordPolicy, generateTempPassword, hashPassword } from "@/lib/auth/password";

const USAGE = `Usage: npx tsx --env-file=.env scripts/admin/create-user.ts --upn <name@domain> --name "<Full Name>" [--role ADMIN|AUDITOR] [--tenant <bank-slug>] [--generate]
  --role      ADMIN (manages its scope; a bank admin also approves) or AUDITOR (read-only); defaults to ADMIN
  --tenant    bank short code; omit for PatchGate platform staff (all banks)
  --generate  print a one-time temporary password (must be changed at first sign-in) instead of prompting
`;

const argsSchema = z.object({
  upn: z
    .string()
    .trim()
    .toLowerCase()
    .min(3)
    .max(200)
    .regex(/^[^\s@]+@[^\s@]+$/, "use name@domain"),
  name: z.string().trim().min(1).max(120),
  role: z.enum(ACTIVE_ROLES, { error: "role must be ADMIN or AUDITOR" }).default("ADMIN"),
  tenant: z.string().trim().toLowerCase().min(1).max(40).optional(),
  generate: z.boolean().default(false),
});

const out = (s: string) => process.stdout.write(`${s}\n`);
const err = (s: string) => process.stderr.write(`${s}\n`);

/** Read a line from the terminal without echo. */
function readSecret(prompt: string): Promise<string> {
  const stdin = process.stdin;
  return new Promise((resolve, reject) => {
    process.stdout.write(prompt);
    let value = "";
    stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    stdin.resume();
    const done = (fn: () => void) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
      process.stdout.write("\n");
      fn();
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return done(() => resolve(value));
        if (ch === "\u0003") return done(() => reject(new Error("cancelled")));
        if (ch === "\u0008" || ch === "\u007f") value = value.slice(0, -1);
        else if (ch >= " ") value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

// One stdin consumer when piped: "password\nconfirmation\n" (or a single line used for both).
let pipedLines: string[] | null = null;
async function nextSecret(prompt: string): Promise<string> {
  if (process.stdin.isTTY) return readSecret(prompt);
  pipedLines ??= await new Promise<string[]>((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c: string) => (data += c));
    process.stdin.on("end", () => resolve(data.split(/\r?\n/)));
    process.stdin.on("error", reject);
  });
  const line = pipedLines.shift();
  return line && line.length > 0 ? line : (pipedLines[0] ?? "");
}

export async function main(argv: string[]): Promise<number> {
  let parsed: z.infer<typeof argsSchema>;
  try {
    const { values } = parseArgs({
      args: argv,
      options: {
        upn: { type: "string" },
        name: { type: "string" },
        role: { type: "string" },
        tenant: { type: "string" },
        generate: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
      strict: true,
    });
    if (values.help) {
      out(USAGE);
      return 0;
    }
    parsed = argsSchema.parse({ ...values, role: values.role?.toUpperCase() });
  } catch (e: unknown) {
    const msg = e instanceof z.ZodError ? e.issues.map((i) => `--${i.path.join(".")}: ${i.message}`).join("; ") : e instanceof Error ? e.message : String(e);
    err(`Invalid arguments: ${msg}\n\n${USAGE}`);
    return 2;
  }

  try {
    if (await prisma.user.findUnique({ where: { upn: parsed.upn }, select: { id: true } })) {
      err(`A user "${parsed.upn}" already exists. Reset their password from Administration → Users instead.`);
      return 1;
    }
    let tenantId: string | null = null;
    if (parsed.tenant) {
      const t = await prisma.tenant.findUnique({ where: { slug: parsed.tenant } });
      if (!t) {
        err(`Unknown bank short code "${parsed.tenant}".`);
        return 1;
      }
      tenantId = t.id;
    }

    let password: string;
    if (parsed.generate) {
      password = generateTempPassword();
    } else {
      password = await nextSecret("New password (min. 14 characters, not shown): ");
      const policy = checkPasswordPolicy(password, parsed.upn);
      if (!policy.ok) {
        err(`Password refused: ${policy.reason}`);
        return 1;
      }
      const confirm = await nextSecret("Repeat the password: ");
      if (confirm !== password) {
        err("The passwords do not match.");
        return 1;
      }
    }

    const passwordHash = await hashPassword(password);
    const user = await prisma.$transaction(async (tx) => {
      const created = await tx.user.create({
        data: {
          upn: parsed.upn,
          name: parsed.name,
          role: parsed.role,
          tenantId,
          passwordHash,
          passwordChangedAt: new Date(),
          mustChangePassword: parsed.generate,
        },
      });
      await auditAuth(
        { actor: "cli:create-user", action: "user.created", entity: "User", entityId: created.id, payload: { upn: created.upn, role: created.role, tenantId, via: "cli" }, tenantId },
        tx,
      );
      return created;
    });

    out(`Created ${user.role} ${user.upn}${parsed.tenant ? ` (bank ${parsed.tenant})` : " (PatchGate platform team)"}.`);
    if (parsed.generate) {
      out(`Temporary password (shown once, must be changed at first sign-in): ${password}`);
    }
    out("At first sign-in the user sets up an authenticator app (TOTP) — two-factor sign-in is mandatory.");
    return 0;
  } finally {
    await prisma.$disconnect();
  }
}
