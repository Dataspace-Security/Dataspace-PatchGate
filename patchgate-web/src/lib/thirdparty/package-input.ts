import { z } from "zod";
import { PUBLISHER_PIN_RE } from "@/lib/fetch/dn";
import { WINGET_ID_RE } from "@/lib/fetch/winget";
import { validateSwitches } from "./switches";

/**
 * Strict allow-list validation for every value that reaches the install script on a PC.
 * Values originate from internet metadata (winget manifests, GitHub releases), so treat them as hostile.
 * Applied at ingestion AND again right before deploy; the PC-side script re-validates too.
 */

const wingetId = z.string().regex(WINGET_ID_RE, "invalid winget id");
const version = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/, "invalid version");
const sha256 = z.string().regex(/^[a-f0-9]{64}$/, "sha256 must be 64 lowercase hex");
// Relative repo path: segments of safe chars, no "..", no leading slash, no backslashes.
const repoPath = z
  .string()
  .max(256)
  .regex(/^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/, "invalid repo path")
  .refine((p) => !p.split("/").some((seg) => seg === ".." || seg === "."), "path traversal");
const publisher = z.string().regex(PUBLISHER_PIN_RE, "publisher pin must be O=<organisation>");

export const packageInputSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("msi"),
    wingetId,
    version,
    sha256,
    repoPath: repoPath.refine((p) => p.startsWith("pkgs/") && p.endsWith(".msi"), "msi must live under pkgs/ and end in .msi"),
    publisher,
    switches: z.literal("").default(""),
  }),
  z.object({
    kind: z.literal("exe"),
    wingetId,
    version,
    sha256,
    repoPath: repoPath.refine((p) => p.startsWith("pkgs/") && p.endsWith(".exe"), "exe must live under pkgs/ and end in .exe"),
    publisher,
    switches: z.string().refine((s) => validateSwitches(s) === s, "switches not allow-listed"),
  }),
  z.object({
    // Tactical agent upgrade: unsigned public build; trust = admin-approved mirror + pinned SHA-256.
    kind: z.literal("agent"),
    wingetId: z.literal("Tactical.Agent"),
    version: z.string().regex(/^\d+\.\d+\.\d+$/, "invalid agent version"),
    sha256,
    repoPath: repoPath.refine(
      (p) => /^tactical\/agent\/\d+\.\d+\.\d+\/tacticalagent-v\d+\.\d+\.\d+-windows-(amd64|386)\.exe$/.test(p),
      "agent must come from tactical/agent/",
    ),
    publisher: z.literal("").default(""),
    switches: z.literal("").default(""),
  }),
]);

export type PackageInput = z.input<typeof packageInputSchema>;

/** Env vars consumed by the signed PatchGate install script (scripts/endpoint/Install-PatchGatePackage.ps1). */
export function toInstallEnv(pkg: PackageInput, repoUrl: string): Record<string, string> {
  const p = packageInputSchema.parse(pkg);
  return {
    PG_KIND: p.kind,
    PG_REPO_URL: repoUrl,
    PG_PATH: p.repoPath,
    PG_SHA256: p.sha256,
    PG_APP_ID: p.wingetId,
    PG_VERSION: p.version,
    PG_PUBLISHER: p.publisher,
    PG_ARGS: p.switches,
  };
}

/** The install script prints exactly one result line; anything else is a failure. */
export function parseInstallResult(output: string): { ok: true } | { ok: false; reason: string } {
  const line = output
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.startsWith("PATCHGATE_RESULT="));
  if (line === "PATCHGATE_RESULT=OK") return { ok: true };
  if (line) return { ok: false, reason: line.slice("PATCHGATE_RESULT=".length, 300) };
  return { ok: false, reason: "no result line from install script" };
}
