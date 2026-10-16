import type { PackageInput } from "./package-input";

/** Minimal DB shapes (kept structural so pure code and tests don't depend on Prisma types). */
export interface AppVersionRow {
  version: string;
  sha256: string;
  repoPath: string | null;
  installerKind: "MSI" | "EXE";
  silentArgs: string;
  wingetId: string;
  publisher: string;
}

export interface AgentReleaseRow {
  version: string;
  sha256: string;
  repoPath: string;
  assetName: string;
}

/**
 * Signer pin the PC must enforce for THIS file: the organisation that signed it when it was verified
 * (tightest), else the app's pin list (rows from before signer capture). "" fails validation (closed).
 */
export function versionPublisher(v: { signerOrg: string | null }, appPins: string | null): string {
  if (v.signerOrg) return `O=${v.signerOrg}`;
  return appPins ?? "";
}

/** Third-party package → install-script input (validated later by packageInputSchema). */
export function appVersionToPackage(v: AppVersionRow): PackageInput {
  const common = { wingetId: v.wingetId, version: v.version, sha256: v.sha256, repoPath: v.repoPath ?? "", publisher: v.publisher };
  return v.installerKind === "EXE"
    ? { kind: "exe", ...common, switches: v.silentArgs }
    : { kind: "msi", ...common, switches: "" };
}

/** Tactical agent mirror row → install-script input. */
export function agentReleaseToPackage(r: AgentReleaseRow): PackageInput {
  return { kind: "agent", wingetId: "Tactical.Agent", version: r.version, sha256: r.sha256, repoPath: r.repoPath };
}

const ARCH_ASSET: Record<string, RegExp> = {
  amd64: /-windows-amd64\.exe$/,
  "386": /-windows-386\.exe$/,
};

/** Agent architectures Tactical publishes for Windows. */
export const AGENT_ARCHES = ["amd64", "386"] as const;

/**
 * Pick the agent build for a PC's architecture (Tactical goarch). Unknown/unsupported arch → null
 * (fail fast) — never guess: a wrong-arch installer would fail silently inside the scheduled task.
 */
export function pickAgentRelease<T extends AgentReleaseRow>(releases: readonly T[], goarch: string | null | undefined): T | null {
  const re = goarch ? ARCH_ASSET[goarch] : undefined;
  if (!re) return null;
  return releases.find((r) => re.test(r.assetName)) ?? null;
}

/** True when an approved build exists for EVERY Windows architecture. */
export function hasAllAgentArches(releases: readonly AgentReleaseRow[]): boolean {
  return AGENT_ARCHES.every((a) => releases.some((r) => ARCH_ASSET[a].test(r.assetName)));
}
