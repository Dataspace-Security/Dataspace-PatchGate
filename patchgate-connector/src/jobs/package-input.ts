import type { JobPackage } from "../protocol.ts";
import { permanent } from "./errors.ts";

/**
 * Defence in depth before a package reaches the PC-side install script
 * (scripts/endpoint/Install-PatchGatePackage.ps1). PatchGate validated the package before signing
 * and the script re-validates; these checks mirror the script so a bad job fails here, loudly.
 * Adapted from patchgate-web/src/lib/thirdparty/package-input.ts.
 */

const APP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9.+_-]{2,127}$/;
const PUBLISHER_RE = /^O=[A-Za-z0-9 .,&()'+-]{2,200}(?: ?; ?O=[A-Za-z0-9 .,&()'+-]{2,200}){0,3}$/;
const AGENT_PATH_RE = /^tactical\/agent\/\d+\.\d+\.\d+\/tacticalagent-v\d+\.\d+\.\d+-windows-(amd64|386)\.exe$/;
const SWITCH_TOKEN_RE = /^[A-Za-z0-9/=_.:-]{1,64}$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f]/;

export function assertDeployablePackage(p: JobPackage): void {
  for (const [k, v] of Object.entries(p)) {
    if (typeof v === "string" && CONTROL.test(v)) throw permanent(`package.${k} contains control characters`);
  }
  if (!APP_ID_RE.test(p.wingetId)) throw permanent("package.wingetId invalid");
  switch (p.kind) {
    case "msi":
      if (!(p.repoPath.startsWith("pkgs/") && p.repoPath.endsWith(".msi"))) throw permanent("msi must live under pkgs/ and end in .msi");
      if (p.switches !== "") throw permanent("msi packages take no switches");
      if (!PUBLISHER_RE.test(p.publisher)) throw permanent("publisher pin must be O=<organisation>");
      return;
    case "exe": {
      if (!(p.repoPath.startsWith("pkgs/") && p.repoPath.endsWith(".exe"))) throw permanent("exe must live under pkgs/ and end in .exe");
      const tokens = p.switches.trim().split(/\s+/).filter(Boolean);
      if (tokens.length === 0 || tokens.length > 12 || !tokens.every((t) => SWITCH_TOKEN_RE.test(t))) throw permanent("exe switches invalid");
      if (!PUBLISHER_RE.test(p.publisher)) throw permanent("publisher pin must be O=<organisation>");
      return;
    }
    case "agent":
      if (p.wingetId !== "Tactical.Agent") throw permanent("agent package must be Tactical.Agent");
      if (!/^\d+\.\d+\.\d+$/.test(p.version)) throw permanent("agent version invalid");
      if (!AGENT_PATH_RE.test(p.repoPath)) throw permanent("agent must come from tactical/agent/");
      if (p.switches !== "" || p.publisher !== "") throw permanent("agent package takes no switches/publisher");
      return;
  }
}

/** Env vars consumed by the signed PatchGate install script. PG_REPO_URL = this connector's cache. */
export function toInstallEnv(p: JobPackage, repoUrl: string): Record<string, string> {
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

export const NO_RESULT_LINE = "no result line from install script";

/** The install script prints exactly one result line; anything else is a failure. */
export function parseInstallResult(output: string): { ok: true } | { ok: false; reason: string } {
  const line = output
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.startsWith("PATCHGATE_RESULT="));
  if (line === "PATCHGATE_RESULT=OK") return { ok: true };
  if (line) return { ok: false, reason: line.slice("PATCHGATE_RESULT=".length, 300) };
  return { ok: false, reason: NO_RESULT_LINE };
}

/** Script failures caused by the cache being busy / unreachable are worth retrying later. */
export function isTransientInstallFailure(reason: string): boolean {
  return /\b503\b|service unavailable|server unavailable|timed? ?out|unable to connect|connection (was )?(closed|reset|refused)/i.test(reason);
}

/** Version comparison (from patchgate-web/src/lib/thirdparty/version.ts). */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) =>
    v
      .trim()
      .replace(/^v/i, "")
      .split(/[-+ ]/)[0]!
      .split(/[._]/)
      .map((p) => {
        const n = Number.parseInt(p, 10);
        return Number.isFinite(n) ? n : 0;
      });
  const pa = parts(a);
  const pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}
