import type { JobPackage } from "../protocol.ts";
import type { Logger } from "../util/log.ts";
import { permanent } from "./errors.ts";

/**
 * OPTIONAL bank-held trust policy (config `trust`): defence in depth against a compromised PatchGate
 * platform. PatchGate signs jobs, but the bank decides locally which publishers may be installed:
 *  - trust.publishers: wingetId → exact "O=..." pins. If set, every msi/exe package must name a listed
 *    app and its publisher field may only NARROW the local pin list (every O= it names must be pinned
 *    locally), never replace it. Apps that are not listed are refused unless trust.allowUnlistedApps.
 *  - trust.agentSha256: allow-list of Tactical agent builds (kind "agent" is unsigned): any other hash
 *    is refused.
 * Microsoft update files (msu/cab/wsusscan) are always checked for a Microsoft Authenticode signature
 * by the PC-side scripts; there is nothing to configure for them here.
 */

export interface TrustPolicy {
  publishers?: Readonly<Record<string, readonly string[]>>;
  allowUnlistedApps: boolean;
  agentSha256?: readonly string[];
}

/** "O=A Corp; O=B Ltd" → ["O=A Corp", "O=B Ltd"] (whitespace around ';' ignored, case-sensitive). */
export function splitPublisherPins(publisher: string): string[] {
  return publisher
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean);
}

function reject(msg: string, pkg: JobPackage, log: Logger | undefined, job: string): never {
  log?.error("package REFUSED by local trust policy", { security: true, job, wingetId: pkg.wingetId, version: pkg.version, kind: pkg.kind, sha256: pkg.sha256, reason: msg });
  throw permanent(`refused by the bank's local trust policy: ${msg}`);
}

/** Throws a permanent JobError if the package is not allowed by the local policy. No policy = allow. */
export function assertTrustedPackage(pkg: JobPackage, policy: TrustPolicy | undefined, log: Logger | undefined, job: string): void {
  if (!policy) return;
  if (pkg.kind === "msi" || pkg.kind === "exe") {
    if (!policy.publishers) return;
    const pins = Object.hasOwn(policy.publishers, pkg.wingetId) ? policy.publishers[pkg.wingetId] : undefined;
    if (!pins) {
      if (policy.allowUnlistedApps) {
        log?.warn("package allowed although not in trust.publishers (trust.allowUnlistedApps)", { security: true, job, wingetId: pkg.wingetId });
        return;
      }
      reject(`app ${pkg.wingetId} is not listed in trust.publishers`, pkg, log, job);
    }
    const requested = splitPublisherPins(pkg.publisher);
    if (requested.length === 0) reject(`job has no publisher pin for ${pkg.wingetId}`, pkg, log, job);
    const local = new Set(pins);
    const foreign = requested.filter((p) => !local.has(p));
    if (foreign.length > 0) reject(`publisher ${foreign.join("; ")} is not pinned locally for ${pkg.wingetId}`, pkg, log, job);
    return;
  }
  if (pkg.kind === "agent" && policy.agentSha256) {
    if (!policy.agentSha256.includes(pkg.sha256)) reject(`Tactical agent build ${pkg.sha256} is not in trust.agentSha256`, pkg, log, job);
  }
}
