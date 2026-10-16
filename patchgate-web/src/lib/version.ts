import { PROTOCOL_VERSION } from "@/lib/connector/protocol";

/**
 * Build / release identity of this PatchGate server.
 *
 * Single source of truth is the repository's VERSION file. release/release.sh passes it to the image
 * build as PATCHGATE_BUILD_ID, which is also the Next.js `deploymentId` (next.config.ts) and stays in the
 * runtime environment (Dockerfile). Next.js allows only [A-Za-z0-9_-] there, so the release encodes the
 * semver dots as underscores ("1.0.0-rc2" -> "1_0_0-rc2"; semver itself never contains "_") and this
 * module decodes it again. The git commit is optional: set PATCHGATE_GIT_SHA at runtime (the image also
 * carries it as the OCI label org.opencontainers.image.revision).
 */
export type BuildInfo = Readonly<{
  /** Release version (semver, e.g. "1.0.0-rc2"); "dev" outside a release build. */
  version: string;
  /** Exact build id the image was built with (release builds: `version` with "." encoded as "_"). */
  buildId: string;
  /** Full or short git commit, or null when unknown. */
  gitSha: string | null;
  /** Connector protocol version this server speaks (lib/connector/protocol.ts). */
  protocolVersion: number;
}>;

const DEV_VERSION = "dev";
// Next.js deploymentId character set (letters, digits, "_" and "-").
const BUILD_ID_RE = /^[0-9A-Za-z][0-9A-Za-z_-]{0,63}$/;
// An encoded release version: MAJOR_MINOR_PATCH[-prerelease with "_" for "."].
const ENCODED_SEMVER_RE = /^\d+_\d+_\d+(-[0-9A-Za-z][0-9A-Za-z_-]*)?$/;
const GIT_SHA_RE = /^[0-9a-f]{7,40}$/;

function clean(value: string | undefined, pattern: RegExp): string | null {
  const v = value?.trim();
  return v && pattern.test(v) ? v : null;
}

/** Pure: derive the build identity from an environment (exported for tests). */
export function buildInfoFrom(env: Readonly<Record<string, string | undefined>>): BuildInfo {
  const buildId = clean(env.PATCHGATE_BUILD_ID, BUILD_ID_RE) ?? DEV_VERSION;
  const version = ENCODED_SEMVER_RE.test(buildId) ? buildId.replaceAll("_", ".") : buildId;
  const gitSha = clean(env.PATCHGATE_GIT_SHA?.toLowerCase(), GIT_SHA_RE);
  return Object.freeze({ version, buildId, gitSha, protocolVersion: PROTOCOL_VERSION });
}

let cached: BuildInfo | null = null;

/** Build identity of the running process (read once; the environment does not change at runtime). */
export function buildInfo(): BuildInfo {
  cached ??= buildInfoFrom(process.env);
  return cached;
}

/** Inverse of the decoding above: the PATCHGATE_BUILD_ID for a release version ("1.0.0-rc2" -> "1_0_0-rc2"). */
export function encodeBuildId(version: string): string {
  return version.replaceAll(".", "_");
}

/** Short label for the UI, e.g. "v1.0.0-rc2", or the raw build id ("dev", "rc1") for non-release builds. */
export function versionLabel(info: BuildInfo = buildInfo()): string {
  return /^\d+\.\d+\.\d+/.test(info.version) ? `v${info.version}` : info.version;
}
