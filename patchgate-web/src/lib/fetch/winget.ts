import { parse } from "yaml";
import { z } from "zod";
import { compareVersions } from "@/lib/thirdparty/version";
import { silentSwitchesFor } from "@/lib/thirdparty/switches";

/** Metadata source for third-party apps: Microsoft's open-source winget-pkgs repository. */

export const WINGET_HOSTS = ["api.github.com", "raw.githubusercontent.com"] as const;
const REPO = "microsoft/winget-pkgs";
/**
 * winget package ids: dot-separated segments; real ids contain "+" and "_" (e.g. Notepad++.Notepad++).
 * No spaces, slashes, quotes or shell metacharacters. Max 128 chars.
 */
export const WINGET_ID_RE = /^(?=.{3,128}$)[A-Za-z0-9][A-Za-z0-9+_-]*(\.[A-Za-z0-9][A-Za-z0-9+_-]*)+$/;
const ID_RE = WINGET_ID_RE;

/** Strict filesystem/URL segment for the internal repo ("+" etc. → "_"). */
export function repoSegment(wingetId: string): string {
  return wingetId.replace(/[^A-Za-z0-9._-]/g, "_");
}
const VERSION_RE = /^\d[A-Za-z0-9.+_-]{0,63}$/;

export function manifestDirFor(wingetId: string): string {
  if (!ID_RE.test(wingetId)) throw new Error("Invalid winget id");
  const parts = wingetId.split(".");
  return `manifests/${parts[0][0].toLowerCase()}/${parts.join("/")}`;
}

export function versionsApiUrl(wingetId: string): string {
  return `https://api.github.com/repos/${REPO}/contents/${manifestDirFor(wingetId)}`;
}

export function installerManifestUrl(wingetId: string, version: string): string {
  if (!VERSION_RE.test(version)) throw new Error("Invalid version");
  return `https://raw.githubusercontent.com/${REPO}/master/${manifestDirFor(wingetId)}/${version}/${wingetId}.installer.yaml`;
}

/** Directory listing contains versions AND sub-package/channel folders (Beta, Canary...). */
export function pickLatestVersion(names: readonly string[]): string | null {
  const versions = names.filter((n) => VERSION_RE.test(n));
  if (versions.length === 0) return null;
  return versions.reduce((best, v) => (compareVersions(v, best) > 0 ? v : best));
}

export const contentsListingSchema = z.array(z.object({ name: z.string(), type: z.string() }).loose());

const switchesSchema = z.object({ Silent: z.string().optional() }).loose();

const installerSchema = z
  .object({
    Architecture: z.string(),
    InstallerUrl: z.string(),
    InstallerSha256: z.string(),
    InstallerType: z.string().optional(),
    Scope: z.string().optional(),
    ProductCode: z.string().optional(),
    InstallerSwitches: switchesSchema.optional(),
  })
  .loose();

const manifestSchema = z
  .object({
    InstallerType: z.string().optional(),
    Scope: z.string().optional(),
    ProductCode: z.string().optional(),
    InstallerSwitches: switchesSchema.optional(),
    Installers: z.array(installerSchema),
  })
  .loose();

export interface SelectedInstaller {
  url: string;
  sha256: string;
  productCode: string | null;
  architecture: string;
  /** How the PC-side script runs it */
  kind: "msi" | "exe";
  /** winget technology: wix/msi/nullsoft/inno/burn/exe */
  installerType: string;
  /** Validated silent switches ("" for MSI — the script uses fixed msiexec args) */
  switches: string;
}

const MSI_TYPES = new Set(["msi", "wix"]);
const ARCH_PREFERENCE = ["x64", "neutral", "x86"];

/**
 * Pick a machine-scope installer: any MSI first (x64 > neutral > x86), else an EXE whose
 * technology has a known-safe silent switch set (see thirdparty/switches.ts).
 */
export function selectInstaller(manifestYaml: string): SelectedInstaller | null {
  const parsed = manifestSchema.safeParse(parse(manifestYaml));
  if (!parsed.success) return null;
  const root = parsed.data;

  const candidates = root.Installers.map((i) => {
    const type = (i.InstallerType ?? root.InstallerType ?? "").toLowerCase();
    const scope = (i.Scope ?? root.Scope ?? "").toLowerCase();
    const isMsi = MSI_TYPES.has(type);
    const switches = isMsi ? "" : silentSwitchesFor(type, scope, i.InstallerSwitches?.Silent ?? root.InstallerSwitches?.Silent ?? null);
    return {
      url: i.InstallerUrl,
      sha256: i.InstallerSha256,
      arch: i.Architecture.toLowerCase(),
      productCode: i.ProductCode ?? root.ProductCode ?? null,
      type,
      scope,
      kind: isMsi ? ("msi" as const) : ("exe" as const),
      switches,
    };
  }).filter(
    (c) =>
      (c.scope === "" || c.scope === "machine") &&
      /^[A-Fa-f0-9]{64}$/.test(c.sha256) &&
      c.switches !== null,
  );

  for (const kind of ["msi", "exe"] as const) {
    for (const arch of ARCH_PREFERENCE) {
      const hit = candidates.find((c) => c.kind === kind && c.arch === arch);
      if (hit) {
        return {
          url: hit.url,
          sha256: hit.sha256.toLowerCase(),
          productCode: hit.productCode,
          architecture: arch,
          kind,
          installerType: hit.type,
          switches: hit.switches ?? "",
        };
      }
    }
  }
  return null;
}
