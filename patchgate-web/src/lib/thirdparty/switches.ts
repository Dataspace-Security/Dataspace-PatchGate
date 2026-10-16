/**
 * Silent-install switch policy for EXE installers.
 * Command lines are NEVER taken verbatim from internet metadata:
 *  - known technologies (NSIS, Inno, WiX Burn) get fixed, well-known switch sets;
 *  - generic "exe" installers are allowed only if the manifest's Silent switches consist
 *    solely of flag tokens from this allow-list (no values, paths, quotes or shell syntax).
 * The PC-side install script re-validates every token against the same list.
 */

export const ALLOWED_SWITCHES: ReadonlySet<string> = new Set([
  "/S", "/s",
  "/SP-", "/VERYSILENT", "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/ALLUSERS", "/NOCANCEL",
  "/quiet", "/qn", "/passive", "/norestart", "/install",
  "-s", "-q", "--silent", "--quiet", "--norestart",
]);

const MAX_TOKENS = 12;

/** Returns the normalised switch string, or null if any token is not allow-listed. */
export function validateSwitches(raw: string): string | null {
  const tokens = raw.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0 || tokens.length > MAX_TOKENS) return null;
  return tokens.every((t) => ALLOWED_SWITCHES.has(t)) ? tokens.join(" ") : null;
}

const INNO = "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART";

/**
 * Silent switches for a winget installer technology + scope, or null if unsupported.
 * `manifestSilent` is consulted only for generic "exe" installers.
 */
export function silentSwitchesFor(installerType: string, scope: string, manifestSilent: string | null): string | null {
  switch (installerType.toLowerCase()) {
    case "nullsoft":
      return "/S";
    case "inno":
      // Selection only admits machine or unspecified scope; force all-users either way so the app
      // never lands in the SYSTEM profile (where inventory would never see it).
      void scope;
      return `${INNO} /ALLUSERS`;
    case "burn":
      return "/quiet /norestart";
    case "exe":
      return manifestSilent ? validateSwitches(manifestSilent) : null;
    default:
      return null;
  }
}
