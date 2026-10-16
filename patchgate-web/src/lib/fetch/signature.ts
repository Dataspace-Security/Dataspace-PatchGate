import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { orgMatches } from "./dn";

const run = promisify(execFile);

export type SignatureResult = { ok: true; subject: string } | { ok: false; reason: string };

/** Exact organisation pin, e.g. "O=Google LLC" — never a substring match (see dn.ts). */
export const publisherMatches = orgMatches;

export function parsePowerShellResult(stdout: string): { status: string; subject: string } | null {
  try {
    const o = JSON.parse(stdout.trim()) as { Status?: unknown; Subject?: unknown };
    if (typeof o.Status !== "string") return null;
    return { status: o.Status, subject: typeof o.Subject === "string" ? o.Subject : "" };
  } catch {
    return null;
  }
}

export function parseOsslsigncodeResult(stdout: string): { ok: boolean; subject: string } {
  const ok = /Signature verification:\s*ok/i.test(stdout);
  const subject = /Subject:\s*(.+)/.exec(stdout)?.[1]?.trim() ?? "";
  return { ok, subject };
}

// Path is passed via env var, never interpolated into the command line.
const PS_SCRIPT =
  "$s = Get-AuthenticodeSignature -LiteralPath $env:PG_VERIFY_FILE; " +
  "$subj = if ($s.SignerCertificate) { $s.SignerCertificate.SubjectName.Decode([System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines) } else { \"\" }; " +
  "[pscustomobject]@{ Status = [string]$s.Status; Subject = [string]$subj } | ConvertTo-Json -Compress";

/**
 * Read an Authenticode signature: valid chain (Windows trust store, or CODESIGN_CA_FILE via osslsigncode
 * elsewhere) + signer subject. No pin check — see verifyAuthenticode / thirdparty/trust.ts.
 * Fails closed when no verifier is available.
 */
export async function readAuthenticode(filePath: string, opts: { codesignCaFile?: string } = {}): Promise<SignatureResult> {
  try {
    if (process.platform === "win32") {
      const { stdout } = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT], {
        env: { ...process.env, PG_VERIFY_FILE: filePath },
        timeout: 60_000,
        windowsHide: true,
      });
      const r = parsePowerShellResult(stdout);
      if (!r) return { ok: false, reason: "could not read signature" };
      if (r.status !== "Valid") return { ok: false, reason: `signature ${r.status}` };
      return { ok: true, subject: r.subject };
    }

    if (!opts.codesignCaFile) {
      return { ok: false, reason: "no signature verifier: set CODESIGN_CA_FILE (osslsigncode) on non-Windows hosts" };
    }
    const { stdout } = await run("osslsigncode", ["verify", "-in", filePath, "-CAfile", opts.codesignCaFile], {
      timeout: 60_000,
    }).catch((e: { stdout?: string }) => ({ stdout: e.stdout ?? "" }));
    const r = parseOsslsigncodeResult(stdout);
    if (!r.ok) return { ok: false, reason: "signature invalid or untrusted" };
    return { ok: true, subject: r.subject };
  } catch (err: unknown) {
    return { ok: false, reason: `verifier error: ${err instanceof Error ? err.message : "unknown"}` };
  }
}

/** Verify Authenticode signature + pinned publisher (exact organisation match). */
export async function verifyAuthenticode(
  filePath: string,
  expectedPublisher: string,
  opts: { codesignCaFile?: string } = {},
): Promise<SignatureResult> {
  const r = await readAuthenticode(filePath, opts);
  if (!r.ok) return r;
  if (!publisherMatches(r.subject, expectedPublisher)) return { ok: false, reason: `publisher mismatch (${r.subject})` };
  return r;
}

// MSI ProductVersion via the Windows Installer COM API; EXE via the version resource. Path via env var.
const PS_VERSION =
  "$f = $env:PG_VERIFY_FILE; " +
  "if ($env:PG_VERIFY_KIND -eq 'msi') { " +
  "$i = New-Object -ComObject WindowsInstaller.Installer; " +
  "$db = $i.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$i,@($f,0)); " +
  "$v = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@(\"SELECT Value FROM Property WHERE Property='ProductVersion'\")); " +
  "$v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null); " +
  "$r = $v.GetType().InvokeMember('Fetch','InvokeMethod',$null,$v,$null); " +
  "if ($r) { $r.GetType().InvokeMember('StringData','GetProperty',$null,$r,1) } " +
  "} else { (Get-Item -LiteralPath $f).VersionInfo.ProductVersion }";

const VERSION_RE = /^[0-9A-Za-z.+_-]{1,64}$/;

/** Best-effort version embedded in the installer (null if unreadable). Shown to the approver. */
export async function readFileVersion(filePath: string, kind: "msi" | "exe"): Promise<string | null> {
  if (process.platform !== "win32") return null;
  try {
    const { stdout } = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", PS_VERSION], {
      env: { ...process.env, PG_VERIFY_FILE: filePath, PG_VERIFY_KIND: kind },
      timeout: 60_000,
      windowsHide: true,
    });
    const v = stdout.trim().replace(/\s+/g, "");
    return VERSION_RE.test(v) ? v : null;
  } catch {
    return null;
  }
}
