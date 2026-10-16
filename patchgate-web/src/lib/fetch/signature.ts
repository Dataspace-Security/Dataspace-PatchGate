import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
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

/**
 * Parse `osslsigncode verify` output. OK only when the tool reports overall success ("Succeeded") and
 * every per-signature line is exactly "Signature verification: ok" (and every timestamp present verified).
 * Line-anchored on purpose:
 * "Timestamp Server Signature verification: ok" must never count as the file signature being valid.
 * The subject is the first signer's (the block after "Signer's certificate:").
 */
export function parseOsslsigncodeResult(stdout: string): { ok: boolean; subject: string } {
  const verdicts = [...stdout.matchAll(/^Signature verification:\s*(\S+)\s*$/gm)].map((m) => m[1].toLowerCase());
  // A timestamp that is present but does not verify fails the file (osslsigncode 2.14 only logs it).
  const tsVerdicts = [...stdout.matchAll(/^Timestamp Server Signature verification:\s*(\S+)\s*$/gm)].map((m) => m[1].toLowerCase());
  const ok =
    verdicts.length > 0 &&
    verdicts.every((v) => v === "ok") &&
    tsVerdicts.every((v) => v === "ok") &&
    /^Succeeded\s*$/m.test(stdout);
  const signerBlock = stdout.slice(Math.max(0, stdout.indexOf("Signer's certificate:")));
  const subject = /^\s*Subject:\s*(.+)$/m.exec(signerBlock)?.[1]?.trim() ?? "";
  return { ok, subject };
}

export type CrlCheck = "off" | "online";

export interface AuthenticodeOptions {
  /** PEM bundle of trusted code-signing roots (non-Windows; osslsigncode -CAfile). */
  codesignCaFile?: string;
  /**
   * PEM bundle of trusted timestamping roots (osslsigncode -TSA-CAfile). Defaults to codesignCaFile —
   * osslsigncode would otherwise use the OS TLS bundle, which lacks Microsoft/DigiCert timestamp roots.
   */
  tsaCaFile?: string;
  /**
   * "online": fetch CRLs from the certificates' distribution points (plain HTTP; needs egress to the CRL
   * hosts). "off" (default): no online revocation check (CRLs embedded in the signature are still used).
   */
  crlCheck?: CrlCheck;
}

/** Map validated env to verifier options (one place for every caller). */
export function codesignOptions(e: { CODESIGN_CA_FILE?: string; CODESIGN_CRL_CHECK?: CrlCheck }): AuthenticodeOptions {
  return { codesignCaFile: e.CODESIGN_CA_FILE, crlCheck: e.CODESIGN_CRL_CHECK };
}

/** Arguments for `osslsigncode verify` (argv array; never a shell string). */
export function osslsigncodeVerifyArgs(filePath: string, opts: AuthenticodeOptions & { codesignCaFile: string }): string[] {
  const args = ["verify", "-in", filePath, "-CAfile", opts.codesignCaFile, "-TSA-CAfile", opts.tsaCaFile ?? opts.codesignCaFile];
  if ((opts.crlCheck ?? "off") === "off") args.push("-ignore-crl");
  return args;
}

/**
 * Keep only the certificates of a PEM bundle that satisfy `keep` (e.g. "self-signed Microsoft root").
 * Unparseable blocks are dropped. Returns the filtered bundle and how many certificates it holds.
 */
export function filterCaBundle(pem: string, keep: (cert: X509Certificate) => boolean): { pem: string; count: number } {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  const kept = blocks.filter((b) => {
    try {
      return keep(new X509Certificate(b));
    } catch {
      return false;
    }
  });
  return { pem: kept.length ? `${kept.join("\n")}\n` : "", count: kept.length };
}

/** Self-signed root whose subject organisation is exactly `org` (signature checked, not just names). */
export function isRootOf(org: string): (cert: X509Certificate) => boolean {
  return (cert) => cert.ca && cert.subject === cert.issuer && cert.verify(cert.publicKey) && orgMatches(cert.subject, `O=${org}`);
}

// Path is passed via env var, never interpolated into the command line.
const PS_SCRIPT =
  "$s = Get-AuthenticodeSignature -LiteralPath $env:PG_VERIFY_FILE; " +
  "$subj = if ($s.SignerCertificate) { $s.SignerCertificate.SubjectName.Decode([System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines) } else { \"\" }; " +
  "[pscustomobject]@{ Status = [string]$s.Status; Subject = [string]$subj } | ConvertTo-Json -Compress";

/**
 * Read an Authenticode signature: valid chain + valid timestamp (Windows trust store, or CODESIGN_CA_FILE
 * via osslsigncode elsewhere) + signer subject. No pin check — see verifyAuthenticode / thirdparty/trust.ts.
 * Fails closed when no verifier is available.
 */
export async function readAuthenticode(filePath: string, opts: AuthenticodeOptions = {}): Promise<SignatureResult> {
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
    const args = osslsigncodeVerifyArgs(filePath, { ...opts, codesignCaFile: opts.codesignCaFile });
    // Non-zero exit = failed verification: never trust stdout alone.
    const res = await run("osslsigncode", args, { timeout: 60_000, maxBuffer: 4 * 1024 * 1024 }).then(
      ({ stdout }) => ({ exitOk: true, stdout }),
      (e: { stdout?: string }) => ({ exitOk: false, stdout: e.stdout ?? "" }),
    );
    const r = parseOsslsigncodeResult(res.stdout);
    if (!res.exitOk || !r.ok) return { ok: false, reason: "signature invalid or untrusted" };
    return { ok: true, subject: r.subject };
  } catch (err: unknown) {
    return { ok: false, reason: `verifier error: ${err instanceof Error ? err.message : "unknown"}` };
  }
}

/** Verify Authenticode signature + pinned publisher (exact organisation match). */
export async function verifyAuthenticode(
  filePath: string,
  expectedPublisher: string,
  opts: AuthenticodeOptions = {},
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
