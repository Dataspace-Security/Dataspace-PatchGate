/**
 * RFC 5424 formatting + RFC 6587 octet-counting framing.
 * Adapted from patchgate-web/src/lib/siem/syslog.ts (same PRI / APP-NAME / SD-ID so bank SIEM rules
 * written for PatchGate's own exporter keep working).
 */

// facility 13 (log audit) * 8 + severity 6 (informational) = 110
const PRI = 110;
const APP_NAME = "patchgate";
// Private enterprise number placeholder for SD-ID; replace with Dataspace's IANA PEN when registered.
const SD_ID = "patchgate@32473";

export interface SyslogRecord {
  ts: Date;
  hostname: string;
  msgId: string;
  sd: Record<string, string>;
  msg: string;
}

function sdEscape(v: string): string {
  return v.replace(/[\\"\]]/g, (c) => `\\${c}`);
}

function safeToken(v: string, max: number): string {
  const t = v.replace(/[^\x21-\x7e]/g, "").slice(0, max);
  return t.length > 0 ? t : "-";
}

function sdName(k: string): string {
  return k.replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 32) || "x";
}

export function formatSyslog(r: SyslogRecord): string {
  const params = Object.entries(r.sd)
    .map(([k, v]) => ` ${sdName(k)}="${sdEscape(v)}"`)
    .join("");
  const msg = r.msg.replace(/[\r\n]+/g, " ");
  const ts = Number.isNaN(r.ts.getTime()) ? new Date().toISOString() : r.ts.toISOString();
  return `<${PRI}>1 ${ts} ${safeToken(r.hostname, 255)} ${APP_NAME} - ${safeToken(r.msgId, 32)} [${SD_ID}${params}] ${msg}`.trimEnd();
}

export function frameOctetCounting(line: string): string {
  return `${Buffer.byteLength(line, "utf8")} ${line}`;
}

export interface SiemTarget {
  protocol: "tls" | "tcp";
  host: string;
  port: number;
}

export function parseSiemUrl(url: string): SiemTarget {
  const m = /^(tls|tcp):\/\/([A-Za-z0-9.-]+):(\d{1,5})$/.exec(url);
  if (!m) throw new Error("SIEM URL must look like tls://host:port");
  const port = Number(m[3]);
  if (port < 1 || port > 65535) throw new Error("SIEM port out of range");
  return { protocol: m[1] as SiemTarget["protocol"], host: m[2] as string, port };
}
