import { readFileSync } from "node:fs";
import { connect as tcpConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";

/**
 * Minimal RFC 5424 syslog client over TCP/TLS with RFC 6587 octet-counting framing.
 * Used to ship PatchGate's audit trail to the bank SIEM (Splunk / QRadar / ArcSight / Sentinel).
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

export function formatSyslog(r: SyslogRecord): string {
  const params = Object.entries(r.sd)
    .map(([k, v]) => ` ${k}="${sdEscape(v)}"`)
    .join("");
  const msg = r.msg.replace(/[\r\n]+/g, " ");
  return `<${PRI}>1 ${r.ts.toISOString()} ${safeToken(r.hostname, 255)} ${APP_NAME} - ${safeToken(r.msgId, 32)} [${SD_ID}${params}] ${msg}`.trimEnd();
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
  return { protocol: m[1] as SiemTarget["protocol"], host: m[2], port };
}

export interface SyslogSender {
  readonly target: string;
  send(lines: readonly string[]): Promise<void>;
}

export interface SenderOptions {
  timeoutMs: number;
  caFile?: string;
}

/** Each send() opens a connection, writes all framed lines, and resolves once the socket closes cleanly. */
export function createSyslogSender(t: SiemTarget, opts: SenderOptions): SyslogSender {
  const ca = opts.caFile ? readFileSync(opts.caFile) : undefined;

  return {
    target: `${t.protocol}://${t.host}:${t.port}`,
    send: (lines) =>
      new Promise<void>((resolve, reject) => {
        let settled = false;
        const done = (err?: Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (err) {
            sock.destroy();
            reject(err);
          } else resolve();
        };

        // Delivered = all bytes flushed to the kernel ("finish") AND the peer closed cleanly.
        // Plain syslog has no app-level ACK; the SIEM-side stream rules (verify-stream.ts) catch gaps.
        let flushed = false;
        const onConnect = () => {
          const payload = lines.map((l) => frameOctetCounting(l)).join("");
          sock.end(payload, "utf8", () => {
            flushed = true;
          });
        };

        const sock: Socket =
          t.protocol === "tls"
            ? tlsConnect({ host: t.host, port: t.port, servername: t.host, ca, rejectUnauthorized: true }, onConnect)
            : tcpConnect({ host: t.host, port: t.port }, onConnect);

        const timer = setTimeout(() => done(new Error("SIEM send timed out")), opts.timeoutMs);
        sock.on("error", (e) => done(e));
        sock.on("close", (hadError) =>
          done(hadError ? new Error("SIEM connection closed with error") : flushed ? undefined : new Error("SIEM closed before data was flushed")),
        );
      }),
  };
}
