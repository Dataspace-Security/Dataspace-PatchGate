import "server-only";
import nodemailer from "nodemailer";

/**
 * SMTP delivery (nodemailer). SMTP_URL:
 *  - smtps://user:pass@host:465 → implicit TLS;
 *  - smtp://user:pass@host:587  → STARTTLS, REQUIRED in production (a server that does not offer it fails
 *    the delivery instead of sending credentials / messages in clear). Dev/test may talk plain SMTP to fakes.
 * Certificates are always verified (TLS ≥ 1.2). The URL (it holds the password) is never logged.
 */

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
  event: string;
}

export type MailResult = { ok: true } | { ok: false; permanent: boolean; error: string };

export interface Mailer {
  send(msg: MailMessage): Promise<MailResult>;
}

export interface SmtpOptions {
  url: string;
  from: string;
  production: boolean;
  timeoutMs?: number;
}

interface SmtpError {
  responseCode?: number;
  code?: string;
  message?: string;
}

/** 5xx from the server = permanent (bad mailbox, policy); everything else (4xx, network, TLS) is retried. */
export function classifySmtpError(err: unknown): { permanent: boolean; error: string } {
  const e = (typeof err === "object" && err !== null ? err : {}) as SmtpError;
  const code = typeof e.responseCode === "number" ? e.responseCode : undefined;
  const base = code ? `SMTP ${code}` : e.code ? `SMTP ${e.code}` : "SMTP error";
  // Server replies may echo addresses; keep the first line, bounded. Never the URL / credentials.
  const detail = (e.message ?? "").split("\n")[0].replace(/smtps?:\/\/\S+/gi, "[smtp-url]").slice(0, 200);
  return { permanent: code !== undefined && code >= 500 && code < 600, error: detail ? `${base}: ${detail}` : base };
}

export function createSmtpMailer(opts: SmtpOptions): Mailer {
  const u = new URL(opts.url);
  const secure = u.protocol === "smtps:";
  const timeout = opts.timeoutMs ?? 15_000;
  const transport = nodemailer.createTransport({
    host: u.hostname,
    port: u.port ? Number(u.port) : secure ? 465 : 587,
    secure,
    requireTLS: !secure && opts.production,
    auth: u.username ? { user: decodeURIComponent(u.username), pass: decodeURIComponent(u.password) } : undefined,
    connectionTimeout: timeout,
    greetingTimeout: timeout,
    socketTimeout: timeout * 2,
    tls: { minVersion: "TLSv1.2", rejectUnauthorized: true },
    disableFileAccess: true,
    disableUrlAccess: true,
  });
  return {
    async send(msg) {
      try {
        await transport.sendMail({
          from: opts.from,
          to: msg.to,
          subject: msg.subject,
          text: msg.text,
          html: msg.html,
          headers: { "Auto-Submitted": "auto-generated", "X-PatchGate-Event": msg.event },
        });
        return { ok: true };
      } catch (err: unknown) {
        return { ok: false, ...classifySmtpError(err) };
      }
    },
  };
}
