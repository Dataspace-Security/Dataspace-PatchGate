/**
 * Tiny, dependency-free structured logger: one JSON object per line (JSON Lines) on stdout/stderr.
 *
 *   import { log } from "@/lib/log";
 *   log.info("worker.tick.done", { durationMs: 812, deployed: 3 });
 *   const l = log.child({ component: "fetch", appId });   // bound fields on every line
 *   l.error("download.failed", { err });                   // Error → { name, message, stack }
 *
 * Line shape: {"ts":"2026-10-15T10:00:00.000Z","level":"info","msg":"worker.tick.done","durationMs":812,...}
 *
 * Conventions (see docs/RUNBOOK.md "Logging"):
 * - `msg` is a stable, dotted event name (`area.event[.outcome]`), not a sentence — it is what alerts match on.
 * - Variable data goes in fields, never interpolated into `msg`.
 * - Never log secrets, package bytes, or full request bodies. Keys that look secret
 *   (password, token, secret, authorization, cookie, api key, private key, session, …) are redacted
 *   automatically at any depth — this is a safety net, not a licence to pass secrets in.
 * - Level from LOG_LEVEL (debug | info | warn | error | silent), default "info"; read on every call so it
 *   can be changed per container without a rebuild. debug/info → stdout, warn/error → stderr.
 * - The audit chain (lib/audit) remains the system of record for security events; logs are operational.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogFields = Record<string, unknown>;

export interface Logger {
  debug(msg: string, fields?: LogFields): void;
  info(msg: string, fields?: LogFields): void;
  warn(msg: string, fields?: LogFields): void;
  error(msg: string, fields?: LogFields): void;
  /** New logger whose lines always carry `bindings` (call-site fields win on conflict). */
  child(bindings: LogFields): Logger;
}

export interface LoggerOptions {
  /** Where lines go. Default: stdout for debug/info, stderr for warn/error. */
  sink?: (line: string, level: LogLevel) => void;
  /** Fixed minimum level; default reads LOG_LEVEL on every call. */
  level?: LogLevel | "silent";
  /** Clock (tests). */
  now?: () => Date;
}

const LEVEL_RANK: Record<LogLevel | "silent", number> = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
const RESERVED = new Set(["ts", "level", "msg"]);
const MAX_DEPTH = 6;
const MAX_STRING = 8_192;
export const REDACTED = "[REDACTED]";

/** Keys whose values are never written. Matched case-insensitively against the key name. */
const SECRET_KEY =
  /password|passwd|passphrase|^pass$|^pwd$|token|secret|authori[sz]ation|cookie|api[-_]?key|private[-_]?key|signing[-_]?key|hmac|session|credential|^otp$|totp|enc[-_]?key/i;

export function isSecretKey(key: string): boolean {
  return SECRET_KEY.test(key);
}

export function parseLevel(raw: string | undefined): LogLevel | "silent" {
  const v = (raw ?? "").trim().toLowerCase();
  return v in LEVEL_RANK ? (v as LogLevel | "silent") : "info";
}

function truncate(s: string): string {
  return s.length > MAX_STRING ? `${s.slice(0, MAX_STRING)}…[truncated ${s.length - MAX_STRING} chars]` : s;
}

/** Deep copy with secret keys redacted, Errors flattened, cycles/depth bounded, BigInt stringified. */
export function sanitize(value: unknown, depth = 0, seen: WeakSet<object> = new WeakSet()): unknown {
  if (value === null || value === undefined) return value;
  switch (typeof value) {
    case "string":
      return truncate(value);
    case "number":
      return Number.isFinite(value) ? value : String(value);
    case "boolean":
      return value;
    case "bigint":
      return value.toString();
    case "function":
    case "symbol":
      return `[${typeof value}]`;
  }
  const obj = value as object;
  if (seen.has(obj)) return "[Circular]";
  if (depth >= MAX_DEPTH) return "[MaxDepth]";
  if (obj instanceof Date) return Number.isNaN(obj.getTime()) ? "Invalid Date" : obj.toISOString();
  if (obj instanceof Error) {
    seen.add(obj);
    const out: LogFields = { name: obj.name, message: truncate(obj.message) };
    if (obj.stack) out.stack = truncate(obj.stack);
    const cause = (obj as { cause?: unknown }).cause;
    if (cause !== undefined) out.cause = sanitize(cause, depth + 1, seen);
    return out;
  }
  if (obj instanceof URL) return obj.origin + obj.pathname; // never log query strings (may carry tokens)
  if (ArrayBuffer.isView(obj) || obj instanceof ArrayBuffer) return `[binary ${obj.byteLength} bytes]`;
  seen.add(obj);
  if (Array.isArray(obj)) return obj.map((v) => sanitize(v, depth + 1, seen));
  if (obj instanceof Map) {
    const out: LogFields = {};
    for (const [k, v] of obj) {
      const key = String(k);
      out[key] = isSecretKey(key) ? REDACTED : sanitize(v, depth + 1, seen);
    }
    return out;
  }
  if (obj instanceof Set) return [...obj].map((v) => sanitize(v, depth + 1, seen));
  const out: LogFields = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = isSecretKey(k) ? REDACTED : sanitize(v, depth + 1, seen);
  }
  return out;
}

function defaultSink(line: string, level: LogLevel): void {
  const stream = level === "warn" || level === "error" ? process.stderr : process.stdout;
  stream.write(`${line}\n`);
}

/** Serialise one record. Exported for tests; never throws. */
export function formatLine(level: LogLevel, msg: string, fields: LogFields | undefined, ts: Date): string {
  const record: LogFields = { ts: ts.toISOString(), level, msg: truncate(String(msg)) };
  if (fields) {
    const clean = sanitize(fields) as LogFields;
    for (const [k, v] of Object.entries(clean)) {
      record[RESERVED.has(k) ? `field_${k}` : k] = v; // a field can never spoof ts/level/msg
    }
  }
  try {
    return JSON.stringify(record);
  } catch {
    return JSON.stringify({ ts: record.ts, level, msg: record.msg, logError: "unserialisable fields" });
  }
}

export function createLogger(bindings: LogFields = {}, opts: LoggerOptions = {}): Logger {
  const sink = opts.sink ?? defaultSink;
  const now = opts.now ?? (() => new Date());
  const minLevel = (): LogLevel | "silent" => opts.level ?? parseLevel(process.env.LOG_LEVEL);

  const emit = (level: LogLevel, msg: string, fields?: LogFields): void => {
    if (LEVEL_RANK[level] < LEVEL_RANK[minLevel()]) return;
    const merged = fields ? { ...bindings, ...fields } : bindings;
    try {
      sink(formatLine(level, msg, Object.keys(merged).length > 0 ? merged : undefined, now()), level);
    } catch {
      // Logging must never take a request down.
    }
  };

  return {
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
    child: (more) => createLogger({ ...bindings, ...more }, opts),
  };
}

/** Process-wide logger. */
export const log: Logger = createLogger();
