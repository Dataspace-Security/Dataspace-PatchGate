/**
 * Structured JSON logs (one object per line) to stdout. Never logs secrets: values under
 * sensitive-looking keys are replaced, and long strings are truncated.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";
const LEVELS: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

const SENSITIVE_KEY = /(key|secret|token|password|passwd|signature|authorization|cookie|proof|code|env_?vars)$/i;
const MAX_STRING = 2000;
const MAX_DEPTH = 5;

export type LogFields = Record<string, unknown>;

export interface Logger {
  debug(msg: string, fields?: LogFields): void;
  info(msg: string, fields?: LogFields): void;
  warn(msg: string, fields?: LogFields): void;
  error(msg: string, fields?: LogFields): void;
  child(fields: LogFields): Logger;
}

function scrub(value: unknown, depth: number): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Error) return { name: value.name, message: scrub(value.message, depth + 1) };
  if (depth >= MAX_DEPTH) return "[depth]";
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => scrub(v, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SENSITIVE_KEY.test(k) ? "[redacted]" : scrub(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

export type LogSink = (line: string) => void;

export function createLogger(opts: { level?: LogLevel; sink?: LogSink; base?: LogFields } = {}): Logger {
  const min = LEVELS[opts.level ?? "info"];
  const sink: LogSink = opts.sink ?? ((line) => process.stdout.write(`${line}\n`));
  const base = opts.base ?? {};

  const emit = (level: LogLevel, msg: string, fields?: LogFields) => {
    if (LEVELS[level] < min) return;
    const record = { ts: new Date().toISOString(), level, msg, ...(scrub({ ...base, ...fields }, 0) as LogFields) };
    try {
      sink(JSON.stringify(record));
    } catch {
      // logging must never crash the service
    }
  };

  return {
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
    child: (fields) => createLogger({ level: opts.level, sink, base: { ...base, ...fields } }),
  };
}

/** A logger that discards everything (tests). */
export const silentLogger: Logger = createLogger({ sink: () => undefined });

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return typeof err === "string" ? err : "unknown error";
}
