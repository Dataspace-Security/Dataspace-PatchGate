import { afterEach, describe, expect, it, vi } from "vitest";
import { createLogger, formatLine, isSecretKey, parseLevel, REDACTED, sanitize, type LogLevel } from "./log";

const FIXED = new Date("2026-10-15T10:00:00.000Z");

function capture(level?: LogLevel | "silent") {
  const lines: { line: string; level: LogLevel }[] = [];
  const logger = createLogger({}, { sink: (line, lvl) => lines.push({ line, level: lvl }), now: () => FIXED, level });
  const parsed = () => lines.map((l) => JSON.parse(l.line) as Record<string, unknown>);
  return { logger, lines, parsed };
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("formatLine", () => {
  it("writes one JSON object with ts, level, msg first and fields after", () => {
    const line = formatLine("info", "worker.tick.done", { durationMs: 812 }, FIXED);
    expect(line).not.toContain("\n");
    expect(JSON.parse(line)).toEqual({ ts: "2026-10-15T10:00:00.000Z", level: "info", msg: "worker.tick.done", durationMs: 812 });
    expect(Object.keys(JSON.parse(line)).slice(0, 3)).toEqual(["ts", "level", "msg"]);
  });

  it("never lets a field spoof ts/level/msg", () => {
    const o = JSON.parse(formatLine("warn", "real", { level: "debug", msg: "fake", ts: "1970" }, FIXED));
    expect(o.level).toBe("warn");
    expect(o.msg).toBe("real");
    expect(o.ts).toBe(FIXED.toISOString());
    expect(o).toMatchObject({ field_level: "debug", field_msg: "fake", field_ts: "1970" });
  });

  it("keeps newlines in messages inside the single JSON line (no log injection)", () => {
    const line = formatLine("info", "a\nb", { note: "x\ny" }, FIXED);
    expect(line.split("\n")).toHaveLength(1);
    expect(JSON.parse(line).msg).toBe("a\nb");
  });
});

describe("redaction", () => {
  it.each(["password", "Password", "passwd", "token", "x-worker-token", "accessToken", "client_secret", "Authorization",
    "cookie", "set-cookie", "apiKey", "API_KEY", "privateKey", "jobSigningKey", "AUDIT_HMAC_KEY", "sessionId", "totpSecret",
    "credentials", "AUTH_ENC_KEY"])(
    "redacts %s",
    (key) => {
      expect(isSecretKey(key)).toBe(true);
    },
  );

  it.each(["user", "upn", "durationMs", "sha256", "bankId", "msg", "status", "passed", "bypass"])("keeps %s", (key) => {
    expect(isSecretKey(key)).toBe(false);
  });

  it("redacts at any depth, including arrays and Maps", () => {
    const out = sanitize({
      req: { headers: { authorization: "Bearer abc", "user-agent": "curl" } },
      list: [{ token: "t1" }, { ok: 1 }],
      map: new Map<string, unknown>([["secret", "s"], ["name", "n"]]),
    });
    expect(out).toEqual({
      req: { headers: { authorization: REDACTED, "user-agent": "curl" } },
      list: [{ token: REDACTED }, { ok: 1 }],
      map: { secret: REDACTED, name: "n" },
    });
  });

  it("the secret value never appears in the written line", () => {
    const { logger, lines } = capture("debug");
    logger.info("login.failed", { upn: "a@bank", password: "hunter2-very-secret", nested: { cookie: "__Host-pg_session=xyz" } });
    expect(lines[0].line).not.toContain("hunter2");
    expect(lines[0].line).not.toContain("xyz");
    expect(lines[0].line).toContain("a@bank");
  });

  it("drops query strings from URL objects (they may carry tokens)", () => {
    expect(sanitize(new URL("https://h.example/p?token=abc"))).toBe("https://h.example/p");
  });
});

describe("sanitize", () => {
  it("flattens errors with cause", () => {
    const err = new Error("outer", { cause: new TypeError("inner") });
    const out = sanitize(err) as Record<string, unknown>;
    expect(out.name).toBe("Error");
    expect(out.message).toBe("outer");
    expect(typeof out.stack).toBe("string");
    expect(out.cause).toMatchObject({ name: "TypeError", message: "inner" });
  });

  it("handles cycles, bigint, dates, non-finite numbers, binary and functions", () => {
    const a: Record<string, unknown> = { n: BigInt(1), d: FIXED, inf: Infinity, buf: Buffer.from("abcd"), fn: () => 1 };
    a.self = a;
    expect(sanitize(a)).toEqual({
      n: "1",
      d: FIXED.toISOString(),
      inf: "Infinity",
      buf: "[binary 4 bytes]",
      fn: "[function]",
      self: "[Circular]",
    });
  });

  it("bounds depth and string length", () => {
    let deep: Record<string, unknown> = { v: 1 };
    for (let i = 0; i < 10; i++) deep = { d: deep };
    expect(JSON.stringify(sanitize(deep))).toContain("[MaxDepth]");
    const s = sanitize("x".repeat(10_000)) as string;
    expect(s.length).toBeLessThan(8_300);
    expect(s).toContain("[truncated");
  });
});

describe("levels", () => {
  it("parses LOG_LEVEL, defaulting to info", () => {
    expect(parseLevel("DEBUG")).toBe("debug");
    expect(parseLevel(" warn ")).toBe("warn");
    expect(parseLevel("silent")).toBe("silent");
    expect(parseLevel(undefined)).toBe("info");
    expect(parseLevel("verbose")).toBe("info");
  });

  it("filters below the minimum level", () => {
    const { logger, parsed } = capture("warn");
    logger.debug("a");
    logger.info("b");
    logger.warn("c");
    logger.error("d");
    expect(parsed().map((o) => o.msg)).toEqual(["c", "d"]);
  });

  it("reads LOG_LEVEL at call time when no fixed level is given", () => {
    const lines: string[] = [];
    const logger = createLogger({}, { sink: (l) => lines.push(l), now: () => FIXED });
    vi.stubEnv("LOG_LEVEL", "error");
    logger.info("hidden");
    vi.stubEnv("LOG_LEVEL", "debug");
    logger.debug("shown");
    expect(lines.map((l) => JSON.parse(l).msg)).toEqual(["shown"]);
  });

  it("silent writes nothing", () => {
    const { logger, lines } = capture("silent");
    logger.error("x");
    expect(lines).toHaveLength(0);
  });
});

describe("child loggers and sinks", () => {
  it("merges bindings; call-site fields win", () => {
    const { logger, parsed } = capture("debug");
    const child = logger.child({ component: "fetch", appId: "a1" }).child({ attempt: 1 });
    child.info("download.ok", { appId: "a2" });
    expect(parsed()[0]).toMatchObject({ component: "fetch", appId: "a2", attempt: 1, msg: "download.ok" });
  });

  it("routes warn/error to stderr and debug/info to stdout by default", () => {
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const logger = createLogger({}, { level: "debug" });
    logger.info("i");
    logger.error("e");
    expect(out).toHaveBeenCalledTimes(1);
    expect(err).toHaveBeenCalledTimes(1);
    expect(String(out.mock.calls[0][0]).endsWith("\n")).toBe(true);
  });

  it("never throws when the sink fails", () => {
    const logger = createLogger({}, { level: "debug", sink: () => { throw new Error("disk full"); } });
    expect(() => logger.error("x", { a: 1 })).not.toThrow();
  });
});
