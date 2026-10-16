import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { onShutdownRequest, shutdownSignals } from "../src/cli.ts";
import { parseConfig } from "../src/config.ts";
import { jobKeyFingerprint, normalizeFingerprint } from "../src/init.ts";
import { fitCollectResult, jsonBytes } from "../src/jobs/result-size.ts";
import { assertTrustedPackage, splitPublisherPins, type TrustPolicy } from "../src/jobs/trust-policy.ts";
import { JobError } from "../src/jobs/errors.ts";
import { AuditPageError, validateAuditPage } from "../src/siem/relay.ts";
import { isRetryableTactical, isRunScriptOutcomeUnknown, TacticalError } from "../src/tactical/client.ts";
import { isTransientFsError, withFsRetry } from "../src/util/fsx.ts";
import { createAgent, httpRequestStream } from "../src/util/http.ts";
import type { JobPackage } from "../src/protocol.ts";

describe("H5: runscript failure classification", () => {
  it("treats lost connections and proxy gateway errors/timeouts as outcome unknown, agent-offline as retryable", () => {
    for (const s of [undefined, 408, 502, 503, 504]) expect(isRunScriptOutcomeUnknown(new TacticalError("x", s))).toBe(true);
    expect(isRunScriptOutcomeUnknown(new TacticalError("x", 400, "The agent timed out"))).toBe(true);
    expect(isRunScriptOutcomeUnknown(new TacticalError("x", 400, "Unable to contact the agent"))).toBe(false);
    expect(isRunScriptOutcomeUnknown(new TacticalError("x", 500))).toBe(false);
    expect(isRunScriptOutcomeUnknown(new TacticalError("x", 404))).toBe(false);
    // the generic classifier is unchanged for read-only calls
    expect(isRetryableTactical(new TacticalError("x", 504))).toBe(true);
  });
});

describe("M10: streamed responses on keep-alive sockets", () => {
  let server: Server;
  let url: URL;
  beforeEach(async () => {
    server = createServer((_req, res) => res.end("hello"));
    server.keepAliveTimeout = 10_000;
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    url = new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}/x`);
  });
  afterEach(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  });

  it("does not accumulate timeout listeners or leave a stale timeout on the reused socket", async () => {
    const agent = createAgent(url, { keepAlive: true, maxSockets: 1 });
    const warnings: Error[] = [];
    const onWarning = (w: Error) => warnings.push(w);
    process.on("warning", onWarning);
    const sockets = new Set<unknown>();
    let baseline = -1;
    try {
      for (let i = 0; i < 15; i++) {
        const { res } = await httpRequestStream({ method: "GET", url, agent, timeoutMs: 60_000 });
        const sock = res.socket!;
        sockets.add(sock);
        for await (const _ of res) void _;
        await new Promise((r) => setImmediate(r));
        if (baseline < 0) baseline = sock.listenerCount("timeout");
        expect(sock.listenerCount("timeout")).toBe(baseline);
        expect(sock.timeout === undefined || sock.timeout !== 60_000).toBe(true);
      }
    } finally {
      process.off("warning", onWarning);
      agent.destroy();
    }
    expect(sockets.size).toBe(1); // really the same keep-alive socket
    expect(warnings.filter((w) => w.name === "MaxListenersExceededWarning")).toEqual([]);
  });
});

describe("LOW: Windows file locks", () => {
  it("retries rename/rm on EPERM/EBUSY (AV / indexer) with backoff, not on real errors", async () => {
    const err = (code: string) => Object.assign(new Error(code), { code });
    let n = 0;
    const out = await withFsRetry(
      async () => {
        if (++n < 3) throw err("EPERM");
        return "done";
      },
      { platform: "win32", baseMs: 1 },
    );
    expect(out).toBe("done");
    expect(n).toBe(3);
    expect(isTransientFsError(err("EBUSY"), "linux")).toBe(true);
    expect(isTransientFsError(err("EPERM"), "linux")).toBe(false);
    let m = 0;
    await expect(
      withFsRetry(
        async () => {
          m++;
          throw err("ENOENT");
        },
        { platform: "win32", baseMs: 1 },
      ),
    ).rejects.toThrow("ENOENT");
    expect(m).toBe(1);
  });
});

describe("LOW: graceful shutdown on Windows", () => {
  class FakeProc extends EventEmitter {
    send = () => true;
  }
  it("listens for SIGBREAK/SIGHUP on win32 and the 'shutdown' IPC message; fires once", () => {
    expect(shutdownSignals("win32")).toEqual(expect.arrayContaining(["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"]));
    expect(shutdownSignals("linux")).toEqual(["SIGTERM", "SIGINT"]);
    const proc = new FakeProc();
    const reasons: string[] = [];
    onShutdownRequest(proc as never, "win32", (r) => reasons.push(r));
    proc.emit("SIGBREAK", "SIGBREAK");
    proc.emit("SIGINT", "SIGINT");
    expect(reasons).toEqual(["SIGBREAK"]);
    expect(proc.listenerCount("SIGBREAK")).toBe(0);

    const proc2 = new FakeProc();
    onShutdownRequest(proc2 as never, "win32", (r) => reasons.push(r));
    proc2.emit("message", "shutdown");
    expect(reasons).toEqual(["SIGBREAK", "ipc:shutdown"]);
  });
});

describe("SECURITY #1: local trust policy", () => {
  const msi = (over: Partial<JobPackage> = {}): JobPackage => ({
    kind: "msi",
    wingetId: "7zip.7zip",
    version: "24.08",
    sha256: "a".repeat(64),
    size: 1,
    repoPath: "pkgs/7zip/24.08/7z.msi",
    publisher: "O=Igor Pavlov",
    switches: "",
    ...over,
  });
  const agent = (sha: string): JobPackage => ({ kind: "agent", wingetId: "Tactical.Agent", version: "2.10.0", sha256: sha, size: 1, repoPath: "tactical/agent/2.10.0/tacticalagent-v2.10.0-windows-amd64.exe", publisher: "", switches: "" });
  const policy: TrustPolicy = { publishers: { "7zip.7zip": ["O=Igor Pavlov"], "Mozilla.Firefox": ["O=Mozilla Corporation", "O=Mozilla Foundation"] }, allowUnlistedApps: false, agentSha256: ["b".repeat(64)] };
  const refused = (f: () => void, re: RegExp) => {
    let err: unknown;
    try {
      f();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(JobError);
    expect((err as JobError).retryable).toBe(false);
    expect((err as JobError).message).toMatch(re);
  };

  it("allows a pinned publisher and a narrowing subset; refuses replacement, extension and unlisted apps", () => {
    expect(() => assertTrustedPackage(msi(), policy, undefined, "DEPLOY_PACKAGE")).not.toThrow();
    expect(() => assertTrustedPackage(msi({ wingetId: "Mozilla.Firefox", publisher: "O=Mozilla Corporation" }), policy, undefined, "x")).not.toThrow();
    refused(() => assertTrustedPackage(msi({ publisher: "O=Evil Corp" }), policy, undefined, "x"), /O=Evil Corp is not pinned locally/);
    refused(() => assertTrustedPackage(msi({ publisher: "O=Igor Pavlov; O=Evil Corp" }), policy, undefined, "x"), /Evil Corp/);
    refused(() => assertTrustedPackage(msi({ wingetId: "Evil.App" }), policy, undefined, "x"), /not listed in trust.publishers/);
    expect(() => assertTrustedPackage(msi({ wingetId: "Other.App", publisher: "O=Other" }), { ...policy, allowUnlistedApps: true }, undefined, "x")).not.toThrow();
    expect(splitPublisherPins("O=A ; O=B")).toEqual(["O=A", "O=B"]);
  });

  it("allow-lists Tactical agent builds by SHA-256; no policy = no restriction", () => {
    expect(() => assertTrustedPackage(agent("b".repeat(64)), policy, undefined, "x")).not.toThrow();
    refused(() => assertTrustedPackage(agent("c".repeat(64)), policy, undefined, "x"), /not in trust.agentSha256/);
    expect(() => assertTrustedPackage(agent("c".repeat(64)), undefined, undefined, "x")).not.toThrow();
    expect(() => assertTrustedPackage(msi({ publisher: "O=Evil" }), { allowUnlistedApps: false }, undefined, "x")).not.toThrow();
  });

  it("config.example.json (with the new cache/journal caps) is valid", () => {
    const raw = JSON.parse(readFileSync(new URL("../config.example.json", import.meta.url), "utf8")) as Record<string, unknown>;
    const c = parseConfig(raw, "/etc/patchgate-connector");
    expect(c.cache.maxCacheBytes).toBe(50 * 1024 ** 3);
    expect(c.limits.journalMaxBytes).toBe(64 * 1024 ** 2);
  });

  it("config: trust section validated strictly", () => {
    const base = { stateDir: "/s", tactical: { url: "https://t" }, cache: { baseUrl: "https://c/repo", tls: { certFile: "a", keyFile: "b" } } };
    const c = parseConfig({ ...base, trust: { publishers: { "7zip.7zip": ["O=Igor Pavlov"] }, agentSha256: ["b".repeat(64)] } }, "/etc");
    expect(c.trust).toEqual({ publishers: { "7zip.7zip": ["O=Igor Pavlov"] }, agentSha256: ["b".repeat(64)], allowUnlistedApps: false });
    expect(() => parseConfig({ ...base, trust: { publishers: { "7zip.7zip": ["Igor Pavlov"] } } }, "/etc")).toThrow(/O=/);
    expect(() => parseConfig({ ...base, trust: { agentSha256: ["B".repeat(64)] } }, "/etc")).toThrow(/SHA-256/);
    expect(() => parseConfig({ ...base, trust: { microsoftOnly: true } }, "/etc")).toThrow();
  });
});

describe("SECURITY #7: job-key fingerprint + audit page integrity", () => {
  it("fingerprint = sha256 hex of the raw 32-byte key; operator formats normalised", () => {
    const raw = Buffer.alloc(32, 7).toString("base64");
    const fp = jobKeyFingerprint(raw);
    expect(fp).toMatch(/^[a-f0-9]{64}$/);
    expect(normalizeFingerprint(`SHA256:${fp.toUpperCase().match(/../g)!.join(":")}`)).toBe(fp);
    expect(() => normalizeFingerprint("abc")).toThrow(/64-hex-digit/);
  });

  const rec = (seq: number) => ({ seq: String(seq), ts: "t", actor: "a", action: "x", entity: "e", entityId: "i", hash: `h${seq}`, payload: null });
  it("accepts complete pages (gaps from other banks' seqs are normal)", () => {
    expect(validateAuditPage("10", 3, { records: [rec(11), rec(40), rec(41)], head: { seq: "90", hash: "h" } })).toHaveLength(3);
    expect(validateAuditPage("10", 3, { records: [rec(15)], head: { seq: "15", hash: "h15" } })).toHaveLength(1);
    expect(validateAuditPage("10", 3, { records: [], head: { seq: "10", hash: "h" } })).toEqual([]);
    expect(validateAuditPage("0", 3, { records: [], head: null })).toEqual([]);
  });
  it("rejects non-monotonic / duplicate / old seqs, oversize pages, withheld records and records beyond head", () => {
    const bad = [
      { records: [rec(12), rec(11)], head: { seq: "12", hash: "h" } },
      { records: [rec(11), rec(11)], head: { seq: "11", hash: "h" } },
      { records: [rec(9)], head: { seq: "9", hash: "h" } },
      { records: [rec(11), rec(12), rec(13), rec(14)], head: { seq: "14", hash: "h" } },
      { records: [rec(11)], head: { seq: "50", hash: "h" } }, // short page but head is further: withheld
      { records: [], head: { seq: "50", hash: "h" } },
      { records: [rec(11), rec(12)], head: { seq: "11", hash: "h" } },
      { records: [rec(11)], head: null },
    ];
    for (const page of bad) expect(() => validateAuditPage("10", 3, page)).toThrow(AuditPageError);
  });
});

describe("M9: COLLECT result size cap", () => {
  it("drops the largest software lists first, then update lists, marking each agent; never mutates input", () => {
    const sw = (n: number) => Array.from({ length: n }, (_, i) => ({ name: `app${i}`.padEnd(200, "x"), version: "1" }));
    const agents = [
      { agentId: "agentAAAA0001", software: sw(50), updates: [{ id: 1 }] },
      { agentId: "agentAAAA0002", software: sw(10) },
      { agentId: "agentAAAA0003", agent: { version: "2.1.0" } },
    ];
    const max = jsonBytes({ agents }) - 5000;
    const r = fitCollectResult(agents, max);
    expect(jsonBytes({ agents: r.agents })).toBeLessThanOrEqual(max);
    expect(r.trimmed).toBe(1);
    expect(r.agents[0]).toMatchObject({ agentId: "agentAAAA0001", updates: [{ id: 1 }], error: expect.stringMatching(/software list omitted/) });
    expect(r.agents[0]!.software).toBeUndefined();
    expect(r.agents[1]!.software).toHaveLength(10);
    expect(agents[0]!.software).toHaveLength(50);
    const updOnly = [{ agentId: "agentAAAA0004", updates: Array.from({ length: 100 }, (_, i) => ({ id: i, title: "t".repeat(100) })) }];
    expect(fitCollectResult(updOnly, 1000).agents[0]).toEqual({ agentId: "agentAAAA0004", error: expect.stringMatching(/update list omitted/) });
  });
});
