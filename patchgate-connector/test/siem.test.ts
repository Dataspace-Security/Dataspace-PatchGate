import { generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { createServer, type Server, type TLSSocket } from "node:tls";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPatchGateClient } from "../src/pg-client.ts";
import { rawFromPublicKey } from "../src/protocol.ts";
import { SiemRelay } from "../src/siem/relay.ts";
import { silentLogger } from "../src/util/log.ts";
import { TLS, tempDir, waitFor } from "./helpers/common.ts";
import { FakePatchGate } from "./helpers/fake-patchgate.ts";

/** Minimal TLS syslog receiver parsing RFC 6587 octet-counted frames. */
class FakeSiem {
  readonly lines: string[] = [];
  connections = 0;
  readonly sockets = new Set<TLSSocket>();
  private server: Server | undefined;
  port = 0;
  async start(): Promise<void> {
    this.server = createServer({ cert: TLS.cert, key: TLS.key }, (sock) => {
      this.connections++;
      this.sockets.add(sock);
      let buf = Buffer.alloc(0);
      sock.on("data", (d: Buffer) => {
        buf = Buffer.concat([buf, d]);
        for (;;) {
          const sp = buf.indexOf(0x20);
          if (sp < 0) break;
          const len = Number(buf.subarray(0, sp).toString());
          if (buf.length < sp + 1 + len) break;
          this.lines.push(buf.subarray(sp + 1, sp + 1 + len).toString("utf8"));
          buf = buf.subarray(sp + 1 + len);
        }
      });
      sock.on("close", () => this.sockets.delete(sock));
      sock.on("error", () => undefined);
    });
    await new Promise<void>((r) => this.server!.listen(0, "127.0.0.1", () => r()));
    this.port = (this.server!.address() as AddressInfo).port;
  }
  dropConnections(): void {
    for (const s of this.sockets) s.destroy();
  }
  async stop(): Promise<void> {
    this.dropConnections();
    await new Promise<void>((r) => this.server?.close(() => r()) ?? r());
  }
}

let dir: string;
let cleanup: () => Promise<void>;
let pg: FakePatchGate;
let siem: FakeSiem;
let relay: SiemRelay;
let pgClient: ReturnType<typeof createPatchGateClient>;

const rec = (seq: number) => ({ seq: String(seq), ts: "2026-10-15T10:00:00.000Z", actor: "user:alice", action: "CR_APPROVED", entity: "ChangeRequest", entityId: `cr${seq}`, hash: `h${seq}`, payload: { n: seq } });

beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
  pg = new FakePatchGate();
  await pg.start();
  siem = new FakeSiem();
  await siem.start();
  const conn = generateKeyPairSync("ed25519");
  pg.connectors.set("c1", { publicKey: rawFromPublicKey(conn.publicKey), tenantId: "t1" });
  pgClient = createPatchGateClient({ serverUrl: pg.url, connectorId: "c1", privateKey: conn.privateKey, timeoutMs: 5000 });
  relay = new SiemRelay({
    pg: pgClient,
    target: { protocol: "tls", host: "localhost", port: siem.port },
    ca: TLS.ca,
    hostname: "connector-a1",
    stateFile: join(dir, "siem-state.json"),
    pollIntervalMs: 50,
    batchSize: 3,
    log: silentLogger,
  });
});
afterEach(async () => {
  await relay.stop();
  await siem.stop();
  await pg.stop();
  await cleanup();
});

describe("SIEM relay", () => {
  it("forwards audit records as RFC 5424 over one TLS connection and persists the position after flush", async () => {
    pg.audit.push(rec(1), rec(2), rec(3), rec(4), rec(5));
    await relay.start();
    await waitFor(() => relay.status().lastForwardedSeq === "5");
    await waitFor(() => siem.lines.filter((l) => l.includes(" AUDIT ")).length === 5);
    const audit = siem.lines.filter((l) => l.includes(" AUDIT "));
    expect(audit[0]).toMatch(/^<110>1 2026-10-15T10:00:00\.000Z connector-a1 patchgate - AUDIT \[patchgate@32473 seq="1" hash="h1"\] \{"actor":"user:alice"/);
    expect(siem.lines.some((l) => l.includes(" ANCHOR ") && l.includes('seq="5"'))).toBe(true);
    expect(siem.connections).toBe(1);
    expect(JSON.parse(await readFile(join(dir, "siem-state.json"), "utf8"))).toEqual({ lastForwardedSeq: "5" });
    expect(relay.status()).toEqual({ configured: true, lastForwardedSeq: "5", error: null });
  });

  it("forwards each record's prevHash in the structured data so the SIEM chain-break rule works on relayed records", async () => {
    pg.audit.push({ ...rec(1), prevHash: "GENESIS" }, { ...rec(2), prevHash: "h1" }, { ...rec(7), prevHash: "h2" });
    await relay.start();
    await waitFor(() => siem.lines.filter((l) => l.includes(" AUDIT ")).length === 3);
    const audit = siem.lines.filter((l) => l.includes(" AUDIT "));
    expect(audit[0]).toContain('[patchgate@32473 seq="1" hash="h1" prevHash="GENESIS"]');
    expect(audit[1]).toContain('[patchgate@32473 seq="2" hash="h2" prevHash="h1"]');
    expect(audit[2]).toContain('[patchgate@32473 seq="7" hash="h7" prevHash="h2"]');
    // each line links to the previous one: what the SIEM rule checks
    const sd = audit.map((l) => ({ hash: /hash="([^"]+)"/.exec(l)?.[1], prev: /prevHash="([^"]+)"/.exec(l)?.[1] }));
    for (let i = 1; i < sd.length; i++) expect(sd[i]!.prev).toBe(sd[i - 1]!.hash);
  });

  it("reconnects after the SIEM drops the connection and resumes from the persisted seq", async () => {
    pg.audit.push(rec(1), rec(2));
    await relay.start();
    await waitFor(() => relay.status().lastForwardedSeq === "2");
    siem.dropConnections();
    await new Promise((r) => setTimeout(r, 100));
    pg.audit.push(rec(3));
    await waitFor(() => relay.status().lastForwardedSeq === "3", 15_000);
    await waitFor(() => siem.lines.some((l) => l.includes('seq="3" hash="h3"')));
    expect(siem.connections).toBeGreaterThanOrEqual(2);
  });

  it("SECURITY #7: rejects a page that withholds records (short page, head further on); forwards nothing, keeps its position", async () => {
    pg.audit.push(rec(1), rec(2), rec(3), rec(4));
    pg.auditWithheld.add("3").add("4"); // server hides the tail but still reports head = 4
    await relay.start();
    await waitFor(() => relay.status().error !== null);
    expect(relay.status().error).toMatch(/records withheld/);
    expect(relay.status().lastForwardedSeq).toBe("0");
    expect(siem.lines).toEqual([]);
    pg.auditWithheld.clear();
    await waitFor(() => relay.status().lastForwardedSeq === "4", 15_000);
  });

  it("does not advance while the SIEM is unreachable (TLS trust failure), and reports the error", async () => {
    await relay.stop();
    relay = new SiemRelay({
      pg: pgClient,
      target: { protocol: "tls", host: "localhost", port: siem.port },
      ca: undefined, // system roots do not trust the test CA → handshake fails
      hostname: "x",
      stateFile: join(dir, "s2.json"),
      pollIntervalMs: 50,
      batchSize: 10,
      log: silentLogger,
    });
    pg.audit.push(rec(1));
    await relay.start();
    await waitFor(() => relay.status().error !== null);
    expect(relay.status().error).toMatch(/certificate|self.signed|unable to verify/i);
    expect(relay.status().lastForwardedSeq).toBe("0");
    expect(siem.lines).toEqual([]);
  });
});
