import { createServer, type AddressInfo, type Server } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createSyslogSender, formatSyslog, frameOctetCounting, parseSiemUrl } from "./syslog";

describe("formatSyslog (RFC 5424)", () => {
  it("produces header, structured data and message", () => {
    const line = formatSyslog({
      ts: new Date("2026-10-14T10:00:00.123Z"),
      hostname: "patchgate01",
      msgId: "AUDIT",
      sd: { seq: "42", hash: "ab" },
      msg: '{"action":"x"}',
    });
    expect(line).toBe(
      '<110>1 2026-10-14T10:00:00.123Z patchgate01 patchgate - AUDIT [patchgate@32473 seq="42" hash="ab"] {"action":"x"}',
    );
  });

  it("escapes structured-data values per RFC 5424 (\" \\ ])", () => {
    const line = formatSyslog({ ts: new Date(0), hostname: "h", msgId: "M", sd: { v: 'a"b\\c]d' }, msg: "" });
    expect(line).toContain('v="a\\"b\\\\c\\]d"');
  });

  it("strips newlines from the message so one event = one record", () => {
    const line = formatSyslog({ ts: new Date(0), hostname: "h", msgId: "M", sd: {}, msg: "a\nb\r\nc" });
    expect(line).not.toMatch(/[\r\n]/);
  });
});

describe("frameOctetCounting (RFC 6587)", () => {
  it("prefixes the UTF-8 byte length", () => {
    expect(frameOctetCounting("é")).toBe("2 é");
  });
});

describe("parseSiemUrl", () => {
  it("parses tls and tcp URLs", () => {
    expect(parseSiemUrl("tls://siem.bank.local:6514")).toEqual({ protocol: "tls", host: "siem.bank.local", port: 6514 });
    expect(parseSiemUrl("tcp://127.0.0.1:1514")).toEqual({ protocol: "tcp", host: "127.0.0.1", port: 1514 });
  });
  it("rejects other schemes and missing ports", () => {
    expect(() => parseSiemUrl("udp://x:514")).toThrow();
    expect(() => parseSiemUrl("tls://x")).toThrow();
  });
});

describe("createSyslogSender", () => {
  let server: Server | undefined;
  afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

  it("delivers framed lines over TCP", async () => {
    const received: string[] = [];
    server = createServer((sock) => sock.on("data", (d) => received.push(d.toString("utf8"))));
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;

    const sender = createSyslogSender({ protocol: "tcp", host: "127.0.0.1", port }, { timeoutMs: 2000 });
    await sender.send(["hello", "wörld"]);
    await new Promise((r) => setTimeout(r, 50));
    expect(received.join("")).toBe("5 hello6 wörld");
  });

  it("rejects when the SIEM is unreachable", async () => {
    const sender = createSyslogSender({ protocol: "tcp", host: "127.0.0.1", port: 1 }, { timeoutMs: 1000 });
    await expect(sender.send(["x"])).rejects.toThrow();
  });
});
