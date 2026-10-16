import { describe, expect, it } from "vitest";
import { checkSiemStream, type SiemRecord } from "./verify-stream";

const a = (seq: number, hash: string, prevHash: string): SiemRecord => ({ msgId: "AUDIT", seq, hash, prevHash });
const anchor = (seq: number, hash: string): SiemRecord => ({ msgId: "ANCHOR", seq, hash });
const hb = (seq: number, hash: string): SiemRecord => ({ msgId: "HEARTBEAT", seq, hash });

describe("checkSiemStream (SIEM-side tamper detection)", () => {
  it("accepts a continuous chain with advancing anchors and heartbeats", () => {
    expect(
      checkSiemStream([a(1, "h1", "g"), a(2, "h2", "h1"), anchor(2, "h2"), hb(2, "h2"), a(3, "h3", "h2"), anchor(3, "h3")]),
    ).toEqual([]);
  });

  it("tolerates seq gaps (rolled-back transactions) as long as hashes link", () => {
    expect(checkSiemStream([a(1, "h1", "g"), a(5, "h5", "h1")])).toEqual([]);
  });

  it("detects tail truncation + re-export: new event does not link to last exported hash", () => {
    // h2,h3 exported, attacker deletes 2-3 in DB; next event links to h1
    const issues = checkSiemStream([a(1, "h1", "g"), a(2, "h2", "h1"), a(3, "h3", "h2"), anchor(3, "h3"), a(4, "h4", "h1")]);
    expect(issues).toContainEqual(expect.objectContaining({ kind: "chain-break", seq: 4 }));
  });

  it("detects a heartbeat reporting a head behind an exported anchor (rows deleted, nothing new)", () => {
    const issues = checkSiemStream([a(1, "h1", "g"), a(2, "h2", "h1"), anchor(2, "h2"), hb(1, "h1")]);
    expect(issues).toContainEqual(expect.objectContaining({ kind: "regression", seq: 1 }));
  });

  it("detects the same seq exported with two different hashes (rewritten history)", () => {
    const issues = checkSiemStream([a(1, "h1", "g"), anchor(1, "h1"), anchor(1, "hX")]);
    expect(issues).toContainEqual(expect.objectContaining({ kind: "fork", seq: 1 }));
  });
});

describe("checkSiemStream with one chain per bank", () => {
  const on = (chain: string, r: SiemRecord): SiemRecord => ({ ...r, chain });

  it("keeps interleaved bank chains independent (each starts at its own genesis)", () => {
    expect(
      checkSiemStream([
        on("bank-a", a(1, "a1", "g")),
        on("bank-b", a(2, "b1", "g")),
        on("bank-a", a(3, "a2", "a1")),
        on("bank-b", anchor(2, "b1")),
        on("bank-a", anchor(3, "a2")),
        on("platform", hb(0, "-")),
      ]),
    ).toEqual([]);
  });

  it("reports a break in one bank's chain without blaming the others", () => {
    const issues = checkSiemStream([
      on("bank-a", a(1, "a1", "g")),
      on("bank-b", a(2, "b1", "g")),
      on("bank-a", a(3, "a3", "aX")),
    ]);
    expect(issues).toEqual([expect.objectContaining({ kind: "chain-break", chain: "bank-a", seq: 3 })]);
  });

  it("detects a regression per chain, not across chains", () => {
    const issues = checkSiemStream([
      on("bank-a", anchor(10, "a10")),
      on("bank-b", hb(2, "b2")), // lower seq, but a different chain: fine
      on("bank-a", hb(4, "a4")),
    ]);
    expect(issues).toEqual([expect.objectContaining({ kind: "regression", chain: "bank-a", seq: 4 })]);
  });
});
