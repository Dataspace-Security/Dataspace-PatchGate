import { describe, expect, it } from "vitest";
import { PeriodError, ageBucket, overlapMs, parsePeriod, type PeriodParams } from "./period";
import { canonicalJson, contentHash, csvCell, csvLine } from "./csv";

const NOW = new Date("2026-10-16T12:00:00Z");

describe("parsePeriod", () => {
  it("defaults to the current month / quarter", () => {
    expect(parsePeriod({}, NOW)).toMatchObject({ kind: "month", from: new Date("2026-10-01T00:00:00Z"), to: new Date("2026-11-01T00:00:00Z"), label: "October 2026" });
    expect(parsePeriod({ period: "quarter" }, NOW)).toMatchObject({ from: new Date("2026-10-01T00:00:00Z"), to: new Date("2027-01-01T00:00:00Z"), label: "Q4 2026" });
  });

  it("parses explicit month / quarter / custom (to inclusive)", () => {
    expect(parsePeriod({ period: "month", month: "2026-12" }, NOW).to).toEqual(new Date("2027-01-01T00:00:00Z"));
    expect(parsePeriod({ period: "quarter", quarter: "2026-q1" }, NOW)).toMatchObject({ from: new Date("2026-01-01T00:00:00Z"), to: new Date("2026-04-01T00:00:00Z") });
    const c = parsePeriod({ period: "custom", from: "2026-09-01", to: "2026-09-30" }, NOW);
    expect(c).toMatchObject({ from: new Date("2026-09-01T00:00:00Z"), to: new Date("2026-10-01T00:00:00Z"), query: "period=custom&from=2026-09-01&to=2026-09-30" });
  });

  it("rejects malformed and oversized periods", () => {
    const bad: PeriodParams[] = [
      { period: "month", month: "2026-13" },
      { period: "quarter", quarter: "2026-Q5" },
      { period: "custom", from: "2026-02-30", to: "2026-03-01" },
      { period: "custom", from: "2026-03-02", to: "2026-03-01" },
      { period: "custom", from: "2024-01-01", to: "2026-01-01" },
      { period: "year" },
      { period: "custom", from: "2026-01-01" },
    ];
    for (const p of bad) expect(() => parsePeriod(p, NOW)).toThrow(PeriodError);
  });
});

describe("age buckets / overlap", () => {
  it("buckets by whole days since release", () => {
    const d = (days: number) => new Date(NOW.getTime() - days * 86_400_000);
    expect(ageBucket(null, NOW)).toBe("unknown");
    expect(ageBucket(d(7), NOW)).toBe("0-7");
    expect(ageBucket(d(7.5), NOW)).toBe("0-7");
    expect(ageBucket(d(8), NOW)).toBe("8-30");
    expect(ageBucket(d(30), NOW)).toBe("8-30");
    expect(ageBucket(d(31), NOW)).toBe("31-90");
    expect(ageBucket(d(91), NOW)).toBe(">90");
  });

  it("overlap of half-open ranges", () => {
    const t = (h: number) => new Date(h * 3_600_000);
    expect(overlapMs(t(0), t(10), t(5), t(20))).toBe(5 * 3_600_000);
    expect(overlapMs(t(0), t(1), t(2), t(3))).toBe(0);
  });
});

describe("csv", () => {
  it("quotes, escapes and neutralises formulas", () => {
    expect(csvCell('a "b", c')).toBe('"a ""b"", c"');
    expect(csvCell("=HYPERLINK(1)")).toBe("'=HYPERLINK(1)");
    expect(csvCell("-1+2")).toBe("'-1+2");
    expect(csvCell(-5)).toBe("-5");
    expect(csvCell(null)).toBe("");
    expect(csvCell(new Date(0))).toBe("1970-01-01T00:00:00.000Z");
    expect(csvCell(["1.0", "2.0"])).toBe('"1.0; 2.0"');
    expect(csvLine(["a", 1, true])).toBe("a,1,true\r\n");
  });

  it("canonical JSON is key-order independent; the hash is stable", () => {
    expect(canonicalJson({ b: 1, a: { d: new Date(0), c: BigInt(5) } })).toBe('{"a":{"c":"5","d":"1970-01-01T00:00:00.000Z"},"b":1}');
    expect(contentHash({ a: 1, b: 2 })).toBe(contentHash({ b: 2, a: 1 }));
    expect(contentHash({ a: 1 })).toMatch(/^[0-9a-f]{64}$/);
  });
});
