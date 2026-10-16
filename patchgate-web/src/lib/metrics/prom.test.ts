import { describe, expect, it } from "vitest";
import { Registry, escapeLabelValue, formatValue, renderFamily } from "./prom";
import { bearerToken, checkMetricsAuth } from "./token";
import { cached } from "./cache";

describe("Prometheus text format", () => {
  it("renders HELP/TYPE and sorted, escaped labels", () => {
    const out = renderFamily({
      name: "patchgate_x",
      help: "Line one\nline \\ two",
      type: "gauge",
      samples: [{ labels: { z: "1", bank: 'a"b\\c\nd' }, value: 3 }],
    });
    expect(out).toBe(['# HELP patchgate_x Line one\\nline \\\\ two', "# TYPE patchgate_x gauge", 'patchgate_x{bank="a\\"b\\\\c\\nd",z="1"} 3'].join("\n"));
  });

  it("formats special values", () => {
    expect(formatValue(Infinity)).toBe("+Inf");
    expect(formatValue(-Infinity)).toBe("-Inf");
    expect(formatValue(Number.NaN)).toBe("NaN");
    expect(formatValue(0.1 + 0.2)).toBe("0.3");
    expect(formatValue(42)).toBe("42");
  });

  it("prints empty declared families and drops duplicate series", () => {
    const r = new Registry();
    r.declare("patchgate_empty", "Nothing yet.");
    r.gauge("patchgate_dup", "Dup.", 1, { a: "1" });
    r.gauge("patchgate_dup", "", 2, { a: "1" });
    r.counter("patchgate_runs_total", "Runs.", 5);
    const text = r.render();
    expect(text).toContain("# TYPE patchgate_empty gauge");
    expect(text.match(/^patchgate_dup\{/gm)).toHaveLength(1);
    expect(text).toContain('patchgate_dup{a="1"} 1');
    expect(text).toContain("# TYPE patchgate_runs_total counter\npatchgate_runs_total 5");
    expect(text.endsWith("\n")).toBe(true);
  });

  it("keeps the first non-empty HELP text", () => {
    const r = new Registry();
    r.gauge("patchgate_h", "", 1);
    r.gauge("patchgate_h", "Help later.", 2, { x: "y" });
    expect(r.render()).toContain("# HELP patchgate_h Help later.");
  });

  it("rejects invalid metric and label names", () => {
    expect(() => renderFamily({ name: "bad-name", help: "", type: "gauge", samples: [] })).toThrow();
    expect(() => renderFamily({ name: "ok", help: "", type: "gauge", samples: [{ labels: { "bad-label": "x" }, value: 1 }] })).toThrow();
    expect(() => renderFamily({ name: "ok", help: "", type: "gauge", samples: [{ labels: { __reserved: "x" }, value: 1 }] })).toThrow();
  });

  it("caps label value length", () => {
    expect(escapeLabelValue("x".repeat(500))).toHaveLength(200);
  });
});

describe("metrics token", () => {
  const token = "m".repeat(40);

  it("parses bearer tokens strictly", () => {
    expect(bearerToken(`Bearer ${token}`)).toBe(token);
    expect(bearerToken(`bearer ${token}`)).toBe(token);
    expect(bearerToken(`Basic ${token}`)).toBeNull();
    expect(bearerToken("Bearer")).toBeNull();
    expect(bearerToken("Bearer a b")).toBeNull();
    expect(bearerToken(null)).toBeNull();
  });

  it("is disabled without a (long enough) configured token", () => {
    expect(checkMetricsAuth(`Bearer ${token}`, undefined)).toBe("disabled");
    expect(checkMetricsAuth("Bearer short", "short")).toBe("disabled");
  });

  it("accepts only the exact token", () => {
    expect(checkMetricsAuth(`Bearer ${token}`, token)).toBe("ok");
    expect(checkMetricsAuth(`Bearer ${token}x`, token)).toBe("unauthorized");
    expect(checkMetricsAuth(`Bearer ${"n".repeat(40)}`, token)).toBe("unauthorized");
    expect(checkMetricsAuth(null, token)).toBe("unauthorized");
  });
});

describe("cached()", () => {
  it("de-duplicates concurrent calls and honours the TTL", async () => {
    let t = 0;
    let calls = 0;
    const c = cached(async () => ++calls, { ttlMs: 100, now: () => t });
    const [a, b] = await Promise.all([c.get(), c.get()]);
    expect([a, b, calls]).toEqual([1, 1, 1]);
    t = 50;
    expect(await c.get()).toBe(1);
    t = 150;
    expect(await c.get()).toBe(2);
  });

  it("does not cache failures unless asked to", async () => {
    let t = 0;
    let calls = 0;
    const failing = cached(async () => {
      calls++;
      throw new Error("x");
    }, { ttlMs: 100, now: () => t });
    await expect(failing.get()).rejects.toThrow("x");
    await expect(failing.get()).rejects.toThrow("x");
    expect(calls).toBe(2);

    let calls2 = 0;
    const sticky = cached(async () => {
      calls2++;
      throw new Error("y");
    }, { ttlMs: 100, errorTtlMs: 30, now: () => t });
    await expect(sticky.get()).rejects.toThrow("y");
    t = 10;
    await expect(sticky.get()).rejects.toThrow("y");
    expect(calls2).toBe(1);
    t = 50;
    await expect(sticky.get()).rejects.toThrow("y");
    expect(calls2).toBe(2);
  });
});
