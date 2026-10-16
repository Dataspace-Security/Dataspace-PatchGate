import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Browsers compile an <input pattern="…"> as /^(?:…)$/v. With the `v` flag a stray "-" or "(" inside a character
 * class is a syntax error: the browser then IGNORES the pattern (only a console error), so client-side validation
 * silently disappears. Every pattern attribute in the app must compile with the `v` flag.
 */
function tsxFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? tsxFiles(join(dir, e.name)) : e.name.endsWith(".tsx") ? [join(dir, e.name)] : [],
  );
}

describe("HTML pattern attributes", () => {
  const root = join(__dirname, "..");
  const patterns = tsxFiles(root).flatMap((f) => [...readFileSync(f, "utf8").matchAll(/\bpattern="([^"]+)"/g)].map((m) => ({ file: f.slice(root.length + 1), pattern: m[1] })));

  it("finds the app's patterns", () => {
    expect(patterns.length).toBeGreaterThanOrEqual(4);
  });

  it.each(patterns)("$file: $pattern compiles with the v flag (as browsers do)", ({ pattern }) => {
    expect(() => new RegExp(`^(?:${pattern})$`, "v")).not.toThrow();
  });

  it("the bank short-code pattern still accepts and rejects what the server does", () => {
    const p = patterns.find((x) => x.file.includes("bank-admin"))?.pattern ?? "";
    const re = new RegExp(`^(?:${p})$`, "v");
    expect(["bank-a", "b1", "abc-def-9"].every((s) => re.test(s))).toBe(true);
    expect(["-bank", "bank-", "Bank", "a_b"].some((s) => re.test(s))).toBe(false);
  });
});
