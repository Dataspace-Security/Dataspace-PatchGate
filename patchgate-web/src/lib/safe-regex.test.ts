import { describe, expect, it } from "vitest";
import { checkSafeRegex, isSafeRegex, SAFE_REGEX_MAX_LENGTH } from "./safe-regex";
import { inventoryRegexFor } from "./discovery/normalize";

describe("checkSafeRegex (admin inventoryMatch → runs on every bank's inventory)", () => {
  it.each([
    "^Google Chrome",
    "^7-Zip(?![\\w+])",
    "^Mozilla Firefox .*ESR",
    "^Notepad\\+\\+",
    "^(Adobe Acrobat|Adobe Reader)( DC)?",
    "^VLC media player\\b",
    "^Microsoft Edge$",
    "^Java \\d+ Update \\d+",
    "^Python 3\\.\\d{1,2}",
    "[a-z]{2,4}-x64",
  ])("accepts %s", (p) => {
    expect(checkSafeRegex(p)).toEqual({ ok: true });
  });

  it.each([
    ["(a+)+$", "nested"],
    ["^(\\w+\\s?)*$", "nested"],
    ["((ab)*)+", "nested"],
    ["(a|aa)*b", "alternation"],
    ["(x{2,})+y", "nested"],
    [".*.*.*x", "unbounded"],
    ["(a)\\1", "backreference"],
    ["(?<n>a)\\k<n>", "backreference"],
    ["(", "invalid"],
    ["", "empty"],
    ["a".repeat(SAFE_REGEX_MAX_LENGTH + 1), "longer"],
  ])("rejects %s", (p, why) => {
    const v = checkSafeRegex(p);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toContain(why);
  });

  it("accepted patterns stay fast on adversarial input", () => {
    const input = `${"a".repeat(5000)}!`;
    for (const p of ["^a*b", "^(?:a|b)c", "a.*a.*!$", "^(a+b)?c"]) {
      expect(isSafeRegex(p), p).toBe(true);
      const t = performance.now();
      new RegExp(p, "i").test(input);
      expect(performance.now() - t, p).toBeLessThan(500);
    }
  });

  it("discovery-generated inventory regexes are always safe", () => {
    for (const name of ["7-Zip 26.01 (x64 edition)", "Notepad++ (64-bit x64)", "a+b*c?(d) [e] {f} | g \\ h", "Microsoft Visual C++ 2015-2022 Redistributable (x64)"]) {
      expect(checkSafeRegex(inventoryRegexFor(name)), name).toEqual({ ok: true });
    }
  });
});
