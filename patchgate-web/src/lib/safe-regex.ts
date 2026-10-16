/**
 * Guard for administrator-supplied regular expressions that run against EVERY bank's software inventory
 * (App.inventoryMatch). JavaScript regexes backtrack, so a catastrophic pattern ("(a+)+$", "(a|aa)*b",
 * ".*.*.*.*x") stalls the event loop for all banks (ReDoS). Conservative static check, no dependencies:
 *  - length cap, must compile (with the "i" flag it is used with)
 *  - no backreferences (\1, \k<name>)
 *  - star height 1: a repeated group may not contain a quantifier or an alternation
 *  - at most MAX_UNBOUNDED unbounded quantifiers (*, +, {n,}, {n,m>100}) in the whole pattern
 * Patterns a human writes for product names ("^Google Chrome", "^7-Zip(?![\w+])", "^Mozilla Firefox .*ESR")
 * pass; anything clever is refused with a reason.
 */
import { z } from "zod";

export const SAFE_REGEX_MAX_LENGTH = 200;
const MAX_UNBOUNDED = 2;
const LARGE_REPEAT = 100;

export type SafeRegexVerdict = { ok: true } | { ok: false; reason: string };

interface Frame {
  quantified: boolean; // contains a repeating quantifier (at any depth)
  alternation: boolean;
}

/** Parse a quantifier at s[i]; returns its length and whether it repeats (max > 1) / is unbounded. */
function quantifierAt(s: string, i: number): { len: number; repeats: boolean; unbounded: boolean } | null {
  const c = s[i];
  const lazy = (n: number) => (s[i + n] === "?" ? n + 1 : n);
  if (c === "*" || c === "+") return { len: lazy(1), repeats: true, unbounded: true };
  if (c === "?") return { len: lazy(1), repeats: false, unbounded: false };
  if (c === "{") {
    const m = /^\{(\d{1,6})(,(\d{0,6}))?\}/.exec(s.slice(i));
    if (!m) return null; // a literal "{" (no valid quantifier syntax)
    const min = Number(m[1]);
    const max = m[2] === undefined ? min : m[3] === "" ? Infinity : Number(m[3]);
    return { len: lazy(m[0].length), repeats: max > 1, unbounded: max === Infinity || max > LARGE_REPEAT };
  }
  return null;
}

export function checkSafeRegex(pattern: string): SafeRegexVerdict {
  if (pattern.length === 0) return { ok: false, reason: "empty pattern" };
  if (pattern.length > SAFE_REGEX_MAX_LENGTH) return { ok: false, reason: `longer than ${SAFE_REGEX_MAX_LENGTH} characters` };
  try {
    new RegExp(pattern, "i");
  } catch {
    return { ok: false, reason: "invalid regex" };
  }

  const stack: Frame[] = [{ quantified: false, alternation: false }];
  let unbounded = 0;
  let i = 0;
  // Applies a quantifier (if any) following an atom/group ending at index i; `inner` = the group just closed.
  const afterAtom = (inner: Frame | null): SafeRegexVerdict | null => {
    const q = quantifierAt(pattern, i);
    if (!q) return null;
    i += q.len;
    if (q.unbounded) unbounded++;
    if (unbounded > MAX_UNBOUNDED) return { ok: false, reason: `more than ${MAX_UNBOUNDED} unbounded quantifiers (* + {n,})` };
    if (q.repeats && inner && (inner.quantified || inner.alternation)) {
      return { ok: false, reason: "nested quantifier / repeated alternation (catastrophic backtracking)" };
    }
    if (q.repeats) stack[stack.length - 1].quantified = true;
    return null;
  };

  while (i < pattern.length) {
    const c = pattern[i];
    let verdict: SafeRegexVerdict | null = null;
    if (c === "\\") {
      const n = pattern[i + 1] ?? "";
      if (/[1-9]/.test(n) || n === "k") return { ok: false, reason: "backreferences are not allowed" };
      i += n === "u" && pattern[i + 2] === "{" ? pattern.indexOf("}", i) + 1 - i : n === "u" ? 6 : n === "x" ? 4 : 2;
      verdict = afterAtom(null);
    } else if (c === "[") {
      let j = i + 1;
      if (pattern[j] === "^") j++;
      if (pattern[j] === "]") j++;
      while (j < pattern.length && pattern[j] !== "]") j += pattern[j] === "\\" ? 2 : 1;
      i = j + 1;
      verdict = afterAtom(null);
    } else if (c === "(") {
      stack.push({ quantified: false, alternation: false });
      i++;
      if (pattern[i] === "?") {
        const m = /^\?(?::|=|!|<=|<!|<[A-Za-z_][A-Za-z0-9_]*>)/.exec(pattern.slice(i));
        i += m ? m[0].length : 1;
      }
    } else if (c === ")") {
      const inner = stack.pop();
      if (!inner || stack.length === 0) return { ok: false, reason: "unbalanced parentheses" };
      i++;
      const parent = stack[stack.length - 1];
      parent.quantified ||= inner.quantified;
      verdict = afterAtom(inner);
    } else if (c === "|") {
      stack[stack.length - 1].alternation = true;
      i++;
    } else {
      i++;
      verdict = afterAtom(null);
    }
    if (verdict) return verdict;
  }
  return { ok: true };
}

export function isSafeRegex(pattern: string): boolean {
  return checkSafeRegex(pattern).ok;
}

/** zod field for an inventory regex at an API boundary (2..200 chars, valid, backtracking-safe). */
export const safeRegexSchema = z
  .string()
  .min(2)
  .max(SAFE_REGEX_MAX_LENGTH)
  .superRefine((p, ctx) => {
    const v = checkSafeRegex(p);
    if (!v.ok) ctx.addIssue({ code: "custom", message: `unsafe or invalid regex: ${v.reason}` });
  });
