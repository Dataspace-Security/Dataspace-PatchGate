/**
 * Winget-compatible normalisation of Windows "Add/Remove Programs" entries, so installed software
 * reported by Tactical can be matched to the winget source index (norm_names / norm_publishers).
 * Mirrors winget's NameNormalizer closely enough for matching (index form: "7zip(X64)", "microsoft").
 */
import { checkSafeRegex, SAFE_REGEX_MAX_LENGTH } from "@/lib/safe-regex";

export type Arch = "X64" | "X86" | "Arm64";

const ARCH_PATTERNS: [RegExp, Arch][] = [
  [/\b(?:arm64|aarch64)\b/gi, "Arm64"],
  [/\b(?:x64|x86[-_]64|amd64|win64|64[- ]?bits?)\b/gi, "X64"],
  [/\b(?:x86|i[36]86|win32|32[- ]?bits?)\b/gi, "X86"],
];
const LOCALE = /\b[a-z]{2,3}-[a-z]{2}\b/gi;
// "2.22.0.windows.1", "v1.2", "19.00", "0.82", "4.6.6", "1.2.3-beta"
const VERSION = /\bv?\d+(?:[.,]\d+)+(?:[.\-+_][0-9a-z]+)*\b/gi;
const NOISE_WORDS = /\b(?:version|release|build|update)\b/gi;
const LEGAL = new Set([
  "ab", "ag", "as", "bv", "co", "company", "corp", "corporation", "gmbh", "inc", "incorporated", "kg", "limited",
  "llc", "llp", "ltd", "nv", "oy", "plc", "pty", "sa", "sarl", "sas", "spa", "srl", "sro",
]);

export interface NormalizedName {
  /** Index form, e.g. "7zip(X64)" (arch suffix only when present) */
  indexed: string;
  /** Without arch, e.g. "7zip" */
  base: string;
  arch: Arch | null;
}

const alnum = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

export function normalizeName(raw: string): NormalizedName {
  let s = raw.normalize("NFKD").replace(/[̀-ͯ]/g, "");
  let arch: Arch | null = null;
  for (const [re, a] of ARCH_PATTERNS) {
    if (re.test(s)) arch ??= a;
    re.lastIndex = 0;
    s = s.replace(re, " ");
  }
  s = s.replace(LOCALE, " ").replace(VERSION, " ").replace(NOISE_WORDS, " ");
  const base = alnum(s);
  return { base, arch, indexed: arch ? `${base}(${arch})` : base };
}

export function normalizePublisher(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const words = raw
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/https?:\/\//gi, " ")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  while (words.length > 1 && LEGAL.has(words[words.length - 1])) words.pop();
  const out = words.join("");
  return out || null;
}

const PRODUCT_CODE = /msiexec(?:\.exe)?"?\s+\/[ix]\s*(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})/i;

/** MSI product code from an uninstall string ("MsiExec.exe /X{GUID}"), lower-case with braces. */
export function productCodeFromUninstall(uninstall: string | null | undefined): string | null {
  const m = uninstall ? PRODUCT_CODE.exec(uninstall) : null;
  return m ? m[1].toLowerCase() : null;
}

/** Grouping key for one product across the fleet. */
export function discoveryKey(normName: string, normPublisher: string | null): string {
  return `${normName}|${normPublisher ?? ""}`;
}

/** Product words before the first version number / parenthesis: "7-Zip 26.01 (x64 edition)" → "7-Zip". */
export function productStem(displayName: string): string {
  const words: string[] = [];
  for (const w of displayName.trim().split(/\s+/)) {
    if (w.startsWith("(") || /^v?\d+(?:[.,]\d+)+/i.test(w) || /^(?:version|release|build)$/i.test(w)) break;
    words.push(w);
    if (words.length === 4) break;
  }
  return words.length > 0 ? words.join(" ") : displayName.trim();
}

/**
 * Inventory regex (anchored, escaped) prefilled for the admin: the product stem, so future versions
 * still match ("7-Zip 26.01 (x64)" ← "^7-Zip").
 */
export function inventoryRegexFor(displayName: string): string {
  const stem = productStem(displayName).slice(0, SAFE_REGEX_MAX_LENGTH / 2 - 10);
  const re = `^${stem.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w+])`;
  // Escaped literal + one lookahead: safe by construction, but it runs on every bank's inventory — verify.
  const v = checkSafeRegex(re);
  if (!v.ok) throw new Error(`generated inventory regex rejected: ${v.reason}`);
  return re;
}
