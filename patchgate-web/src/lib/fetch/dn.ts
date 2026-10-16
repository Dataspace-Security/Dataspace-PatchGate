/**
 * Distinguished-name parsing for exact publisher pinning.
 * A pin is "O=<organisation>", or a list of up to 4 separated by ";" for vendors that renamed their
 * code-signing organisation (e.g. "O=Eclipse Foundation; O=Eclipse.org Foundation, Inc.").
 * Matching is EXACT (case-insensitive) against the certificate's O attribute — never a substring.
 */

const ORG = "O=[A-Za-z0-9 .,&()'+-]{2,200}";
export const PUBLISHER_PIN_RE = new RegExp(`^${ORG}(?: ?; ?${ORG}){0,3}$`);

/** Individual organisation names from a validated pin list. */
export function parsePins(pins: string): string[] {
  return pins.split(";").map((p) => p.trim().slice(2).trim().toLowerCase());
}

function splitRdns(dn: string): string[] {
  const trimmed = dn.trim();
  if (trimmed.startsWith("/")) return trimmed.split("/").filter(Boolean); // OpenSSL style
  const parts: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed[i];
    if (c === "\\" && i + 1 < trimmed.length) {
      cur += trimmed[++i];
      continue;
    }
    if (c === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && (c === "," || c === ";" || c === "\n" || c === "\r")) {
      if (cur.trim()) parts.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

export function parseDn(dn: string): [string, string][] {
  return splitRdns(dn).flatMap((rdn) => {
    const eq = rdn.indexOf("=");
    if (eq <= 0) return [];
    return [[rdn.slice(0, eq).trim().toUpperCase(), rdn.slice(eq + 1).trim()] as [string, string]];
  });
}

export function orgMatches(subject: string, pins: string): boolean {
  if (!PUBLISHER_PIN_RE.test(pins)) return false;
  const expected = new Set(parsePins(pins));
  return parseDn(subject).some(([k, v]) => k === "O" && expected.has(v.toLowerCase()));
}

const ORG_VALUE_RE = /^[A-Za-z0-9 .,&()'+-]{2,200}$/;
const MAX_PINS = 4;

/** The certificate's organisation (first O attribute), or null when it has none. */
export function signerOrgOf(subject: string): string | null {
  const o = parseDn(subject).find(([k]) => k === "O");
  return o ? o[1] : null;
}

/** True when an organisation can be expressed as a pin (character set, length). */
export function isPinnableOrg(org: string): boolean {
  return ORG_VALUE_RE.test(org);
}

/**
 * New pin list with `org` added (no-op if already present). Throws when the org can't be pinned or
 * the list is full — an admin must then edit the pins explicitly.
 */
export function appendPin(pins: string | null, org: string): string {
  if (!isPinnableOrg(org)) throw new Error(`Organisation "${org}" cannot be pinned`);
  if (!pins) return `O=${org}`;
  if (!PUBLISHER_PIN_RE.test(pins)) throw new Error("Existing pin list is invalid");
  const current = parsePins(pins);
  if (current.includes(org.toLowerCase())) return pins;
  if (current.length >= MAX_PINS) throw new Error(`Pin list already has ${MAX_PINS} organisations`);
  return `${pins}; O=${org}`;
}
