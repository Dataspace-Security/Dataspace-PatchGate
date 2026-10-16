/** Hostname glob (* = any run, ? = one character) → anchored, case-insensitive RegExp. Exported for tests. */
export function globToRegExp(glob: string): RegExp {
  const body = [...glob].map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[.+^${}()|[\]\\-]/g, "\\$&"))).join("");
  return new RegExp(`^${body}$`, "i");
}
