/** One-line description of an error including its cause chain (e.g. undici "fetch failed" → ECONNREFUSED). */
export function describeError(err: unknown): string {
  const parts: string[] = [];
  let cur: unknown = err;
  for (let depth = 0; cur && depth < 4; depth++) {
    if (cur instanceof Error) {
      const code = (cur as { code?: unknown }).code;
      parts.push(`${cur.name}: ${cur.message}${typeof code === "string" ? ` [${code}]` : ""}`);
      cur = (cur as { cause?: unknown }).cause;
    } else {
      parts.push(String(cur));
      break;
    }
  }
  return parts.join(" ← ").slice(0, 1000);
}
