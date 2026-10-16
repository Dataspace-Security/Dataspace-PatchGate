/**
 * Result size limits. PatchGate rejects oversize result bodies (413); a COLLECT page of 200 agents with
 * 3,000 software entries each can reach tens of MB. Results are shrunk to fit instead of being lost:
 * software lists are dropped first, then update lists, and every agent that lost data is marked with a
 * per-agent error so PatchGate knows to re-collect it.
 */

/** Hard cap on one serialised result body (PatchGate accepts up to 32 MiB; keep a safety margin). */
export const MAX_RESULT_BYTES = 24 * 1024 * 1024;

export const jsonBytes = (v: unknown): number => Buffer.byteLength(JSON.stringify(v), "utf8");

export interface CollectAgentRow {
  agentId: string;
  updates?: unknown[];
  software?: unknown[];
  agent?: { version: string; goarch?: string | null };
  error?: string;
}

const OMITTED = (what: string, maxBytes: number) =>
  `${what} omitted: the COLLECT result exceeded the ${maxBytes}-byte result limit; collect this agent in a smaller batch`;

/**
 * Returns a COLLECT result that serialises to at most `maxBytes` (new objects; input not mutated).
 * Drops the largest software lists first, then the largest update lists. Throws if even that is not
 * enough (cannot happen with protocol-sized pages).
 */
export function fitCollectResult<T extends CollectAgentRow>(agents: readonly T[], maxBytes = MAX_RESULT_BYTES): { agents: T[]; trimmed: number } {
  let total = jsonBytes({ agents });
  if (total <= maxBytes) return { agents: [...agents], trimmed: 0 };
  const out: T[] = agents.map((a) => ({ ...a }));
  const trimmedIdx = new Set<number>();
  for (const field of ["software", "updates"] as const) {
    const order = out
      .map((a, i) => ({ i, bytes: a[field] ? jsonBytes(a[field]) : 0 }))
      .filter((x) => x.bytes > 0)
      .sort((x, y) => y.bytes - x.bytes);
    for (const { i } of order) {
      if (total <= maxBytes) break;
      const row = out[i] as T;
      const { [field]: _dropped, ...rest } = row;
      const what = field === "software" ? "software list" : "update list";
      const error = (row.error ? `${row.error}; ${OMITTED(what, maxBytes)}` : OMITTED(what, maxBytes)).slice(0, 2000);
      const next = { ...rest, error } as T;
      total += jsonBytes(next) - jsonBytes(row);
      out[i] = next;
      trimmedIdx.add(i);
    }
  }
  total = jsonBytes({ agents: out });
  if (total > maxBytes) throw new Error(`COLLECT result is ${total} bytes even without software/update lists`);
  return { agents: out, trimmed: trimmedIdx.size };
}
