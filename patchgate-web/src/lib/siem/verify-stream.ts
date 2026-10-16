/**
 * The checks a SIEM correlation rule (or an auditor's offline tool) runs over PatchGate's syslog stream,
 * in arrival order. These catch tampering that a DB-level attacker cannot hide, because the SIEM copy is
 * outside PatchGate's control:
 *  - chain-break: an AUDIT record whose prevHash is not the previous AUDIT record's hash
 *                 (tail rows deleted after export, then new events appended)
 *  - regression:  an ANCHOR/HEARTBEAT reporting a head seq lower than one already exported
 *                 (rows deleted, nothing new written)
 *  - fork:        the same seq seen with two different hashes (history rewritten)
 * A missing HEARTBEAT for > 2h (PatchGate silenced) is a time-based rule in the SIEM itself.
 *
 * Every record carries `chain` (a bank id, or "platform"): there is one independent hash chain per bank,
 * so all rules run per chain. Records without a chain belong to "platform" (pre-multi-bank exports).
 */

export interface SiemRecord {
  msgId: "AUDIT" | "ANCHOR" | "HEARTBEAT";
  seq: number;
  hash: string;
  prevHash?: string;
  chain?: string;
}

export interface SiemIssue {
  kind: "chain-break" | "regression" | "fork";
  chain: string;
  seq: number;
  detail: string;
}

interface ChainState {
  hashBySeq: Map<number, string>;
  lastAuditHash: string | null;
  maxSeq: number;
}

export const DEFAULT_CHAIN = "platform";

export function checkSiemStream(records: readonly SiemRecord[]): SiemIssue[] {
  const issues: SiemIssue[] = [];
  const states = new Map<string, ChainState>();

  for (const r of records) {
    const chain = r.chain ?? DEFAULT_CHAIN;
    let s = states.get(chain);
    if (!s) {
      s = { hashBySeq: new Map(), lastAuditHash: null, maxSeq: -1 };
      states.set(chain, s);
    }

    const seen = s.hashBySeq.get(r.seq);
    if (seen !== undefined && seen !== r.hash) {
      issues.push({ kind: "fork", chain, seq: r.seq, detail: `seq ${r.seq} exported as ${seen} and ${r.hash}` });
    } else if (seen === undefined) {
      s.hashBySeq.set(r.seq, r.hash);
    }

    if (r.msgId === "AUDIT") {
      if (s.lastAuditHash !== null && r.prevHash !== s.lastAuditHash) {
        issues.push({ kind: "chain-break", chain, seq: r.seq, detail: `prevHash ${r.prevHash} ≠ last exported ${s.lastAuditHash}` });
      }
      s.lastAuditHash = r.hash;
    } else if (r.seq < s.maxSeq) {
      issues.push({ kind: "regression", chain, seq: r.seq, detail: `${r.msgId} head ${r.seq} < exported ${s.maxSeq}` });
    }
    s.maxSeq = Math.max(s.maxSeq, r.seq);
  }
  return issues;
}
