// Run the SIEM-side tamper rules (same logic as patchgate-web/src/lib/siem/verify-stream.ts) over
// everything the lab SIEM received. Exit code 1 if tampering is detected.
// Usage: node lab/siem/check.mjs [sender-hostname]   e.g. bank-a-connector-hq (the Bank A connector relay);
//        without an argument every record is checked (only meaningful when ONE chain was sent here).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const text = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "received.log"), "utf8");
const re = / (AUDIT|ANCHOR|HEARTBEAT) \[patchgate@32473 seq="(\d+)" hash="([^"]+)"(?: prevHash="([^"]+)")?/;
const host = process.argv[2];
// RFC 5424: "<PRI>1 TIMESTAMP HOSTNAME APP-NAME ..." — keep one sender's stream when a host is given.
const lines = text.split("\n").filter((l) => !host || l.split(" ")[2] === host);
const records = lines.map((l) => re.exec(l)).filter(Boolean).map((m) => ({ msgId: m[1], seq: Number(m[2]), hash: m[3], prevHash: m[4] }));

const issues = [];
const hashBySeq = new Map();
let lastAudit = null;
let maxSeq = -1;
let unlinked = 0; // AUDIT records without prevHash (connector relay format): linkage cannot be checked
for (const r of records) {
  const seen = hashBySeq.get(r.seq);
  if (seen !== undefined && seen !== r.hash) issues.push(`FORK at seq ${r.seq}`);
  else if (seen === undefined) hashBySeq.set(r.seq, r.hash);
  if (r.msgId === "AUDIT") {
    if (r.prevHash === undefined) unlinked++;
    else if (lastAudit !== null && r.prevHash !== lastAudit) issues.push(`CHAIN-BREAK at seq ${r.seq}`);
    lastAudit = r.hash;
  } else if (r.seq < maxSeq) issues.push(`REGRESSION: ${r.msgId} seq ${r.seq} < ${maxSeq}`);
  maxSeq = Math.max(maxSeq, r.seq);
}
const counts = records.reduce((a, r) => ({ ...a, [r.msgId]: (a[r.msgId] ?? 0) + 1 }), {});
console.log(`SIEM received: ${JSON.stringify(counts)}; head seq ${maxSeq}`);
if (issues.length) {
  console.log("TAMPERING DETECTED:\n  " + issues.join("\n  "));
  process.exit(1);
}
if (unlinked) {
  console.log(`WARNING: ${unlinked} AUDIT record(s) carry no prevHash (connector relay format) — chain linkage NOT verifiable; checked: no fork, no regression.`);
} else {
  console.log("SIEM stream intact: chain continuous, no regression, no fork.");
}
