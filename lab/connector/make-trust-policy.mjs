// Generate a STARTING Bank A trust policy (connector.json "trust") from PatchGate's verified catalog.
// After generation it is the bank's own file: edit it, or delete it to regenerate. PatchGate cannot change it.
// Reads `psql -tAF'|'` rows on stdin: "<wingetId>|<publisher pins>" lines, a "--" line, then agent SHA-256 lines.
// Usage: (rows) | node lab/connector/make-trust-policy.mjs <out.json>
import { writeFileSync } from "node:fs";

let input = "";
process.stdin.on("data", (c) => (input += c));
process.stdin.on("end", () => {
  const lines = input.split(/\r?\n/).map((l) => l.trim());
  const sep = lines.indexOf("--");
  const appLines = (sep < 0 ? lines : lines.slice(0, sep)).filter(Boolean);
  const agentLines = (sep < 0 ? [] : lines.slice(sep + 1)).filter((l) => /^[a-f0-9]{64}$/.test(l));

  const publishers = {};
  for (const line of appLines) {
    const [id, pins = ""] = line.split("|");
    const set = new Set(publishers[id] ?? []);
    for (const p of pins.split(";").map((x) => x.trim()).filter(Boolean)) set.add(p.startsWith("O=") ? p : `O=${p}`);
    if (set.size > 0) publishers[id] = [...set];
  }
  const policy = { publishers, allowUnlistedApps: false, agentSha256: [...new Set(agentLines)] };
  writeFileSync(process.argv[2], JSON.stringify(policy, null, 2) + "\n");
  console.log(`wrote Bank A trust policy ${process.argv[2]} (${Object.keys(publishers).length} apps, ${policy.agentSha256.length} agent builds)`);
});
