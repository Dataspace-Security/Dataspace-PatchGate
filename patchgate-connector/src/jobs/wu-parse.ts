import { z } from "zod";
import { resultSchemas, type JobPackage } from "../protocol.ts";
import { permanent } from "./errors.ts";

/**
 * Windows-update jobs (WU_SCAN / WU_INSTALL): the contract with the PC-side scripts
 * (patchgate-web/scripts/endpoint/Invoke-PatchGateWuScan.ps1, Install-PatchGateWinUpdate.ps1).
 * Script output is UNTRUSTED (it comes from a PC): it is parsed strictly and clipped to the protocol limits.
 */

export const RESULT_PREFIX = "PATCHGATE_RESULT=";
/** Error text when a script printed no result line (killed, timed out, or Tactical answered "timeout"). */
export const NO_RESULT_LINE = "no result line from script";
export const WU_PACKAGE_ID = "Microsoft.WindowsUpdate";
export const SCAN_CAB_PACKAGE_ID = "Microsoft.WsusScan";
export const MICROSOFT_PUBLISHER = "O=Microsoft Corporation";
/** PG_UPDATES budget per script run (Windows environment block ≤ 32 KiB; Tactical passes env on a command). */
export const MAX_UPDATES_ENV_CHARS = 6000;

const GUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const SEG = "[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?";
export const SCAN_CAB_PATH_RE = /^winupdate\/wsusscan\/[a-f0-9]{16}\/wsusscn2\.cab$/;
/** One PG_UPDATES entry; MUST match $FileRe in Install-PatchGateWinUpdate.ps1. */
export const UPDATE_ENTRY_RE = new RegExp(`^(${GUID}),(KB[0-9]{4,8}|-),(msu|cab),([a-f0-9]{64}),([0-9]{1,10}),(winupdate/${GUID}/${SEG})$`);

/** The last PATCHGATE_RESULT= line, JSON-decoded. Tactical may return the output JSON-quoted. */
export function extractResultJson(output: string): unknown {
  let text = output;
  if (text.startsWith('"')) {
    try {
      const unq = JSON.parse(text) as unknown;
      if (typeof unq === "string") text = unq;
    } catch {
      // not a JSON string: use as is
    }
  }
  const line = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith(RESULT_PREFIX))
    .pop();
  if (!line) throw new Error("no result line from script");
  try {
    return JSON.parse(line.slice(RESULT_PREFIX.length)) as unknown;
  } catch {
    throw new Error("result line is not valid JSON");
  }
}

const failSchema = z.object({ ok: z.literal(false), error: z.string() });
type ScanAgent = z.infer<(typeof resultSchemas)["WU_SCAN"]>["agents"][number];
const scanUpdatesSchema = resultSchemas.WU_SCAN.shape.agents.element.shape.updates.unwrap();

/** Parse one agent's scan output into a WU_SCAN agent entry (errors become a per-agent error). */
export function parseScanOutput(agentId: string, output: string): ScanAgent {
  let body: unknown;
  try {
    body = extractResultJson(output);
  } catch (err) {
    return { agentId, error: (err as Error).message };
  }
  const fail = failSchema.safeParse(body);
  if (fail.success) return { agentId, error: `scan failed on PC: ${fail.data.error}`.slice(0, 2000) };
  const ok = z.object({ ok: z.literal(true), updates: z.array(z.unknown()).max(5000) }).safeParse(body);
  if (!ok.success) return { agentId, error: "unexpected scan output" };
  const updates = scanUpdatesSchema.safeParse(ok.data.updates.slice(0, 1000));
  if (!updates.success) {
    const issue = updates.error.issues[0];
    return { agentId, error: `invalid scan output at ${issue?.path.join(".") ?? "?"}: ${issue?.message ?? "?"}`.slice(0, 2000) };
  }
  return { agentId, updates: updates.data };
}

const installOkSchema = z.object({
  ok: z.literal(true),
  installed: z.array(z.string().regex(new RegExp(`^${GUID}$`, "i"))).max(100),
  skipped: z.array(z.string().regex(new RegExp(`^${GUID}$`, "i"))).max(100),
  failed: z.array(z.object({ updateId: z.string().max(64), error: z.string() })).max(100),
  rebootRequired: z.boolean(),
  rebootScheduled: z.boolean(),
});
export type InstallRun = z.infer<typeof installOkSchema>;

export function parseInstallOutput(output: string): { ok: true; run: InstallRun } | { ok: false; error: string } {
  let body: unknown;
  try {
    body = extractResultJson(output);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
  const fail = failSchema.safeParse(body);
  if (fail.success) return { ok: false, error: fail.data.error.slice(0, 1500) };
  const ok = installOkSchema.safeParse(body);
  if (!ok.success) return { ok: false, error: "unexpected install script output" };
  return { ok: true, run: ok.data };
}

/** Defence in depth: the scan catalog package must be exactly what the scan script accepts. */
export function assertScanCab(p: JobPackage): void {
  if (p.kind !== "wsusscan" || p.wingetId !== SCAN_CAB_PACKAGE_ID || p.publisher !== MICROSOFT_PUBLISHER || p.switches !== "") {
    throw permanent("scanCab must be the Microsoft wsusscan package");
  }
  if (!SCAN_CAB_PATH_RE.test(p.repoPath)) throw permanent("scanCab repoPath invalid");
}

/** One update's files as PG_UPDATES entries (validated like the install script validates them). */
export function updateEntries(u: { updateId: string; kb: string | null; files: JobPackage[] }): string[] {
  const id = u.updateId.toLowerCase();
  return u.files.map((f) => {
    if (f.kind !== "msu" && f.kind !== "cab") throw permanent(`update ${id}: file kind ${f.kind} not allowed`);
    if (f.wingetId !== WU_PACKAGE_ID || f.publisher !== MICROSOFT_PUBLISHER || f.switches !== "") throw permanent(`update ${id}: not a Microsoft update package`);
    if (!f.repoPath.startsWith(`winupdate/${id}/`) || !f.repoPath.endsWith(`.${f.kind}`)) throw permanent(`update ${id}: file path does not belong to the update`);
    const entry = `${id},${u.kb ?? "-"},${f.kind},${f.sha256},${f.size},${f.repoPath}`;
    if (!UPDATE_ENTRY_RE.test(entry)) throw permanent(`update ${id}: invalid file entry`);
    return entry;
  });
}

/** Split updates into script runs whose PG_UPDATES fits the budget; an update is never split. */
export function batchUpdates<T extends { updateId: string; entries: string[] }>(updates: readonly T[], budget = MAX_UPDATES_ENV_CHARS): T[][] {
  const batches: T[][] = [];
  let cur: T[] = [];
  let len = 0;
  for (const u of updates) {
    const size = u.entries.join(";").length + 1;
    if (size > budget) throw permanent(`update ${u.updateId} has too many files for one script run`);
    if (cur.length > 0 && len + size > budget) {
      batches.push(cur);
      cur = [];
      len = 0;
    }
    cur.push(u);
    len += size;
  }
  if (cur.length > 0) batches.push(cur);
  return batches;
}
