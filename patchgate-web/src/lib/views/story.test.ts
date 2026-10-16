import { describe, expect, it } from "vitest";
import {
  crProgress,
  deploymentStage,
  fmtAgo,
  installedVersionsFor,
  nextWindowStart,
  ofN,
  pcStatus,
  pcStatusLabel,
  pct,
  pickAttention,
  plural,
  rankMissingPatches,
  startOfMonthUtc,
  type StageInput,
} from "./story";

const NOW = new Date("2026-10-15T12:00:00Z");
const base: StageInput = { status: "QUEUED", note: null, error: null, failureKind: null, windowOpen: null, connectorOnline: true, job: null, now: NOW };

describe("numbers", () => {
  it("always shows counts with their total", () => {
    expect(ofN(7, 10)).toBe("7 of 10");
    expect(ofN(50000, 50000)).toBe("50,000 of 50,000");
  });

  it("percent never rounds to 0 or 100 unless it really is", () => {
    expect(pct(0, 10)).toBe(0);
    expect(pct(1, 1000)).toBe(1);
    expect(pct(999, 1000)).toBe(99);
    expect(pct(10, 10)).toBe(100);
    expect(pct(3, 0)).toBeNull();
  });

  it("plural + relative time", () => {
    expect(plural(1, "PC")).toBe("1 PC");
    expect(plural(2, "PC")).toBe("2 PCs");
    expect(plural(3, "patch", "patches")).toBe("3 patches");
    expect(fmtAgo(null, NOW)).toBe("never");
    expect(fmtAgo(new Date(NOW.getTime() - 20_000), NOW)).toBe("just now");
    expect(fmtAgo(new Date(NOW.getTime() - 2 * 60_000), NOW)).toBe("2 min ago");
    expect(fmtAgo(new Date(NOW.getTime() - 5 * 3_600_000), NOW)).toBe("5 h ago");
    expect(fmtAgo(new Date(NOW.getTime() - 3 * 86_400_000), NOW)).toBe("3 days ago");
    expect(fmtAgo(new Date(NOW.getTime() + 30 * 60_000), NOW)).toBe("in 30 min");
  });

  it("month start is UTC midnight on the 1st", () => {
    expect(startOfMonthUtc(NOW).toISOString()).toBe("2026-10-01T00:00:00.000Z");
  });
});

describe("PC compliance", () => {
  it("unscanned beats everything; scanned with no missing patch is up to date", () => {
    expect(pcStatus({ lastScanAt: null, missing: 3, critical: 1 })).toEqual({ kind: "unscanned" });
    expect(pcStatus({ lastScanAt: NOW, missing: 0, critical: 0 })).toEqual({ kind: "uptodate" });
    expect(pcStatus({ lastScanAt: NOW, missing: 4, critical: 1 })).toEqual({ kind: "needs", missing: 4, critical: 1 });
  });

  it("labels", () => {
    expect(pcStatusLabel({ kind: "unscanned" })).toEqual({ label: "Not scanned yet", tone: "neutral" });
    expect(pcStatusLabel({ kind: "uptodate" })).toEqual({ label: "Up to date", tone: "good" });
    expect(pcStatusLabel({ kind: "needs", missing: 4, critical: 1 })).toEqual({ label: "Needs 4 · 1 critical", tone: "bad" });
    expect(pcStatusLabel({ kind: "needs", missing: 2, critical: 0 })).toEqual({ label: "Needs 2", tone: "warn" });
  });

  it("finds installed versions of an app like the ingest does (regex, case-insensitive), invalid patterns match nothing", () => {
    const items = [
      { name: "Mozilla Firefox (x64 en-US)", version: "150.0" },
      { name: "mozilla firefox ESR", version: "150.0" },
      { name: "Notepad++", version: null },
    ];
    expect(installedVersionsFor(items, "^Mozilla Firefox")).toEqual(["150.0"]);
    expect(installedVersionsFor(items, "^Notepad\\+\\+")).toEqual(["unknown version"]);
    expect(installedVersionsFor(items, "(")).toEqual([]);
  });
});

describe("what to fix first", () => {
  it("ranks by PCs × severity, then by PCs", () => {
    const ranked = rankMissingPatches([
      { patchId: "low-many", pcs: 9, severity: "LOW" as const },
      { patchId: "crit-few", pcs: 2, severity: "CRITICAL" as const },
      { patchId: "imp", pcs: 5, severity: "IMPORTANT" as const },
      { patchId: "crit-more", pcs: 3, severity: "CRITICAL" as const },
    ]);
    expect(ranked.map((r) => r.patchId)).toEqual(["crit-more", "imp", "crit-few", "low-many"]);
  });

  it("keeps at most 6 attention items, most important first, ignoring empty slots", () => {
    const item = (key: string, priority: number) => ({ key, priority, text: key, href: "/", tone: "warn" as const });
    const picked = pickAttention([item("c", 3), null, false, item("a", 1), item("b", 1), item("d", 4), item("e", 5), item("f", 6), item("g", 7)]);
    expect(picked.map((i) => i.key)).toEqual(["a", "b", "c", "d", "e", "f"]);
  });
});

describe("deployment stage (per PC of a change request)", () => {
  it("queued: connector, cache, files, busy, window", () => {
    expect(deploymentStage({ ...base, connectorOnline: null }).label).toBe("Waiting for a site connector");
    expect(deploymentStage({ ...base, connectorOnline: false }).label).toBe("Waiting: site connector offline");
    expect(deploymentStage({ ...base, note: "waiting for the site cache" }).label).toBe("Downloading to bank (site cache)");
    const files = deploymentStage({ ...base, note: "waiting for Windows update files: file in quarantine until 2026-10-16" });
    expect(files).toMatchObject({ label: "Waiting for Microsoft files", detail: "file in quarantine until 2026-10-16" });
    expect(deploymentStage({ ...base, note: "endpoint busy with another change request" }).label).toBe("Waiting: PC busy with another change request");
    const win = deploymentStage({ ...base, windowOpen: false, nextWindowAt: new Date(NOW.getTime() + 3 * 3_600_000) });
    expect(win).toMatchObject({ key: "waiting-window", label: "Waiting for maintenance window", detail: "Next window starts in 3 h." });
    expect(deploymentStage(base)).toMatchObject({ key: "queued", done: false });
  });

  it("sending: scheduled, sent, installing, retrying", () => {
    const s = { ...base, status: "SENDING" as const };
    expect(deploymentStage({ ...s, job: { status: "QUEUED", notBefore: new Date(NOW.getTime() + 5 * 60_000) } })).toMatchObject({ key: "scheduled", label: "Scheduled" });
    expect(deploymentStage({ ...s, job: { status: "QUEUED", notBefore: NOW } }).label).toBe("Sent to the bank, waiting to start");
    expect(deploymentStage({ ...s, job: { status: "DELIVERED", notBefore: NOW } }).label).toBe("Installing");
    expect(deploymentStage({ ...s, note: "retry 1 scheduled after: agent offline" })).toMatchObject({ label: "Retrying (attempt 2)", detail: "Last try: agent offline" });
    expect(deploymentStage({ ...s, note: "Tactical messaging down at the site — retrying automatically (retry 3 scheduled)" })).toMatchObject({
      key: "tactical-down",
      label: "Waiting: Tactical messaging down at the site",
      tone: "warn",
      detail: expect.stringContaining("attempt 4"),
    });
    expect(deploymentStage({ ...s, note: "waiting for the site cache" }).label).toBe("Downloading to bank (site cache)");
  });

  it("sent / succeeded / timed out", () => {
    expect(deploymentStage({ ...base, status: "SENT" }).label).toBe("Installed — awaiting confirmation");
    expect(deploymentStage({ ...base, status: "SENT", note: "outcome unknown (timeout); confirming via inventory" }).key).toBe("outcome-unknown");
    expect(deploymentStage({ ...base, status: "SUCCEEDED" })).toMatchObject({ label: "Installed ✓ (confirmed)", tone: "good", done: true });
    expect(deploymentStage({ ...base, status: "SUCCEEDED", note: "nothing to install on this PC" }).label).toBe("Already up to date ✓");
    expect(deploymentStage({ ...base, status: "TIMED_OUT", failureKind: "INSTALL", error: "install not confirmed by collected inventory within timeout" })).toMatchObject({
      label: "Timed out",
      done: true,
    });
    expect(deploymentStage({ ...base, status: "TIMED_OUT", failureKind: "DEADLINE", error: "deadline passed" }).label).toBe("Not started: deadline passed");
  });

  it("failures say why, in plain words", () => {
    const f = { ...base, status: "FAILED" as const };
    expect(deploymentStage({ ...f, failureKind: "INSTALL", error: "PATCHGATE_RESULT=FAIL:msiexec 1603" }).label).toBe("Failed: PATCHGATE_RESULT=FAIL:msiexec 1603");
    expect(deploymentStage({ ...f, failureKind: "RING_STOPPED" }).label).toBe("Not started: rollout stopped");
    expect(deploymentStage({ ...f, failureKind: "UNMANAGED" }).label).toBe("Failed: no connector manages this PC");
    expect(deploymentStage({ ...f, failureKind: "CACHE", error: "x" }).label).toBe("Failed: bank site cache could not get the package");
    expect(deploymentStage({ ...f, failureKind: null, error: null }).label).toBe("Failed: no reason recorded");
    const long = deploymentStage({ ...f, failureKind: "INSTALL", error: "e".repeat(500) }).label;
    expect(long.length).toBeLessThan(200);
  });

  it("progress counts: done = confirmed + failed, total = every PC", () => {
    expect(crProgress({ SUCCEEDED: 3, FAILED: 1, TIMED_OUT: 1, SENT: 2, SENDING: 1, QUEUED: 2 })).toEqual({
      total: 10,
      done: 5,
      confirmed: 3,
      awaitingConfirmation: 2,
      inProgress: 1,
      waiting: 2,
      failed: 2,
    });
    expect(crProgress({}).total).toBe(0);
  });

  it("next window start honours the window's time zone", () => {
    const next = nextWindowStart({ cron: "0 2 * * *", timezone: "Asia/Kolkata" }, NOW);
    expect(next?.toISOString()).toBe("2026-10-15T20:30:00.000Z");
    expect(nextWindowStart({ cron: "not a cron", timezone: "UTC" }, NOW)).toBeNull();
  });
});
