import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { resultSchemas } from "@/lib/connector/protocol";
import { renderMessage } from "@/lib/notify/templates";
import { readWuLockDetail, wuLockDetail, wuLockTransition } from "./wu-lock";

describe("Windows Update lock transitions", () => {
  it("alerts when a PC becomes NOT locked (also on its first report), not again while it stays unlocked", () => {
    expect(wuLockTransition(true, false)).toBe("broken");
    expect(wuLockTransition(null, false)).toBe("broken");
    expect(wuLockTransition(false, false)).toBe("none");
    expect(wuLockTransition(false, true)).toBe("restored");
    expect(wuLockTransition(true, true)).toBe("none");
    expect(wuLockTransition(null, true)).toBe("none");
  });

  it("stores issues + last outside install and reads stored JSON defensively", () => {
    const d = wuLockDetail({ locked: false, issues: Array.from({ length: 25 }, (_, i) => `i${i}`) });
    expect(d.issues).toHaveLength(20);
    expect(d.lastOutsideInstall).toBeNull();
    expect(readWuLockDetail(null)).toEqual({ issues: [], lastOutsideInstall: null });
    expect(readWuLockDetail({ issues: ["a", 5], lastOutsideInstall: { at: "x", title: 1 } })).toEqual({ issues: ["a"], lastOutsideInstall: null });
  });

  it("protocol: wuLock is optional and bounded", () => {
    const agent = { agentId: "agent-1", updates: [] };
    expect(resultSchemas.WU_SCAN.safeParse({ agents: [agent] }).success).toBe(true);
    expect(resultSchemas.WU_SCAN.safeParse({ agents: [{ ...agent, wuLock: { locked: true, issues: [] } }] }).success).toBe(true);
    expect(resultSchemas.WU_SCAN.safeParse({ agents: [{ ...agent, wuLock: { locked: "no", issues: [] } }] }).success).toBe(false);
    expect(resultSchemas.WU_SCAN.safeParse({ agents: [{ ...agent, wuLock: { locked: false, issues: Array(21).fill("x") } }] }).success).toBe(false);
  });

  it("renders the WU_LOCK_BROKEN notification with the PCs and problems", () => {
    const m = renderMessage("WU_LOCK_BROKEN", { bankName: "Bank A", connectorName: "HO", endpointCount: 1, hostnames: "pc-1", issues: "NoAutoUpdate is 0" }, "https://pg.example");
    expect(m.subject).toContain("Windows Update NOT locked on 1 PC — Bank A");
    expect(m.text).toContain("PCs: pc-1");
    expect(m.text).toContain("Problems: NoAutoUpdate is 0");
    expect(m.link).toBe("https://pg.example/endpoints");
  });
});

describe("PC scripts: the installer sets exactly the values the scan checks", () => {
  const root = resolve(__dirname, "../../../..");
  const installer = resolve(root, "installers/pc/Install-PatchGateAgent.ps1");
  const scan = resolve(root, "patchgate-web/scripts/endpoint/Invoke-PatchGateWuScan.ps1");
  const block = (file: string) => {
    const m = /# BEGIN PatchGate WU lock values[^\n]*\n([\s\S]*?)# END PatchGate WU lock values/.exec(readFileSync(file, "utf8").replace(/\r\n/g, "\n"));
    return m?.[1];
  };
  it.runIf(existsSync(installer) && existsSync(scan))("identical WU lock value blocks", () => {
    const a = block(installer);
    expect(a).toBeTruthy();
    expect(a).toContain("'NoAutoUpdate'; Type = 'DWord'; Value = 1");
    expect(a).toContain("'UseWUServer'; Type = 'DWord'; Value = 1");
    expect(block(scan)).toBe(a);
  });
});
