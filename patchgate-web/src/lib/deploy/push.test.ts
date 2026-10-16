import { describe, expect, it, vi } from "vitest";
import { pushToEndpoint, MAX_SCAN_ROUNDS, type PushInput } from "./push";
import type { TacticalClient } from "@/lib/tactical/client";
import type { TacticalWinUpdate } from "@/lib/tactical/types";

type Upd = Pick<TacticalWinUpdate, "id" | "guid"> & Partial<TacticalWinUpdate>;
const u = (p: Upd): TacticalWinUpdate => ({
  kb: null,
  title: "t",
  installed: false,
  action: "nothing",
  severity: null,
  ...p,
});

/** In-memory Tactical: setUpdateAction mutates state; optional policy re-approves on read. */
function fakeTactical(initial: TacticalWinUpdate[], opts: { reapprove?: string[]; scriptOut?: string; agentVersion?: string } = {}) {
  let state = initial.map((x) => ({ ...x }));
  const calls: string[] = [];
  const client: TacticalClient = {
    listAgents: vi.fn(async () => []),
    getAgent: vi.fn(async () => ({ version: opts.agentVersion ?? "2.10.0", goarch: "amd64" })),
    scanUpdates: vi.fn(async () => void calls.push("scan")),
    getUpdates: vi.fn(async () => {
      if (opts.reapprove) {
        state = state.map((x) => (opts.reapprove!.includes(x.guid) ? { ...x, action: "approve" } : x));
      }
      return state.map((x) => ({ ...x }));
    }),
    setUpdateAction: vi.fn(async (pk, action) => {
      calls.push(`${action}:${pk}`);
      state = state.map((x) => (x.id === pk ? { ...x, action } : x));
    }),
    installApproved: vi.fn(async () => void calls.push("install")),
    getSoftware: vi.fn(async () => []),
    refreshSoftware: vi.fn(async () => void calls.push("refresh")),
    runScript: vi.fn(async (_a: string, input: { envVars: Record<string, string> }) => {
      calls.push(`script:${input.envVars.PG_KIND}`);
      return opts.scriptOut ?? "PATCHGATE_RESULT=OK";
    }),
  };
  return { client, calls };
}

const base: PushInput = {
  agentId: "agent-0001",
  attempt: 1,
  windowsGuids: new Set(["a"]),
  packages: [],
  repoUrl: "https://patchgate.bank.local/repo",
  installScriptId: 42,
};

const pkg = {
  kind: "msi" as const,
  wingetId: "Google.Chrome",
  version: "130.0.6723.59",
  sha256: "a".repeat(64),
  repoPath: "pkgs/Google.Chrome/130.0.6723.59/chrome.msi",
  publisher: "O=Google LLC",
};

describe("pushToEndpoint", () => {
  it("resets foreign approvals BEFORE approving ours, then installs", async () => {
    const { client, calls } = fakeTactical([
      u({ id: 1, guid: "a" }),
      u({ id: 2, guid: "b", action: "approve" }),
    ]);
    const out = await pushToEndpoint(client, base);
    expect(out).toEqual({ kind: "sent", targetGuids: ["a"], note: null });
    expect(calls).toEqual(["nothing:2", "approve:1", "install"]);
  });

  it("asks the agent to scan and retries when an approved patch is not visible yet", async () => {
    const { client, calls } = fakeTactical([u({ id: 1, guid: "x" })]);
    const out = await pushToEndpoint(client, base);
    expect(out.kind).toBe("retry");
    expect(calls).toEqual(["scan"]);
  });

  it("after max scan rounds proceeds without the missing patch and records a note", async () => {
    const { client, calls } = fakeTactical([u({ id: 1, guid: "a" })]);
    const out = await pushToEndpoint(client, {
      ...base,
      attempt: MAX_SCAN_ROUNDS,
      windowsGuids: new Set(["a", "z"]),
    });
    expect(out).toMatchObject({ kind: "sent", targetGuids: ["a"] });
    if (out.kind === "sent") expect(out.note).toMatch(/z/);
    expect(calls).toContain("install");
  });

  it("refuses to install and withdraws approvals if Tactical re-approves a foreign update", async () => {
    const { client, calls } = fakeTactical([u({ id: 1, guid: "a" }), u({ id: 2, guid: "b" })], {
      reapprove: ["b"],
    });
    await expect(pushToEndpoint(client, base)).rejects.toThrow(/approval state mismatch/);
    expect(calls).not.toContain("install");
    expect(calls).toContain("nothing:1");
  });

  it("does not call install when everything approved is already installed", async () => {
    const { client, calls } = fakeTactical([u({ id: 1, guid: "a", installed: true })]);
    expect(await pushToEndpoint(client, base)).toMatchObject({ kind: "sent", targetGuids: [] });
    expect(calls).not.toContain("install");
  });

  it("passes third-party values as env vars and checks the script result", async () => {
    const { client } = fakeTactical([]);
    await pushToEndpoint(client, { ...base, windowsGuids: new Set(), packages: [pkg] });
    expect(client.runScript).toHaveBeenCalledWith("agent-0001", {
      scriptId: 42,
      timeoutSec: 900,
      envVars: expect.objectContaining({ PG_SHA256: pkg.sha256, PG_PATH: pkg.repoPath }),
    });
  });

  it("fails when the install script reports failure", async () => {
    const { client } = fakeTactical([], { scriptOut: "PATCHGATE_RESULT=FAIL:signature" });
    await expect(
      pushToEndpoint(client, { ...base, windowsGuids: new Set(), packages: [pkg] }),
    ).rejects.toThrow(/signature/);
  });

  it("fails when no install script is configured", async () => {
    const { client } = fakeTactical([]);
    await expect(
      pushToEndpoint(client, {
        ...base,
        windowsGuids: new Set(),
        packages: [pkg],
        installScriptId: undefined,
      }),
    ).rejects.toThrow(/TACTICAL_INSTALL_SCRIPT_ID/);
  });
});

describe("third-party install with unknown outcome", () => {
  it("does NOT retry (no double install) when Tactical times out waiting for the script; confirms via inventory instead", async () => {
    const { TacticalError } = await import("@/lib/tactical/client");
    const { client } = fakeTactical([]);
    client.runScript = vi.fn(async () => {
      throw new TacticalError("Tactical unreachable (POST /agents/x/runscript/): timeout");
    });
    const out = await pushToEndpoint(client, { ...base, windowsGuids: new Set(), packages: [pkg] });
    expect(out.kind).toBe("sent");
    if (out.kind === "sent") expect(out.note).toMatch(/confirm/i);
    expect(client.runScript).toHaveBeenCalledTimes(1);
  });

  it("still fails on a definite HTTP error from Tactical", async () => {
    const { TacticalError } = await import("@/lib/tactical/client");
    const { client } = fakeTactical([]);
    client.runScript = vi.fn(async () => {
      throw new TacticalError("Tactical POST -> 403", 403);
    });
    await expect(pushToEndpoint(client, { ...base, windowsGuids: new Set(), packages: [pkg] })).rejects.toThrow(/403/);
  });
});

const agentPkg = {
  kind: "agent" as const,
  wingetId: "Tactical.Agent" as const,
  version: "2.11.0",
  sha256: "e".repeat(64),
  repoPath: "tactical/agent/2.11.0/tacticalagent-v2.11.0-windows-amd64.exe",
};

describe("Tactical agent upgrade", () => {
  it("runs the agent upgrade LAST (the agent restarts) after app installs", async () => {
    const { client, calls } = fakeTactical([]);
    await pushToEndpoint(client, { ...base, windowsGuids: new Set(), packages: [agentPkg, pkg] });
    expect(calls.filter((c) => c.startsWith("script:"))).toEqual(["script:msi", "script:agent"]);
  });

  it("skips the upgrade when the agent is already at or above the target", async () => {
    const { client, calls } = fakeTactical([], { agentVersion: "2.11.0" });
    const out = await pushToEndpoint(client, { ...base, windowsGuids: new Set(), packages: [agentPkg] });
    expect(calls).not.toContain("script:agent");
    if (out.kind === "sent") expect(out.note).toMatch(/already/);
  });

  it("does not refresh software inventory for an agent-only push", async () => {
    const { client, calls } = fakeTactical([]);
    await pushToEndpoint(client, { ...base, windowsGuids: new Set(), packages: [agentPkg] });
    expect(calls).not.toContain("refresh");
  });
});
