import { resolve, sep } from "node:path";
import { describe, expect, it } from "vitest";
import { assertRepoRelPath, repoAbsPath } from "./repo";

const ROOT = resolve("/srv/repo");

describe("repo paths", () => {
  it("resolves valid paths under the root", () => {
    expect(repoAbsPath(ROOT, "pkgs/Google.Chrome/155.0/chrome.msi")).toBe(
      [ROOT, "pkgs", "Google.Chrome", "155.0", "chrome.msi"].join(sep),
    );
  });

  it.each(["../etc/passwd", "pkgs/../../x", "/abs", "pkgs//x", ".tmp/abc", "pkgs/a b", "pkgs\\x", ""])(
    "rejects %j",
    (p) => {
      expect(() => assertRepoRelPath(p)).toThrow();
    },
  );
});

describe("served roots and Windows aliases", () => {
  it.each(["PENDIN~1/tactical/x.exe", ".pending/tactical/x", "other/x.msi", "pkgs/foo./x.msi", "pkgs", "tactical/agent/2.11.0/x.exe."])(
    "rejects %j",
    (p) => {
      expect(() => assertRepoRelPath(p)).toThrow();
    },
  );
  it("accepts the two served trees", () => {
    expect(assertRepoRelPath("tactical/agent/2.11.0/tacticalagent-v2.11.0-windows-amd64.exe")).toBeTruthy();
    expect(assertRepoRelPath("pkgs/Microsoft.PowerShell/7.6.7.0/Microsoft.PowerShell-7.6.7.0.msi")).toBeTruthy();
  });
});
