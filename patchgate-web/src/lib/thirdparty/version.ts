/** Version comparison + outdated detection for third-party apps (ARCHITECTURE §6A). */

/**
 * Numeric value of each segment, KEEPING positions: a leading "v" is stripped, and a non-numeric
 * segment counts as 0 instead of being dropped (dropping shifted "v2.9.0" to [9,0]).
 * Pre-release suffixes after "-"/"+" are ignored, so "2.11.0-rc1" == "2.11.0".
 */
function numericParts(v: string): number[] {
  return v
    .trim()
    .replace(/^v/i, "")
    .split(/[-+ ]/)[0]
    .split(/[._]/)
    .map((p) => {
      const n = Number.parseInt(p, 10);
      return Number.isFinite(n) ? n : 0;
    });
}

/** Returns <0, 0, >0. Trailing zero segments are ignored (1.0 == 1.0.0). */
export function compareVersions(a: string, b: string): number {
  const pa = numericParts(a);
  const pb = numericParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export interface InventoryItem {
  name: string;
  version: string;
}

export interface ManagedApp {
  appId: string;
  inventoryMatch: string; // regex against inventory name
  approvedVersion: string;
}

export interface OutdatedApp {
  appId: string;
  installedVersion: string;
  approvedVersion: string;
}

function safeRegex(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern, "i");
  } catch {
    return null;
  }
}

export function findOutdated(
  inventory: readonly InventoryItem[],
  apps: readonly ManagedApp[],
): OutdatedApp[] {
  const result: OutdatedApp[] = [];
  for (const app of apps) {
    const re = safeRegex(app.inventoryMatch);
    if (!re) continue;
    const installed = inventory.find((i) => re.test(i.name));
    if (installed && compareVersions(installed.version, app.approvedVersion) < 0) {
      result.push({
        appId: app.appId,
        installedVersion: installed.version,
        approvedVersion: app.approvedVersion,
      });
    }
  }
  return result;
}

/** True when an inventory entry matches and its version is >= target. Absent ⇒ false. */
export function isInstalledAtLeast(
  inventory: readonly InventoryItem[],
  inventoryMatch: string,
  targetVersion: string,
): boolean {
  const re = safeRegex(inventoryMatch);
  if (!re) return false;
  return inventory.some((i) => re.test(i.name) && compareVersions(i.version, targetVersion) >= 0);
}
