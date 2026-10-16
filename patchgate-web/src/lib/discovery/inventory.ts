import type { SoftwareItem } from "@/lib/tactical/types";
import { normalizeName, normalizePublisher, productCodeFromUninstall } from "./normalize";

export interface InventoryRow {
  name: string;
  publisher: string | null;
  version: string | null;
  productCode: string | null;
  normName: string;
  normPublisher: string | null;
}

const MAX_ITEMS = 2000; // a PC with more entries than this is misreporting; cap the write
const clip = (s: string, n: number) => s.trim().slice(0, n);

/** Tactical software list → rows to store (trimmed, normalised, deduplicated by name + version). */
export function inventoryRows(items: readonly SoftwareItem[]): InventoryRow[] {
  const seen = new Set<string>();
  const out: InventoryRow[] = [];
  for (const item of items.slice(0, MAX_ITEMS)) {
    const name = clip(item.name, 300);
    if (!name) continue;
    const version = item.version ? clip(item.version, 100) : null;
    const key = `${name}\u0000${version ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const normName = normalizeName(name).base;
    if (!normName) continue;
    out.push({
      name,
      publisher: item.publisher ? clip(item.publisher, 300) : null,
      version,
      productCode: productCodeFromUninstall(item.uninstall),
      normName,
      normPublisher: normalizePublisher(item.publisher),
    });
  }
  return out;
}
