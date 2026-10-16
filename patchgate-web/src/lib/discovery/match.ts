import type { NormalizedName } from "./normalize";

/** Read-only view of the winget source index (implemented over SQLite; faked in tests). */
export interface CatalogLookup {
  /** winget ids that list this MSI product code */
  idsByProductCode(productCode: string): string[];
  /** (id, normalised publisher) pairs for any of these normalised names */
  idsByNames(names: readonly string[]): { id: string; publisher: string | null }[];
  /** normalised publishers recorded for a winget id */
  publishersOf(id: string): string[];
}

export interface ProductFacts {
  name: NormalizedName;
  normPublisher: string | null;
  productCodes: readonly string[];
}

export type MatchResult = { wingetId: string; match: "PRODUCT_CODE" | "NAME_PUBLISHER" } | { wingetId: null; match: "NONE" };

const NONE: MatchResult = { wingetId: null, match: "NONE" };
const NIL_GUID = "{00000000-0000-0000-0000-000000000000}";
export const MAX_NAME_CANDIDATES = 6;

/** Names to try in the index: arch form, plain, both arch suffixes, and without a trailing major version. */
export function nameCandidates({ base, indexed }: NormalizedName): string[] {
  const out = [indexed, base, `${base}(X64)`, `${base}(X86)`];
  const noMajor = base.replace(/\d+$/, "");
  if (noMajor.length >= 3 && noMajor !== base) out.push(noMajor, `${noMajor}(X64)`);
  return [...new Set(out)].slice(0, MAX_NAME_CANDIDATES);
}

/**
 * Collapse package variants: when one id is the parent of all others ("Mozilla.Firefox" vs
 * "Mozilla.Firefox.de", "Google.Chrome" vs "Google.Chrome.EXE"), the parent is the product.
 */
export function collapseVariants(ids: ReadonlySet<string>): string | null {
  if (ids.size === 0) return null;
  if (ids.size === 1) return [...ids][0];
  const sorted = [...ids].sort((a, b) => a.length - b.length);
  const root = sorted[0];
  return sorted.slice(1).every((id) => id.toLowerCase().startsWith(`${root.toLowerCase()}.`)) ? root : null;
}

/**
 * Map one installed product to a winget package. Conservative: an ambiguous or uncorroborated match
 * is NONE — the admin can still manage it by hand. A product code (exact MSI identity) wins, but only
 * when the package's publisher agrees: the community index has occasional junk product codes.
 */
export function matchProduct(p: ProductFacts, catalog: CatalogLookup): MatchResult {
  const codes = p.productCodes.filter((c) => c !== NIL_GUID);
  const byCode = new Set(codes.flatMap((c) => catalog.idsByProductCode(c)));
  const codeId = byCode.size > 0 ? collapseVariants(byCode) : null;
  if (codeId && (!p.normPublisher || catalog.publishersOf(codeId).includes(p.normPublisher))) {
    return { wingetId: codeId, match: "PRODUCT_CODE" };
  }

  if (!p.name.base || !p.normPublisher) return NONE;
  const rows = catalog.idsByNames(nameCandidates(p.name));
  const ids = new Set(rows.filter((r) => r.publisher === p.normPublisher).map((r) => r.id));
  // If product codes narrowed it to a few ids, stay inside that set when possible.
  const narrowed = byCode.size > 1 ? new Set([...ids].filter((id) => byCode.has(id))) : ids;
  const id = collapseVariants(narrowed.size > 0 ? narrowed : ids);
  return id ? { wingetId: id, match: "NAME_PUBLISHER" } : NONE;
}
