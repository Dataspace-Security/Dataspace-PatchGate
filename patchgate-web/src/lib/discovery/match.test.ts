import { describe, expect, it } from "vitest";
import { matchProduct, type CatalogLookup } from "./match";
import { normalizeName, normalizePublisher } from "./normalize";

const PUBS: Record<string, string[]> = { "Google.Chrome": ["google"], "Vendor.A": ["vendor"], "Vendor.B": ["vendor"], "Junk.Pkg": ["junk"] };
const catalog: CatalogLookup = {
  publishersOf: (id) => PUBS[id] ?? [],
  idsByProductCode: (c) =>
    ({
      "{chrome}": ["Google.Chrome"],
      "{shared}": ["Vendor.A", "Vendor.B"],
      "{junk}": ["Junk.Pkg"],
      "{00000000-0000-0000-0000-000000000000}": ["Junk.Pkg"],
    })[c] ?? [],
  idsByNames: (names) =>
    [
      { name: "7zip(X64)", id: "7zip.7zip", publisher: "igorpavlov" },
      { name: "7zip", id: "7zip.7zip", publisher: "igorpavlov" },
      { name: "7zip(X64)", id: "Some.Fork", publisher: "someoneelse" },
      { name: "wireshark(X64)", id: "WiresharkFoundation.Wireshark", publisher: "wiresharkfoundation" },
      { name: "zoom", id: "Zoom.Zoom", publisher: "zoom" },
      { name: "tool", id: "Vendor.A", publisher: "vendor" },
      { name: "tool", id: "Vendor.B", publisher: "vendor" },
      { name: "mozillafirefox(X64)", id: "Mozilla.Firefox", publisher: "mozilla" },
      { name: "mozillafirefox(X64)", id: "Mozilla.Firefox.de", publisher: "mozilla" },
      { name: "googlechrome", id: "Google.Chrome", publisher: "google" },
      { name: "googlechrome", id: "Google.Chrome.EXE", publisher: "google" },
      { name: "adobeacrobat(X64)", id: "Adobe.Acrobat.Pro", publisher: "adobe" },
      { name: "adobeacrobat(X64)", id: "Adobe.Acrobat.Reader.64-bit", publisher: "adobe" },
      { name: "powershell", id: "Microsoft.PowerShell", publisher: "microsoft" },
    ].filter((r) => names.includes(r.name)),
};

const facts = (name: string, publisher: string | null, productCodes: string[] = []) => ({
  name: normalizeName(name),
  normPublisher: normalizePublisher(publisher),
  productCodes,
});

describe("matchProduct", () => {
  it("prefers an unambiguous product code", () => {
    expect(matchProduct(facts("Whatever", null, ["{chrome}"]), catalog)).toEqual({ wingetId: "Google.Chrome", match: "PRODUCT_CODE" });
    expect(matchProduct(facts("Whatever", "Google LLC", ["{chrome}"]), catalog)).toEqual({ wingetId: "Google.Chrome", match: "PRODUCT_CODE" });
  });
  it("ignores a product code whose package publisher disagrees (junk index data)", () => {
    expect(matchProduct(facts("Zoom", "Zoom", ["{junk}"]), catalog)).toEqual({ wingetId: "Zoom.Zoom", match: "NAME_PUBLISHER" });
  });
  it("ignores the nil GUID", () => {
    expect(matchProduct(facts("Unknown", null, ["{00000000-0000-0000-0000-000000000000}"]), catalog).match).toBe("NONE");
  });
  it("collapses variant packages to their parent id", () => {
    expect(matchProduct(facts("Mozilla Firefox (x64 en-US)", "Mozilla"), catalog).wingetId).toBe("Mozilla.Firefox");
    expect(matchProduct(facts("Google Chrome", "Google LLC"), catalog).wingetId).toBe("Google.Chrome");
  });
  it("keeps genuinely different products ambiguous", () => {
    expect(matchProduct(facts("Adobe Acrobat (64-bit)", "Adobe"), catalog).match).toBe("NONE");
  });
  it("falls back to the name without a trailing major version", () => {
    expect(matchProduct(facts("PowerShell 7-x64", "Microsoft Corporation"), catalog).wingetId).toBe("Microsoft.PowerShell");
  });
  it("matches name + publisher, ignoring a same-name package from another publisher", () => {
    expect(matchProduct(facts("7-Zip 19.00 (x64)", "Igor Pavlov"), catalog)).toEqual({ wingetId: "7zip.7zip", match: "NAME_PUBLISHER" });
  });
  it("matches the arch-suffixed index form", () => {
    expect(matchProduct(facts("Wireshark 4.6.6 x64", "Wireshark Foundation"), catalog).wingetId).toBe("WiresharkFoundation.Wireshark");
  });
  it("needs a publisher for name matches", () => {
    expect(matchProduct(facts("Zoom", null), catalog)).toEqual({ wingetId: null, match: "NONE" });
  });
  it("is NONE when the publisher differs", () => {
    expect(matchProduct(facts("Zoom", "Evil Inc"), catalog).match).toBe("NONE");
  });
  it("is NONE when name + publisher is still ambiguous", () => {
    expect(matchProduct(facts("Tool", "Vendor"), catalog).match).toBe("NONE");
  });
  it("uses an ambiguous product code to narrow name matches", () => {
    const narrowed: CatalogLookup = { ...catalog, idsByNames: () => [{ id: "Vendor.A", publisher: "vendor" }, { id: "Vendor.C", publisher: "vendor" }] };
    expect(matchProduct(facts("Tool", "Vendor", ["{shared}"]), narrowed)).toEqual({ wingetId: "Vendor.A", match: "NAME_PUBLISHER" });
  });
  it("is NONE for empty names", () => {
    expect(matchProduct(facts("1.2.3", "Vendor"), catalog).match).toBe("NONE");
  });
});
