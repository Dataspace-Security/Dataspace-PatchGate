import { describe, expect, it } from "vitest";
import { inventoryRows } from "./inventory";

describe("inventoryRows", () => {
  it("normalises, extracts product codes and deduplicates", () => {
    const rows = inventoryRows([
      { name: "7-Zip 26.01 (x64 edition)", version: "26.01.00.0", publisher: "Igor Pavlov", uninstall: "MsiExec.exe /I{23170F69-40C1-2702-2601-000001000000}" },
      { name: "7-Zip 26.01 (x64 edition)", version: "26.01.00.0", publisher: "Igor Pavlov", uninstall: null },
      { name: "Git", version: "2.55.0", publisher: "The Git Development Community", uninstall: '"C:\\Program Files\\Git\\unins000.exe"' },
      { name: "   ", version: "1" },
      { name: "1.2.3", version: "" },
    ]);
    expect(rows).toEqual([
      { name: "7-Zip 26.01 (x64 edition)", publisher: "Igor Pavlov", version: "26.01.00.0", productCode: "{23170f69-40c1-2702-2601-000001000000}", normName: "7zipedition", normPublisher: "igorpavlov" },
      { name: "Git", publisher: "The Git Development Community", version: "2.55.0", productCode: null, normName: "git", normPublisher: "thegitdevelopmentcommunity" },
    ]);
  });
  it("caps oversized inventories and long fields", () => {
    const many = Array.from({ length: 2500 }, (_, i) => ({ name: `App ${String.fromCharCode(97 + (i % 26))}${i}`, version: "1.0" }));
    expect(inventoryRows(many).length).toBe(2000);
    expect(inventoryRows([{ name: "x".repeat(500), version: "1" }])[0].name.length).toBe(300);
  });
});
