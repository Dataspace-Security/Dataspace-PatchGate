import { describe, expect, it } from "vitest";
import {
  detailsUrl,
  downloadDialogUrl,
  kbFromTitle,
  lookupCatalogUpdate,
  parseDetails,
  parseDownloadDialog,
  planCatalogBinding,
  WU_MAX_FILES_PER_UPDATE,
  type CatalogLookup,
} from "./catalog";

// Captured from https://www.catalog.update.microsoft.com on 2026-10-15 (KB5044284, Server 2025 x64), trimmed.
const ID = "a62b9737-1fe8-4df1-94b4-8ec61855a8d0";
const LCU = "windows11.0-kb5044284-x64_d7eb7ceaa4798b92b988fd7dcc7c6bb39476ccf3.msu";
const CHECKPOINT = "windows11.0-kb5043080-x64_953449672073f8fb99badb4cc6d5d7849b9c83e8.msu";
const DIALOG = `<script type="text/javascript">
var downloadInformation = new Array();
downloadInformation[0] = new Object();
downloadInformation[0].updateID ='${ID}';
downloadInformation[0].isHotFix =false;
downloadInformation[0].enTitle ='2024-10 Cumulative Update for Microsoft server operating system version 24H2 for x64-based Systems (KB5044284)';
downloadInformation[0].sizeLanguage ='';
downloadInformation[0].files = new Array();
downloadInformation[0].files[0] = new Object();
downloadInformation[0].files[0].url = 'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/72f34af9-6ab3-4bb0-9dfe-103e56a305fb/public/${LCU}';
downloadInformation[0].files[0].digest = '1+t86qR5i5K5iP19zHxrs5R2zPM=';
downloadInformation[0].files[0].sha256 = '5K6xozxfc2SN2PsHtF6/W9aaCMiZ3drPwVGua3cxcYU=';
downloadInformation[0].files[0].architectures = '';
downloadInformation[0].files[0].languages = '';
downloadInformation[0].files[0].longLanguages = '';
downloadInformation[0].files[0].fileName = '${LCU}';
downloadInformation[0].files[0].defaultFileNameLength = 190;
downloadInformation[0].files[1] = new Object();
downloadInformation[0].files[1].url = 'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/d8b7f92b-bd35-4b4c-96e5-46ce984b31e0/public/${CHECKPOINT}';
downloadInformation[0].files[1].digest = 'lTRJZyBz+PuZuttMxtXXhJucg+g=';
downloadInformation[0].files[1].sha256 = 'gZYyYQoQGvEccpB/sT/wW1+0IiwOJj7poDvMHR1fJqQ=';
downloadInformation[0].files[1].architectures = '';
downloadInformation[0].files[1].languages = '';
downloadInformation[0].files[1].longLanguages = '';
downloadInformation[0].files[1].fileName = '${CHECKPOINT}';
downloadInformation[0].files[1].defaultFileNameLength = 190;
downloadInformation[0].allFilesExist = false;
</script>`;
const DETAILS = `<div id="titleDiv">
        <span id="ScopedViewHandler_titleText">2024-10 Cumulative Update for Microsoft server operating system version 24H2 for x64-based Systems (KB5044284)</span>
    </div>
    <div id="updateIdDiv">
        <span id="ScopedViewHandler_UpdateID">${ID}</span>
    </div>
                        <div id="classificationDiv">
                            <span id="ScopedViewHandler_labelClassification_Separator" class="labelTitle">Classification:</span>

                                    Security Updates
                        </div>
                            <div id="msrcSeverityDiv">
                                <span id="ScopedViewHandler_labelSecurityBulliten_Separator" class="labelTitle">MSRC severity:</span>
                                <span id="ScopedViewHandler_msrcSeverity">Critical</span>
                            </div>
                            <div id="kbDiv" class="textDoubleSpacer">
                                <span id="ScopedViewHandler_labelKBArticle_Separator" class="labelTitle">KB article numbers:</span>

                                        5044284

                            </div>`;

const found = (o: Partial<Extract<CatalogLookup, { found: true }>> = {}): Extract<CatalogLookup, { found: true }> => {
  const d = parseDownloadDialog(DIALOG, ID);
  if (!d.found) throw new Error("fixture");
  return { found: true, updateId: ID, title: d.title, details: parseDetails(DETAILS, ID)!, files: d.files, ...o };
};

describe("Microsoft Update Catalog parsing (captured responses)", () => {
  it("parses the download dialog: official URLs + SHA-1 + SHA-256 per file", () => {
    const d = parseDownloadDialog(DIALOG, ID.toUpperCase());
    expect(d.found).toBe(true);
    if (!d.found) return;
    expect(d.title).toContain("(KB5044284)");
    expect(d.files.map((f) => f.fileName)).toEqual([LCU, CHECKPOINT]);
    expect(d.files[0]).toMatchObject({ digest: "1+t86qR5i5K5iP19zHxrs5R2zPM=", sha256: "5K6xozxfc2SN2PsHtF6/W9aaCMiZ3drPwVGua3cxcYU=", languages: "" });
  });
  it("refuses a dialog for another update / an error page", () => {
    expect(parseDownloadDialog(DIALOG, "11111111-2222-3333-4444-555555555555").found).toBe(false);
    expect(parseDownloadDialog("<html><body>We did not find any results</body></html>", ID).found).toBe(false);
  });
  it("parses title, classification, severity and KB from the details page", () => {
    expect(parseDetails(DETAILS, ID)).toEqual({
      title: "2024-10 Cumulative Update for Microsoft server operating system version 24H2 for x64-based Systems (KB5044284)",
      kb: "KB5044284",
      msrcSeverity: "Critical",
      classification: "Security Updates",
    });
    expect(parseDetails(DETAILS, "11111111-2222-3333-4444-555555555555")).toBeNull();
    expect(kbFromTitle("x (KB5044284)")).toBe("KB5044284");
  });
  it("builds exact-host GET URLs for one GUID", () => {
    expect(downloadDialogUrl(ID.toUpperCase())).toMatch(/^https:\/\/www\.catalog\.update\.microsoft\.com\/DownloadDialog\.aspx\?updateIDs=/);
    expect(decodeURIComponent(downloadDialogUrl(ID))).toContain(`"updateID":"${ID}"`);
    expect(detailsUrl(ID)).toBe(`https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=${ID}`);
    expect(() => downloadDialogUrl("x'];alert(1)//")).toThrow();
  });
});

describe("planCatalogBinding (authoritative update → files)", () => {
  it("binds the catalog files with both digests, checkpoint (other KB) first", () => {
    const b = planCatalogBinding(found());
    expect(b.ok).toBe(true);
    if (!b.ok) return;
    expect(b).toMatchObject({ kb: "KB5044284", msrcSeverity: "Critical", classification: "Security Updates" });
    expect(b.files.map((f) => [f.ordinal, f.name])).toEqual([
      [0, CHECKPOINT],
      [1, LCU],
    ]);
    expect(b.files[1]).toMatchObject({ sha1: "d7eb7ceaa4798b92b988fd7dcc7c6bb39476ccf3", kind: "msu" });
    expect(b.files[1].expectedSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(b.files.every((f) => f.url.startsWith("https://catalog.sf.dl.delivery.mp.microsoft.com/"))).toBe(true);
  });
  it("refuses: no files, too many, foreign host, wrong digests, wrong KB, language sets, exe", () => {
    const f0 = found().files[0];
    const no = (o: Partial<Extract<CatalogLookup, { found: true }>>) => planCatalogBinding(found(o));
    expect(no({ files: [] })).toMatchObject({ ok: false, reason: expect.stringContaining("no downloadable") });
    expect(no({ files: Array.from({ length: WU_MAX_FILES_PER_UPDATE + 1 }, () => f0) })).toMatchObject({ ok: false, reason: expect.stringContaining("too many") });
    expect(no({ files: [{ ...f0, url: `https://evil.example/filestreamingservice/files/x/public/${LCU}` }] })).toMatchObject({ ok: false });
    expect(no({ files: [{ ...f0, digest: "lTRJZyBz+PuZuttMxtXXhJucg+g=" }] })).toMatchObject({ ok: false, reason: expect.stringContaining("differs from its name") });
    expect(no({ files: [{ ...f0, digest: null }] })).toMatchObject({ ok: false, reason: expect.stringContaining("no SHA-1") });
    expect(no({ files: [{ ...f0, sha256: "zz" }] })).toMatchObject({ ok: false, reason: expect.stringContaining("SHA-256") });
    expect(no({ files: [found().files[1]] })).toMatchObject({ ok: false, reason: expect.stringContaining("KB5044284") });
    expect(no({ files: [{ ...f0, languages: "de" }, { ...found().files[1], languages: "fr" }] })).toMatchObject({ ok: false, reason: expect.stringContaining("language") });
    expect(no({ files: [{ ...f0, url: f0.url.replace(".msu", ".exe") }] })).toMatchObject({ ok: false });
  });
  it("keeps the catalog's metadata even when refusing (for the bank's view)", () => {
    expect(planCatalogBinding(found({ files: [] }))).toMatchObject({ ok: false, kb: "KB5044284", msrcSeverity: "Critical" });
  });
  it("looks up through an injected fetcher (two GETs on the catalog host only)", async () => {
    const urls: string[] = [];
    const r = await lookupCatalogUpdate(ID, async (u) => {
      urls.push(u);
      return u.includes("DownloadDialog") ? DIALOG : DETAILS;
    });
    expect(r.found).toBe(true);
    expect(urls.every((u) => new URL(u).hostname === "www.catalog.update.microsoft.com")).toBe(true);
    expect(await lookupCatalogUpdate(ID, async () => "<html>error</html>")).toEqual({ found: false });
  });
});
