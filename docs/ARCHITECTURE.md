# Dataspace PatchGate — Architecture

> Controlled, approval-gated Windows patching for banks whose endpoints must never reach the internet.
> Status: **Draft v0.3** (phase-2 implemented: SIEM audit export, scan ingestion, fetcher + repo, WSUS connector, panel) · Owner: Dataspace Security · Date: 2026-10-14

---

## 1. Problem

Bank endpoints (branch PCs, teller machines, back-office desktops) must be patched, but:

- they must **not connect to the internet** directly (RBI / internal IS policy);
- **no patch may install without a recorded human approval** (change management);
- the bank must be able to **prove** patch compliance to auditors.

Tactical RMM can already scan and install Windows updates on agents, but its decision logic (auto-approval by severity, hourly schedule) lives inside Tactical and it fetches content via each PC's Windows Update configuration.

**PatchGate** moves *all decisions* into one controlled server with an admin panel. Tactical becomes a delivery pipe only.

```
Internet ──► PatchGate (app + WSUS + repo) ──► Tactical RMM (offline) ──► Windows PCs (offline)
              decides, fetches & stores          delivers only              execute
```

## 2. Goals / Non-goals

**Goals**
1. Single internet-facing component; endpoints have zero internet egress.
2. Every install is traceable to an approval (who, when, which patch, which machines).
3. Maker-checker approval (requester ≠ approver).
4. Ring-based rollout (Test → Pilot → Production) with maintenance windows per ring.
5. Compliance dashboard + exportable audit reports.
6. Re-use proven engines (WSUS for catalog/content, Tactical for delivery) — no custom patch-applicability logic.

**Non-goals (v1)**
- Third-party apps outside the curated allow-list (see §6A) — allow-list grows per bank request.
- Linux / macOS patching.
- Driver / firmware updates.
- Replacing Tactical's remote-control / monitoring features.

## 3. Components

> **Network rule (fixed):** PatchGate is the **only** component with internet access.
> Tactical RMM server, Tactical agents and all bank PCs are **fully offline** and receive
> everything (Windows patches, third-party installers, and Tactical's *own* updates) **only from PatchGate**.

| # | Component | Zone | Responsibility |
|---|---|---|---|
| 1 | **PatchGate App** (Next.js admin panel + API) | PatchGate zone | Catalog, approvals (maker-checker), rings, schedules, Tactical orchestration, audit log, reports. |
| 2 | **PostgreSQL** (via Prisma) | PatchGate zone | PatchGate state + append-only hash-chained audit log. |
| 3 | **PatchGate Fetcher** | PatchGate zone | The only process allowed outbound internet (allow-listed hosts): Microsoft Update (via WSUS), vendor installers (§6A), Tactical/MeshCentral releases (§6B). Verifies signature + hash, quarantines, publishes. |
| 4 | **WSUS (owned by PatchGate)** | PatchGate zone | Windows catalog sync + content store. Driven by PatchGate through a small connector (PowerShell `UpdateServices` wrapper). PCs scan/download from here. |
| 5 | **PatchGate Repo** | PatchGate zone (internal-facing HTTPS) | Read-only package repo for offline consumers: third-party installers, Tactical server/agent release bundles. Signed index. |
| 6 | **Tactical RMM server** | Offline zone | Delivery only — triggers scans/installs/scripts on agents via NATS. Own scheduler, auto-approval, auto-update **disabled**. No internet route. |
| 7 | **Tactical agent** | Offline zone (every PC) | Runs WUA scan/install against PatchGate's WSUS; runs the signed PatchGate install script for third-party packages. No internet route. |

### Stack (decided 2026-10-14)
- App: **Next.js 16 (App Router) + TypeScript**, code in `patchgate-web/`
- DB: **PostgreSQL 16 + Prisma 6**
- WSUS connector: PowerShell `UpdateServices` behind a small authenticated HTTP service on the WSUS host
- Auth: bank AD via **SAML (ADFS) / LDAPS** + mandatory MFA (dev stub until then)

## 4. Network & trust zones

```
 ┌────────────── Internet ──────────────┐
 │ Microsoft Update · vendor CDNs ·     │
 │ GitHub releases (Tactical/Mesh)      │
 └──────────────────┬───────────────────┘
                    │ 443 OUTBOUND ONLY, allow-listed hosts, from Fetcher/WSUS only
 ┌──────────────────▼───────────────────┐  PatchGate zone (DMZ-style, dual-homed)
 │ PatchGate App + Postgres             │◄── 443 ── Admin workstations (VPN/jump host, MFA)
 │ Fetcher · WSUS · Repo                │
 └──────────────────┬───────────────────┘
 ═══════════════════╪═════════════════════  internal firewall: inbound to PatchGate only,
                    │                        PatchGate → Tactical API only
 ┌──────────────────▼───────────────────┐  Offline zone (NO internet route at all)
 │ Tactical RMM server                  │──► pulls its own updates from PatchGate Repo
 │        │ NATS 443                    │
 │        ▼                             │
 │ Bank PCs + Tactical agent            │──► WSUS 8531 + Repo 443 on PatchGate only
 └──────────────────────────────────────┘
```

| From | To | Port | Purpose |
|---|---|---|---|
| PatchGate Fetcher / WSUS | Internet (allow-list) | 443 out | Patches, installers, Tactical releases |
| PatchGate App | Tactical API | 443 | Scan / approve / install / run-script |
| Bank PCs | PatchGate WSUS | 8531 | WUA scan + Windows content |
| Bank PCs | PatchGate Repo | 443 | Third-party packages (by signed install script) |
| Tactical server | PatchGate Repo | 443 | Tactical/Mesh/agent update bundles |
| Bank PCs | Tactical | 443 | Agent ↔ NATS |
| Admins | PatchGate App | 443 | Panel (MFA, mgmt network only) |
| Tactical server, PCs | Internet | — | **Denied** (enforced at firewall, not just config) |
| Internet | PatchGate | — | **Denied** (no inbound) |

> PatchGate is the single bridge, so it is the highest-value target: CIS-hardened, no inbound from the internet,
> egress allow-list enforced by the firewall, separate service accounts for Fetcher vs App, and
> for strict air-gap mandates split it into *PatchGate-Fetch* (internet) and *PatchGate-Serve* (internal)
> connected by one-way signed media (§8 Variant B).

## 5. Core flows

### 5.1 Catalog sync (nightly)
1. PatchGate WSUS syncs from Microsoft (products: Windows 10/11, Server versions in use; classifications: Security, Critical, Update Rollups, Definition Updates).
2. Only the PatchGate zone performs this sync; nothing in the offline zone ever contacts Microsoft.
3. Connector reports new/changed updates → Core stores them in `patch` table with KB, MSRC severity, CVEs, supersedence.
4. Panel shows **"New this cycle"** with severity + CVE links.

### 5.2 Scan & applicability (daily + on demand)
1. Core → Tactical `POST /winupdate/{agent_id}/scan/` for each agent (batched).
2. Agent's WUA scans **against PatchGate WSUS** (enforced by GPO + firewall) and reports to Tactical.
3. Core pulls `GET /winupdate/{agent_id}/` → stores `endpoint_patch_state` (needed / installed / failed).
4. Panel shows per-patch "machines needing it" and per-machine "missing patches".

### 5.3 Approval (maker-checker)
```
 DRAFT ──submit──► PENDING_APPROVAL ──approve──► APPROVED ──window opens──► DEPLOYING ──► COMPLETED
   ▲                      │                                                   │
   └──────reject──────────┘                                                   └─► PARTIAL / FAILED
```
- A **Change Request** = set of patches + target ring + maintenance window + reboot policy + change ticket ref.
- Maker (Patch Operator) creates/submits; Checker (Patch Approver) approves. Same user cannot do both (enforced server-side).
- On approval, Core approves the same updates in **WSUS** for the ring's WSUS computer group (so content is available) and records the approval in the audit log.

### 5.4 Deployment (inside maintenance window)
For each agent in the ring, Core:
1. Sets Tactical `action=approve` **only** for the approved KBs (`PUT /winupdate/{pk}/`), and `action=nothing` for everything else on that agent.
2. Calls `POST /winupdate/{agent_id}/install/`.
3. Agent downloads from PatchGate WSUS and installs; reboots per policy.
4. Core polls `GET /winupdate/{agent_id}/` until installed / timeout, updates state, writes audit events.
5. Ring auto-promotion is **never automatic** — next ring requires a new approval (or pre-approved promotion with soak-time + failure threshold, configurable).

### 5.5 Reporting
- Compliance % by branch / ring / severity; overdue critical patches (SLA, e.g. Critical ≤ 15 days).
- Per-change-request evidence pack (PDF/CSV): approvals, targets, results, timestamps.

## 6. Tactical integration — required configuration & gotchas

Verified against Tactical source (`api/tacticalrmm/winupdate/`, `agents/models.py`):

| Item | Setting / Fact | Why |
|---|---|---|
| Disable Tactical auto-approval | `TRMM_DISABLE_APPROVE_UPDATES_TASK = True` | Otherwise Tactical approves by severity every 8h. |
| Disable Tactical install schedule | `TRMM_DISABLE_WINUPDATES_INSTALL_TASK = True` | Otherwise Tactical installs approved updates hourly on its own. |
| Patch policy severities | Set **all** to `manual` in the default policy | ⚠️ `POST /install/` internally calls `agent.approve_updates()`, which re-approves by policy severity. `manual` makes it a no-op. |
| Install granularity | `/install/` installs **all** updates with `action=approve` on that agent | PatchGate must set every non-approved update to `nothing` before calling install. |
| No completion callback | Install is fire-and-forget (`wait=False`) | Core must poll for results. |
| Auth | Tactical API key via `X-API-KEY` header | Dedicated key, least-privilege user (win-update perms only), rotated. |
| Agent self-update | `TRMM_DISABLE_AGENT_AUTO_UPDATE_TASK = True` | Agent upgrades go through the same approval process. |
| Other egress | `INSTALL_NUSHELL=False`, `INSTALL_DENO=False`, Chocolatey off | No hidden internet downloads from endpoints. |

Endpoints used:

| Purpose | Method & path |
|---|---|
| List agents | `GET /agents/` |
| Trigger scan | `POST /winupdate/{agent_id}/scan/` |
| Read update state | `GET /winupdate/{agent_id}/` |
| Set approval | `PUT /winupdate/{pk}/` body `{"action": "approve" \| "nothing" \| "ignore"}` |
| Install | `POST /winupdate/{agent_id}/install/` |
| Reboot (if deferred) | `POST /agents/{agent_id}/reboot/` |

## 6A. Third-party application patching

Same principle as Windows patches: **PatchGate fetches, a human approves, Tactical delivers, PCs pull only from PatchGate.**
WSUS does not cover third-party apps, so PatchGate adds a **Third-Party Repository** module.

### Pipeline
```
winget-pkgs manifests (metadata)  ─┐
Vendor download URLs (allow-listed) ┴─► PatchGate Fetcher ─► verify ─► quarantine ─► PatchGate Repo (HTTPS)
                                                                                     │
Tactical software inventory ─► Core: version compare ─► "Outdated apps" ─► Change Request ─► approve
                                                                                     │
                                         Tactical runscript ─► PC downloads from Repo ─► silent install ─► re-inventory
```

| Step | How |
|---|---|
| **Catalog** | Curated allow-list of apps the bank uses (e.g. Chrome, Edge, Firefox, Adobe Reader, 7-Zip, Notepad++, Java/OpenJDK, Zoom, VLC). Metadata (latest version, installer URL, **SHA-256**, silent switches, product code) taken from Microsoft's open-source **winget-pkgs** manifests — no custom scraping per vendor. |
| **Fetch** | Download installer only from the vendor URL in the manifest; domain must be on the allow-list. |
| **Verify** | (1) SHA-256 must match manifest; (2) Authenticode signature valid **and** signer matches expected publisher (pinned per app); (3) AV/multi-engine scan (bank's AV / sandbox). Any failure → rejected, alert. |
| **Quarantine** | Optional soak (e.g. 48h) before the package is offered — avoids pulling a bad/compromised vendor release on day 0. |
| **Publish** | Copied to PatchGate Repo `https://patchgate.bank.local/repo/pkgs/<app>/<version>/` with signed index (hash list). |
| **Detect** | Tactical software inventory (`GET /software/{agent_id}/`, refresh via `PUT`) → Core compares installed version vs approved version → per-PC "outdated" list. |
| **Approve** | Same Change Request + maker-checker + rings + windows as Windows patches. |
| **Deploy** | Tactical `POST /agents/{agent_id}/runscript/` runs a **fixed, signed PatchGate install script** with args `(app, version, sha256)`: download from PatchGate Repo → re-verify hash + signature → silent install → exit code. Script is the only one the PatchGate API key may run. |
| **Confirm** | Core triggers inventory refresh and marks success when the new version is reported. |

### Rules
- **Never** use Tactical's built-in Chocolatey install (`POST /software/{agent_id}/`) — it pulls from the public Chocolatey feed. Keep Chocolatey disabled.
- Apps with built-in auto-updaters (Chrome, Firefox, Adobe, Zoom) must have auto-update **disabled by GPO/ADMX**, otherwise they try to reach the internet and drift from approved versions.
- Store **N-1** version in the repo for rollback; uninstall via product code / Tactical `uninstall` endpoint.
- Per-app pinned publisher certificate list is mandatory — hash-only verification is not enough if a vendor manifest is ever tampered with.

### Alternatives considered
| Option | Verdict |
|---|---|
| Publish third-party updates **into WSUS** (WSUS Package Publisher / SCUP, or commercial catalogs like Patch My PC) | Good if the bank already uses ConfigMgr/WSUS publishing; one pipeline for everything. Needs code-signing cert trusted by all PCs. Keep as **Option B**. |
| Internal Chocolatey feed (ProGet/Nexus) with internalized packages | Works, but package scripts often hard-code internet URLs; internalization needs paid Chocolatey for Business. |
| Commercial (ManageEngine, Ivanti) | Fastest, but adds another agent + licence cost; overlaps PatchGate. |

## 6B. Tactical RMM's own updates (offline)

Tactical server and agents never reach GitHub or `agents.tacticalrmm.com`. Their updates follow the same gate:

| Item | Normal Tactical behaviour | PatchGate-controlled |
|---|---|---|
| Server release (`update.sh`) | Pulls git, pip, npm, Docker images from internet | PatchGate Fetcher builds an **offline bundle** (release tarball + Python wheels + frontend build + images) → verify → Repo. After a change request is approved, the bank admin runs the offline update on the Tactical server from the Repo. |
| Agent binaries | Downloaded from GitHub / `agents.tacticalrmm.com` | Fetched by PatchGate, hash + signature checked, served from Repo. Agent auto-update disabled; upgrades go through a change request. |
| MeshCentral | npm update from internet | Mirrored in the same offline bundle. |
| Nushell / Deno | Downloaded on agents | Disabled (`INSTALL_NUSHELL=False`, `INSTALL_DENO=False`). |
| Code-signed agents (sponsor) | Token check against AmidaWare | Needs a one-off online step done **by PatchGate**, or unsigned agents — bank decision (see R1). |

## 7. Endpoint configuration (GPO)

- `Specify intranet Microsoft update service location` → `https://patchgate-wsus.bank.local:8531`
- `Do not connect to any Windows Update Internet locations` → **Enabled**
- `Configure Automatic Updates` → **2 – Notify for download and notify for install** (installs are driven by PatchGate/Tactical only)
- `Enable client-side targeting` → WSUS group = ring name (`Ring0-Test`, `Ring1-Pilot`, `Ring2-Prod`)
- Windows Firewall / perimeter: block all outbound internet from endpoint **and Tactical server** VLANs; allow only PatchGate WSUS (8531), PatchGate Repo (443) and Tactical (443).

## 8. Deployment variants

| Variant | Description | Use when |
|---|---|---|
| **A — Single bridge (default)** | PatchGate (app + WSUS + repo) dual-homed: allow-listed egress, serves the offline zone. | Standard bank network. |
| **B — Split / disconnected** | PatchGate-Fetch (internet) and PatchGate-Serve (internal) linked by signed, hashed one-way export media. | Strict air-gap mandate. |
| **C — Lab PoC** | PatchGate + Tactical on separate VMs in one lab network; Tactical VM and test PCs have no internet route. | Pilot only. |

## 9. Data model (core tables)

```
patch(id, kb, wsus_update_id, title, classification, msrc_severity, cves[], released_at, superseded_by)
endpoint(id, tactical_agent_id, hostname, branch, ring_id, os_build, last_scan_at)
endpoint_patch_state(endpoint_id, patch_id, status[needed|installed|failed|not_applicable], last_result, updated_at)
ring(id, name, wsus_group, order, default_window_id)
maintenance_window(id, ring_id, cron, duration_min, timezone, reboot_policy[never|required|always])
change_request(id, title, ticket_ref, ring_id, window_id, status, created_by, approved_by, created_at, approved_at)
change_request_patch(change_request_id, patch_id)
deployment(id, change_request_id, endpoint_id, status, started_at, finished_at, error)
user(id, upn, role[viewer|operator|approver|admin])
audit_event(id, ts, actor, action, entity, entity_id, payload_json, prev_hash, hash)   -- append-only, hash-chained
```

## 10. Security controls

| Area | Control |
|---|---|
| Identity | AD/SAML SSO + MFA; no local accounts except break-glass (sealed, alerted). |
| Authorization | RBAC: Viewer / Operator (maker) / Approver (checker) / Admin. Maker ≠ checker enforced in API. |
| Audit | Append-only, hash-chained `audit_event`; daily export to bank SIEM (syslog/CEF). |
| Secrets | Tactical API key + DB creds in Windows DPAPI / Vault — never in config files or repo. |
| Transport | TLS 1.2+ everywhere; mTLS between Core ↔ Connector; WSUS on HTTPS 8531 only. |
| Content integrity | Verify Microsoft Authenticode signature + SHA-256 of content at PatchGate ingestion and again on the PC before install (mandatory in all variants). |
| Hardening | CIS benchmark on all servers; Tactical web terminal & server scripts disabled; panel reachable only from mgmt VLAN / jump host. |
| Blast radius | Tactical API user scoped to win-update permissions; PatchGate cannot run arbitrary scripts. |
| Backups | Nightly encrypted Postgres + WSUS DB backups; restore tested quarterly. |

## 11. Risks & open questions

| # | Risk / question | Mitigation / owner |
|---|---|---|
| R1 | **Tactical license** — using Tactical inside a commercial Dataspace product/service requires AmidaWare written approval. | Business to obtain approval **before** build; alternative: bank self-hosts Tactical under its own license. |
| R2 | **WSUS deprecation** — Microsoft announced WSUS is deprecated (still supported, no new features). | Keep WSUS behind the Connector interface so it can be swapped (e.g. ConfigMgr, or a Catalog-based engine) later. |
| R3 | Branch bandwidth — monthly cumulative updates are large. | Per-branch cache (BranchCache / downstream WSUS), express/delta updates, staggered windows. |
| R4 | Offline PCs miss windows. | Window "catch-up" policy + overdue alerts in panel. |
| R5 | Failed install / boot loop. | Ring 0 soak time, failure-rate threshold blocks promotion, documented rollback (`wusa /uninstall /kb:`). |
| R6 | **Rolling vendor URLs** (found live, 2026-10-14): Chrome's winget installer URL always serves Google's latest build, so the manifest SHA-256 goes stale and the fetcher rejects it. | Fail-closed by design. v2: for allow-listed rolling-URL apps, trust = valid Authenticode + pinned publisher + version read from the MSI itself, with mandatory quarantine. |
| R7 | **Tactical public agent builds are not code-signed** (verified on v2.11.0). | Mirror only if SHA-256 equals GitHub's published digest; then held PENDING for explicit admin approval (audited). Code-signed agents need AmidaWare sponsorship (R1). |
| R8 | **WSUS strict mode hides un-approved updates from agents**: WSUS only offers clients updates approved for their group, so agent scans show approved-but-missing only. | Full "needed" view comes from the WSUS catalog export; deploy worker rescans ≤ 3 rounds while Sync-WsusApprovals (≤ 10 min) catches up. Option: approve-all in WSUS + GPO "remove access to Windows Update features" (PatchGate/Tactical remain the gate). |
| R9 | Audit DB tampering by a DB superuser (can disable triggers and delete rows; cannot re-forge the chain without the HMAC key held outside the DB). | HMAC key outside DB host; every event + ANCHOR streamed to SIEM; verify cross-checks anchors; SIEM alert on missing HEARTBEAT > 2 h. |
| Q1 | Which approval/change ticket system does the bank use (ServiceNow, etc.)? | Integrate `ticket_ref` validation in v2. |
| Q2 | Single bank or multi-tenant (multiple banks)? | Drives tenant isolation design. |

## 12. Delivery phases

| Phase | Scope | Exit criteria |
|---|---|---|
| **0 — PoC (2 wks)** | Variant C lab: WSUS + Tactical + 5 VMs; GPO; manual approve via Tactical; verify no internet egress from PCs. | Patch installed end-to-end with PCs blocked from internet. |
| **1 — MVP (6 wks)** | Core API, Connector, Panel: catalog view, scan, change request + maker-checker, single ring deploy, audit log. | Approved CR deploys to Ring 0; audit trail complete. |
| **2 — Rings & reporting (4 wks)** | Multi-ring, windows, reboot policies, compliance dashboard, evidence export, SIEM export. | Pilot branch runs one full Patch Tuesday cycle. |
| **3 — Hardening & audit (3 wks)** | Pen-test, CIS hardening, DR test, Variant B import tooling. | Bank IS audit sign-off. |
| **4 — Third-party apps (4 wks)** | §6A: winget-manifest catalog, fetch/verify/quarantine, internal repo, inventory compare, signed install script. | Top-10 bank apps patched through the same approval flow. |
| **5 — v2** | Ticketing integration, multi-tenant, WSUS-publishing option. | — |
