# PatchGate Agent (v2) — design

Status: **proposal** (2026-10-17). Goal: let a bank run PatchGate **without Tactical RMM**. A small PatchGate
Agent on each PC does exactly one thing — patch management — and nothing else.

Today: PatchGate → signed jobs → connector → **Tactical** → runs our fixed scripts on the PC.
v2: PatchGate → signed jobs → connector (site gateway + cache) → **PatchGate Agent** on the PC.

Everything that makes PatchGate valuable stays unchanged: downloads + signature verification, quarantine,
approval (maker-checker / approval switch), rings, windows, progress, audit chain + SIEM, reports, the site cache,
LAN protection. Only the "deliver to the PC" layer is replaced.

---

## 1. Why

| | Tactical (today) | PatchGate Agent (v2) |
|---|---|---|
| What runs on bank PCs | a full remote-management tool (remote shell, any script, file transfer) | **only** signed patch jobs: no shell, no arbitrary scripts |
| Misuse risk | needs sealing, break-glass, audit-log watching, real-time approval guard | removed at the source: the agent cannot do anything PatchGate didn't sign |
| Bank server footprint | Tactical + MeshCentral + Postgres + Redis + NATS (~20 containers) | connector + cache (2–3 containers) |
| Install / upgrade time | long (Tactical images, MeshCentral build) | short |
| Failure modes | Tactical internals (NATS race, celery, Mongo) | ours only |
| Control over UX | limited (Tactical's agent) | full: progress, reboot prompts, compliance data |

Tactical stays supported: per bank, **delivery engine = Tactical | PatchGate Agent**, so pilots can switch PC by PC.

## 2. Architecture

```
                      internet (PatchGate only)
                               │
 ┌─────────────────────────────▼──────────────────────────────┐
 │ PatchGate server  (unchanged)                               │
 │  fetcher → verify → quarantine → approval → signer (Ed25519)│
 └─────────────────────────────┬──────────────────────────────┘
                               │ outbound HTTPS (connector polls)
 ┌──────────── bank LAN ───────▼──────────────────────────────┐
 │ Site connector = gateway + package cache (no internet)      │
 │  • relays PatchGate-signed jobs to agents (cannot forge)    │
 │  • serves verified files (HTTPS :8443, sha256-addressed)    │
 │  • aggregates agent results → PatchGate                     │
 │  • LAN protection: per-site concurrency + bandwidth caps    │
 └───────┬──────────────────────┬─────────────────────────────┘
         │ HTTPS (LAN only)     │
   ┌─────▼─────┐          ┌─────▼─────┐
   │ Agent PC1 │   ...    │ Agent PCn │   Windows service "PatchGateAgent"
   └───────────┘          └───────────┘
```

* PCs never talk to the internet and never to PatchGate directly — only to their site connector.
* The connector is a **relay**, not a trust anchor: every job is signed end-to-end by PatchGate's per-bank
  job-signing key; the agent verifies that signature itself. A compromised site server cannot make agents run
  anything PatchGate didn't sign.

## 3. Agent

**Language: Go.** One static binary (~10–15 MB), no runtime to install, native Windows service support,
easy to sign, low memory (~20–40 MB). (Alternatives: .NET 8 self-contained — larger; Rust — slower to build
team-wide.)

**Runs as** a Windows service under `LocalSystem` (needed to install updates), started automatically,
recovery = restart on failure. Installed under `C:\Program Files\PatchGate\Agent\`, state in
`C:\ProgramData\PatchGate\` (ACL: SYSTEM + Administrators only — the protection already used by the PC installer).

**Fixed job types only** (typed, schema-validated, signed, with expiry ≤ 72 h — same rules as today's protocol):

| Job | What the agent does |
|---|---|
| `INVENTORY` | OS build, installed hotfixes, installed software (registry uninstall keys + MSI), disk/boot time, Windows Update lock state |
| `WU_SCAN` | offline scan with Microsoft's signed `wsusscn2.cab` from the site cache (Windows Update Agent API, `ServerSelection=ssOthers`, offline) → missing updates |
| `WU_INSTALL` | download approved `.msu/.cab` files from the cache, verify SHA-256 + Microsoft Authenticode, install with `wusa`/DISM, report per KB |
| `PKG_INSTALL` | third-party package (MSI/EXE) from the cache: verify SHA-256 + publisher signature (pinned publisher), silent install with the arguments in the signed job, verify the version afterwards |
| `REBOOT` | reboot according to policy (never / if required / always), inside the window, with user notice + deferral limit |
| `AGENT_UPDATE` | new agent version from the cache, signed by us, installed by the agent's updater (approved like any other change request) |
| `WU_LOCK` | (re)apply the Windows Update lock policy and report its state |

There is **no** "run command", "run script", remote shell, file browser or screen access. Unknown job types are
rejected.

**Reuse:** the PowerShell logic we already ship (`Invoke-PatchGateWuScan.ps1`, the WU install logic, the lock
values in `Install-PatchGateAgent.ps1`) is embedded in the binary in phase 1 (hash-pinned, never downloaded),
then ported to native Go (COM via `go-ole`) where it pays off.

## 4. Enrolment and identity

1. The bank admin (or the bank installer) creates a **PC enrolment token** in PatchGate (exists today for
   Tactical: `--pc-token`, 72 h default, max 720 h) — scoped to one site.
2. The agent installer (MSI) is run on the PC (double-click, GPO, Intune, SCCM) with `patchgate-pc.json`
   (site URL, site CA, token, PatchGate job-key fingerprint).
3. On first start the agent generates an **Ed25519 key pair** (private key DPAPI-protected, machine scope),
   and enrols: `POST /agent/v1/enrol {token, publicKey, hostname, hardwareId}` → gets an agent id.
4. The connector forwards the enrolment to PatchGate; PatchGate records the device (Endpoint) under the bank.
   Optional bank setting: **new devices need admin approval** before they receive jobs.
5. Every later request is signed by the agent key (nonce + timestamp, like today's connector protocol);
   the agent pins the **site TLS certificate/CA** and the **PatchGate job-key fingerprint** from enrolment.

Re-imaging / renaming: hardware id + re-enrolment with a new token; the old device is marked replaced.

## 5. Communication

* Agent → connector: HTTPS on the bank LAN only, long-poll `GET /agent/v1/jobs` (default every 60 s ± jitter,
  configurable), results `POST /agent/v1/results`. Both signed by the agent key.
* Files: `GET https://pg-cache.<domain>:8443/repo/<sha256…>` (exists today), resumable, verified on the PC.
* Connector → PatchGate: the existing outbound connector protocol, extended with agent jobs/results
  (additive job types in `protocol.ts`, same signer).
* Offline PCs: jobs wait until expiry; on return the agent picks them up (inside the window).
* LAN protection: unchanged — the connector enforces per-site `maxConcurrentInstalls`, bandwidth caps and
  staggering; the agent downloads only when its job is released.

## 6. Security model

| Threat | Control |
|---|---|
| Forged job (site server / LAN attacker) | agent verifies PatchGate's Ed25519 signature + bank key fingerprint pinned at enrolment; expiry; replay ids |
| Malicious file in the cache | agent verifies SHA-256 from the signed job **and** Authenticode (Microsoft / pinned vendor publisher) before running |
| Local user tampering | service + state ACLs (SYSTEM/Admins), private key DPAPI machine-protected, service stop/uninstall → missed heartbeats → alert in PatchGate |
| Agent used as a backdoor | no generic command/script capability exists in the binary; fixed job set; code review + reproducible build |
| Supply chain of the agent itself | built by `release/release.sh` (SBOM, vulnerability scan), **Authenticode-signed with an EV code-signing certificate**, MSI signed, agent updates only via approved change request |
| Rogue device enrolment | short-lived site-scoped tokens, optional admin approval of new devices, audit event per enrolment |

All agent actions are audited on the bank's chain (as today) and reach the bank SIEM through the connector.

## 7. Packaging and deployment

* **MSI** (WiX) — silent install for GPO / Intune / SCCM; parameters: site URL, token, CA, fingerprint
  (or the `patchgate-pc.json` next to the MSI).
* The existing double-click `Install-PatchGateAgent.cmd` keeps working: it installs the MSI instead of Tactical.
* The bank installer (`installers/bank/install.sh`) gets `--delivery agent|tactical` (default stays `tactical`
  until v2 is proven); with `agent` it skips Tactical/MeshCentral entirely.
* Uninstall: MSI uninstall (admin) — reported to PatchGate; Windows Update lock removal optional.

## 8. PatchGate server changes

* `Endpoint.deliveryEngine` (`TACTICAL | AGENT`), `Endpoint.agentPublicKey`, `agentVersion`, device approval flag.
* Planner: same deployment pipeline; for `AGENT` endpoints it emits agent job types instead of Tactical ones.
* UI: Endpoints shows the engine; new "Devices waiting for approval" list (if enabled); agent version column.
* Protocol: additive job/result types (both `protocol.ts` copies + signer allow-list), as done for every
  extension so far.
* Nothing changes in approval, quarantine, rings, windows, reports, audit, roles.

## 9. Phased plan

| Phase | Scope | Exit criterion | Estimate |
|---|---|---|---|
| **P0 Spike** | Go service skeleton, enrolment against a test connector, INVENTORY job end-to-end | a VM shows up in PatchGate via the agent | 1 week |
| **P1 Windows updates** | WU_SCAN + WU_INSTALL + WU_LOCK + REBOOT, results/progress in PatchGate | one approved KB installed on the VMware Windows VM through the agent | 2 weeks |
| **P2 Third-party apps** | PKG_INSTALL (MSI/EXE, publisher pin, silent args, version check) | VLC / 7-Zip update approved + installed | 1 week |
| **P3 Hardening** | ACLs, tamper alerts, device approval, AGENT_UPDATE, MSI, EV signing, AV testing (Defender + one bank AV) | security review clean; no AV blocks | 1–2 weeks |
| **P4 Pilot** | `--delivery agent` in the bank installer; mixed mode (some PCs Tactical, some agent) | 2–3 pilot PCs patched for 2 weeks without issues | 1–2 weeks |
| **P5 Default** (optional) | agent becomes default for new banks; Tactical optional | — | — |

**Total to a solid first version: about 5–8 weeks**, plus the EV certificate (procurement typically 1–3 weeks;
start in parallel with P0).

## 10. Testing

* Windows 10 22H2, Windows 11 23H2/24H2/25H2, Windows Server 2016/2019/2022/2025 (VMware snapshots).
* Offline (no internet on PC), slow LAN, PC asleep / offline during window, reboot pending, low disk.
* Antivirus: Defender + at least one common bank EDR; SmartScreen behaviour of the signed MSI.
* Security: job forgery, replayed jobs, tampered cache file, service stop, uninstall by a non-admin.
* Scale: 1 000 simulated agents against one connector (CPU, memory, LAN bandwidth caps honoured).

## 11. Risks and open decisions

| Item | Note |
|---|---|
| EV code-signing certificate | required to avoid AV/SmartScreen blocks; company identity verification needed |
| Windows Update Agent COM edge cases | mitigated by reusing the already-proven PowerShell logic first |
| Banks that already use Tactical | keep `tactical` engine; per-PC migration path |
| Remote support needs | the agent deliberately has none; banks keep their own remote-support tool |
| Decision | go / no-go for P0 — and who owns the EV certificate request |
