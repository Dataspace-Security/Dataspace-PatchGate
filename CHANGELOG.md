# Changelog

All notable changes to PatchGate are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/) — see docs/RELEASE.md for what counts as breaking.
`release/release.sh` copies the section of the version being released into `release-notes.md`.

Components versioned together (single `VERSION` file): PatchGate server (web, tools/migrate), connector,
signer, egress proxy, backup, site bundle. The connector protocol has its own integer version
(`PROTOCOL_VERSION`, currently 1); a protocol change is always called out below.

## [Unreleased]

### Added — Tactical messaging self-healing + visibility (protocol: optional heartbeat field, additive)
- **Site watchdog** (`installers/site/tactical/tactical-watchdog.sh`): after a reboot official Tactical's
  `trmm-nats` can lose a start-up race and Tactical answers every script run with `natsdown` (no PC reachable).
  `install-site.sh` install / `--upgrade` (and so `installers/bank/install.sh`) now installs
  `patchgate-tactical-watchdog.{service,timer}` (2 min after boot, then every minute, after `docker.service`;
  `/etc/cron.d/patchgate-tactical-watchdog` without systemd); `--uninstall` removes it, `--status` and the bank
  self-check show it. It restarts ONLY `trmm-nats` when nats-server is not running (same probe as `--status`),
  with back-off (1, 2, 4 … min apart, max 6 per hour), only while the site is meant to be up and never during an
  installer run (`state/watchdog.pause`), logs to journald/syslog (`patchgate-tactical-watchdog`) and writes the
  non-secret `etc/tactical-health.json` for the connector. Tactical images unchanged; the compose override adds a
  visibility-only healthcheck to `tactical-nats`. Both bundle builders ship the script.
- **Connector:** reports `tacticalHealth { state: ok | natsdown | unreachable, since, detail, watchdog }` in every
  heartbeat, from its own Tactical calls (natsdown answers, API without answer) and the watchdog file
  (`tactical.healthFile`, default `tactical-health.json` next to `connector.json`; ignored when older than 5 min).
- **Connector protocol (v1, additive):** optional `heartbeat.tacticalHealth` (both `protocol.ts` copies); older
  servers ignore it, older connectors omit it (PatchGate then shows `tactical.reachable` only, no timed alert).
- **PatchGate:** Connectors page badge "Tactical healthy / messaging down / unreachable" (since, watchdog
  restarts) and a red banner; dashboard attention item; `/operations` connectors cell turns red; metrics
  `patchgate_connector_tactical_health{state}` + `patchgate_connector_tactical_unhealthy_seconds`, alert rule
  `PatchGateTacticalMessagingDown` (P1). Unhealthy > 5 min at an online site → ONE critical `TACTICAL_UNHEALTHY`
  notification + `tactical.unhealthy` audit on the bank's chain per episode (NotificationAlert row, RLS);
  `TACTICAL_RECOVERED` + `tactical.recovered` when ok again. No migration.
- **Deployments:** an install answered `natsdown` (never sent to the PC) shows "Tactical messaging down at the
  site — retrying automatically" (stage "Waiting: Tactical messaging down at the site") and is retried at most
  5 min apart for up to 30 attempts within the maintenance window (was: failed after 5 attempts).
- Docs: RUNBOOK §14 "Tactical messaging down", BANK-INSTALL (watchdog).

### Added — real-time Tactical guard (protocol: new job type + connector push, additive)
- **Out-of-band approvals reset within ~30 seconds** (was: at the next COLLECT, ≤ 6 h / every 10 min for 2 h after
  human activity). The connector's new Tactical guard (`tactical.guardIntervalSec`, default 30, `0` = off;
  `tactical.guardMaxAgentReadsPerTick`, default 25) runs on the site: one `GET /agents/` (`has_patches_pending`)
  + `GET /winupdate/<agent>/` only for PCs with pending approvals (capped per round); an approval PatchGate did not
  authorise is reset at once (same as `RESET_APPROVALS`, verified by one re-read) and reported. PatchGate's own
  approvals of an open deployment window are never touched; leftovers of an ended window are withdrawn quietly;
  nothing is reset while the allow-set is unknown. State in `stateDir/tactical-guard.json` (0600).
- **Audit log in real time:** the guard reads Tactical's audit log from its own cursor every round and pushes
  out-of-band entries at once; visible under Connectors → Tactical activity within ~1 minute.
- **Connector protocol (v1, additive):** `POST /api/connector/v1/tactical-events` `TacticalPush { audit?:
  { afterId, events ≤ 200, cursor, reset? }, approvalResets?: ≤ 200 }` → `{ auditCursor, stored }` (signed like
  every connector request, 1 MiB body cap); job type `TACTICAL_GUARD_SYNC` `{ syncId, part, parts ≤ 50, allow ≤ 500
  entries { agentId, guids, until }, auditCursor }` → `{ allowEntries, known }` (PatchGate signs it when the
  heartbeat's new optional `guard` status reports `allowSetKnown: false`); signer job-type list updated;
  migration `20261016180000_tactical_realtime_guard` (enum value). Old connectors: unchanged behaviour (no
  `guard` in the heartbeat → no sync jobs; PatchGate keeps its COLLECT approval re-checks for them).
- **PatchGate:** pushes are ingested immediately with the same persistence as before (TacticalActivity source
  `APPROVAL_GUARD` / `AUDIT_LOG`, `tactical.out_of_band_action` on the bank's chain); `TACTICAL_OUT_OF_BAND` is
  coalesced (at most one per bank per 5 min; the next alert counts what was coalesced). Connectors page shows
  "Approval of KB… on DESKTOP-… reset automatically at hh:mm:ss UTC". `TACTICAL_AUDIT_SYNC` and the COLLECT
  comparison remain as backstop; the 10 min / 2 h approval re-read runs only for connectors without an armed guard.

### Added — approval switch, rollout progress, live pages, correct agent times
- **Approval on/off per bank** (Settings → Approval policy, "Approval required", default ON). Only an ADMIN (bank
  or platform) may switch it; audited (`bank_policy.approval_switched`) and notified (new **critical** event
  `APPROVAL_SETTING_CHANGED` → bank + platform admins). OFF: an admin's change request is approved on submit
  (`ChangeRequest.autoApproved`, audit `change_request.approval_skipped` with the policy reason) and can be
  deployed; emergency / two-approver rules apply only while ON. Amber note on the dashboard and change-request
  pages while OFF. Migration `20261016173000_approval_switch` drops CHECK `Tenant_requireBankApproval_always`.
- **Deployment progress bar** on the change request (and compact in the list): % finished, succeeded / failed /
  in progress / queued, endpoints per stage (queued → files downloading / verifying → caching at site →
  installing → reboot pending → succeeded / failed), derived from deployment status, wait notes and active jobs.
- **Live pages**: dashboard, change requests (list + detail), endpoints and connectors refresh themselves
  (`router.refresh`, 5 s while work is active, 30 s idle, paused in hidden tabs; "Live · updated Xs ago").
  Server-side only; connector polling is unchanged.
- **Agent times**: SYNC_AGENTS carries Tactical `last_seen` / `boot_time` (protocol v1, additive optional fields
  `lastSeen`, `bootTime`); PatchGate stores them in UTC (`Endpoint.lastSeenAt` = Tactical's last contact instead of
  the sync time, new `Endpoint.bootedAt`, migration `20261016173100_endpoint_agent_times`), guards clock skew (a
  future boot time is "unknown", never "-14543 seconds ago") and shows "seen / booted … ago" on the Endpoints page.

### Added — Tactical is sealed (protocol: new job type, additive)
- **Sealed site Tactical** (`installers/site/tactical/provision-site.py`, every install/upgrade/`--pc-token`):
  dashboard login blocked (`block_dashboard_login`) for every Tactical user except `patchgate-svc` and the
  agent-installer user, their dashboard sessions ended, every other API key expired, every patch policy (not
  only the default) set to manual, role "PatchGate service" gets `can_view_auditlogs`. `tacticaladmin` is now a
  break-glass account: `install-site.sh --break-glass on|off` (new `tactical/break-glass.py`, in the site bundle)
  unblocks / re-blocks it and writes the change to Tactical's audit log. Agent version fixed: Tactical's global
  agent auto-update (`CoreSettings.agent_auto_update`) turned off; re-enabling it is reported as "AGENT AUTO-UPDATE
  TURNED ON". `install-site.sh --status` ends with a read-only seal self-check. Official Tactical images, unmodified.
- **Connector protocol (v1, additive):** job type `TACTICAL_AUDIT_SYNC` `{ afterId, limit ≤ 500 }` → `{ events[],
  cursor, more, reset? }`; constants `MAX_TACTICAL_AUDIT_EVENTS`, `TACTICAL_SERVICE_USERNAME`. The connector reads
  `PATCH /logs/audit/` (read-only, newest first, back to the cursor) and returns entries not made by the service
  account (logins as it are always reported). Old connectors reject the unknown job type: upgrade connectors
  before (or with) the server; the signer's job-type list includes it.
- **PatchGate:** `TacticalActivity` table (RLS) + `Connector.tacticalAuditCursor/tacticalHumanSeenAt`
  (migration `20261016160000_tactical_seal`); every out-of-band entry is stored once, audited as
  `tactical.out_of_band_action` on the bank's chain and notified (new **critical** event `TACTICAL_OUT_OF_BAND`
  → platform + bank admins). Approval drift: update approvals PatchGate did not set (Tactical does not audit
  them) are found on every COLLECT page, alerted and reset with `RESET_APPROVALS` when no PatchGate deployment
  is in flight on that PC (now the backstop of the real-time guard above). Connectors page:
  "Tactical activity" list with a red badge; ADMIN acknowledges (`tactical.activity_acknowledged`), AUDITOR reads.
- **Endpoints page for connector banks:** "Sync agents now" queues `SYNC_AGENTS` at once (de-duplicated,
  audited `endpoints.sync_requested`); "Request scan of all PCs" syncs first, marks every PC due and — for
  `windowsUpdateSource=PATCHGATE` — requests a `WU_SCAN` that runs after the sync once the verified scan catalog
  is cached at the site (migration `20261016161000_connector_scan_request`, `Connector.wuScanRequestedAt`);
  the button shows what happens ("Syncing PCs from Tactical, then scanning …", catalog still downloading).
  Periodic `SYNC_AGENTS` every 15 min instead of hourly (`AGENT_SYNC_MINUTES`, 5–1440).

### Changed
- **User accounts are managed only by PatchGate platform admins.** Creating users, editing name / role / active,
  resetting a password and unlocking now return 403 ("Accounts are managed by PatchGate platform
  administrators") for bank admins and bank auditors; they keep a read-only list of their own bank's users
  (/admin/users shows no form and no row actions). Platform admins create the bank's admins and auditors
  (Admin → Users or `create-user.ts --tenant`). Closes the maker-checker gap where a bank admin could create a
  second admin, learn its temporary password and approve their own change request. Removed the now-unneeded
  bank-admin rules: "bank admins reset only auditors" (`user.reset_denied`) and the 30-day promotion cooldown
  after a bank-admin reset. The first sign-in after a reset is still flagged `afterReset=true`.
- Server installer: `--image-archive` also takes a release `images/` directory (loads every archive in it).
- **Role model: two roles, the same for our team and inside every bank** — `ADMIN` (does everything in its
  scope; a bank admin is also the bank's checker) and the new `AUDITOR` (read-only: platform auditors read every
  bank, bank auditors their own bank; never one-time secrets; 403 on every mutating route). `VIEWER`, `OPERATOR`
  and `APPROVER` are retired: they stay in the enum but the database refuses them (CHECK `User_role_scope`).
  Migrations `20261016140000_auditor_role` (enum value) and `20261016140100_role_scope` (mapping + CHECK +
  default `AUDITOR`). Existing users are mapped: platform `OPERATOR`/`APPROVER`/`VIEWER` → `AUDITOR`; bank
  `APPROVER` → `ADMIN` (bank admins are the checkers now); bank `OPERATOR`/`VIEWER` → `AUDITOR`. **Platform
  makers (former operators) become auditors — give them `ADMIN` again if they must keep raising requests.**
  `OIDC_ROLE_MAP` accepts only
  `ADMIN` / `AUDITOR`; `create-user.ts --role ADMIN|AUDITOR`.
- **TOTP removed: local sign-in is password-only by design.** No 6-digit code, no authenticator enrolment / QR
  code, no "Reset MFA" admin action (`reset-mfa`, notification `MFA_RESET`, audit `user.mfa_reset` /
  `auth.mfa_enrolled`), no `POST /api/auth/totp`. The short-lived `AUTH_MFA` switch is gone with it (env var,
  admin banner, `/api/health` `mfa`, `/api/ready` `checks.mfa`, /operations note, audit `auth.mfa_disabled`).
  Strong passwords (scrypt, ≥ 14 chars), lockout, temporary-password change, password max age, inactivity disable
  and session rules are unchanged; `auth.login` records `method: "password"`. Banks that need MFA use their SSO
  (`AUTH_MODE=oidc`), where the IdP enforces it. Migration `20261016170000_remove_totp` drops
  `User.totpSecretEnc` / `totpEnabled` / `totpLastStep` and `AuthChallenge.pendingSecretEnc` and deletes pending
  TOTP sign-in steps. The sign-in challenge cookie is now `__Host-pg_challenge` (was `__Host-pg_mfa`; a sign-in
  in progress during the upgrade restarts). `AUTH_ENC_KEY` stays (it seals notification webhook URLs); the
  rotation CLI now reports webhook rows only. Lab / colleague kit: `--code` / `pg-api.mjs totp` removed,
  `lab-users.json` holds password, role and bank only. Dependency `qrcode` removed.
- Simpler navigation: rings, maintenance windows, approval policy, notifications and account security are one
  **Advanced settings** group; reboot policy and emergency change are under **Advanced options** on the change
  request form / draft. No behaviour or default changed.

### Fixed
- **winget catalogue index never verified on Linux** (third-party discovery stayed empty). Causes: the
  index signer certificate carries Microsoft's critical *Application Policies* extension (OID
  1.3.6.1.4.1.311.21.10) that OpenSSL rejects ("unhandled critical extension"), and osslsigncode checked the
  timestamp against the Debian TLS bundle instead of `CODESIGN_CA_FILE`. The image now builds osslsigncode
  2.14 with `docker/osslsigncode/0001-accept-ms-application-policies.patch` (accepts exactly that extension),
  passes `-TSA-CAfile`, and the index is trusted only via the self-signed Microsoft roots of the bundle
  (needs *Microsoft Root Certificate Authority 2011* + *2010*, RUNBOOK §4.4) with signer `O=Microsoft
  Corporation`. New `CODESIGN_CRL_CHECK=off|online` (default `off`: `-ignore-crl`; CRLs are plain HTTP and the
  egress proxy is HTTPS-only).
- **Signature verification hardening (Linux):** `osslsigncode` results now require exit code 0, "Succeeded" and
  a line-anchored `Signature verification: ok`; previously "Timestamp Server Signature verification: ok"
  alone matched. A timestamp that is present but does not verify now fails the file.
- Server installer: the post-install smoke test waits up to 3 min (`SMOKE_WAIT_SIEM=180`) for the first SIEM
  audit export instead of failing `siemExport`; with the placeholder SIEM it reports WARN, not FAIL.

### Added (Windows Update lock, deliverable Windows patches)
- **Windows Update locked by PatchGate on bank PCs.** `Install-PatchGateAgent.ps1` now sets (at every run, also
  when the agent is already installed; `-SkipWuLock` to opt out) the Windows Update policies that stop the PC
  from taking updates from Microsoft itself: `UseWUServer=1` with `WUServer`/`WUStatusServer`
  `http://patchgate-wu-locked.invalid`, `DoNotConnectToWindowsUpdateInternetLocations=1`, `NoAutoUpdate=1`,
  `DisableDualScan=1`, `SetPolicyDrivenUpdateSourceFor*Updates=1` + `UseUpdateClassPolicySource=1`,
  `ExcludeWUDriversInQualityUpdate=1`, `SetDisableUXWUAccess=1`; Defender `FallbackOrder=InternalDefinitionUpdateServer`
  (`-AllowDefenderDefinitionUpdates` = `MMPC`); `wuauserv` stays Manual. This also blocks Tactical's own online
  "Run Update Scan" / "Install Approved Updates". The offline scan (scan package service) and `wusa`/DISM
  installs are unaffected by design (to be confirmed on the first lab PC). RUNBOOK §6.2 (values, GPO equivalent,
  Defender trade-off), TEAM-GUIDE step 3.
- **Lock detection + alert.** `Invoke-PatchGateWuScan.ps1` reports `wuLock {locked, issues, lastOutsideInstall}`
  (best-effort WU history) with every WU_SCAN result. **Protocol (additive, PROTOCOL_VERSION unchanged):** optional
  `wuLock` on each `WU_SCAN` result agent. Migration `20261016151000_endpoint_wu_lock` (`Endpoint.wuLocked`,
  `wuLockCheckedAt`, `wuLockDetail`). Endpoints page: "Windows Update" column (locked / NOT locked, problems on
  hover) + banner. Locked → NOT locked (or first report NOT locked): audit `endpoint.wu_lock_broken` on the bank
  chain and one new `WU_LOCK_BROKEN` notification (warning, bank + platform admins, webhooks) per scan result;
  `endpoint.wu_lock_restored` when locked again. **Re-register (and re-sign) the scan script in Tactical.**
- **PC install in one step:** double-click `installers/pc/Install-PatchGateAgent.cmd` (self-elevates, runs the
  script with the `patchgate-pc.json` next to it; the script also defaults to that file). New optional JSON fields
  `siteIp` and `hostNames`: hosts entries only for names DNS does not resolve (no `-SiteIp` needed). Self-test
  before installing: Tactical API + package cache reachable with a trusted certificate (exit 4 otherwise). Last
  line `OK - PC enrolled, will appear in PatchGate within minutes` / `FAILED - <reason>`.
- PC installer: the hosts-file update writes all missing names in one append and retries up to 10 times when
  another process holds the file (Defender, an editor); if it still fails it prints the exact lines to add and
  continues when the names already resolve (exit 1 only when they do not).
- **Windows patches PatchGate cannot deliver are not selectable** (banks with `windowsUpdateSource=PATCHGATE`):
  a patch listed only by Tactical's own online scan (no PatchGate offline-scan evidence, no `WinUpdate` row) shows
  "Needs PatchGate scan" on the Patches page; creating, submitting and starting a change request with it is
  refused (422/409) instead of failing at deployment after maker + checker approval. Same for updates whose
  Microsoft download is UNRESOLVABLE.
- Deployment wait notes are clearer: "files in quarantine until <time> UTC", "Microsoft files still downloading /
  being verified", "Microsoft Update Catalog lookup still running" (without the trailing "— waiting"); a queued
  deployment without a note says it is picked up by the next deployment run.
- Colleague test kit: the server install gets `--codesign-ca` with *Microsoft Root Certificate Authority 2011* +
  *2010* (public certificates in `kits/colleague-test/lib/`, SHA-256 pinned, fails closed) so the third-party
  catalogue verifies in the kit.

## [1.0.0-rc3] - 2026-10-16

Third release candidate: rc2 plus the platform approval rule and the fixes from the rc2 end-to-end validation.
For the first real-server / pilot install. Not yet validated on a real bank PC.

### Changed
- **Bank approval is always required**: every change request needs at least one approver from the bank
  itself; no bank or platform admin can turn this off (input schemas accept only `true`; database CHECK
  `Tenant_requireBankApproval_always`, migration `20261016130000`). The on/off toggles are removed from
  Settings → Approvals and Admin → Banks.

### Fixed (found by the rc2 end-to-end validation)
- Server installer, registry mode: signer / egress-proxy / backup now use the release's scanned images
  (`patchgate-<name>:<version>`, written to `SIGNER_IMAGE` / `EGRESS_PROXY_IMAGE` / `BACKUP_IMAGE`) instead of
  silently rebuilding `:local` images from `deploy/`; build mode encodes dots in the Next.js build id.
- `release.sh` also ships `install-site.sh` in `bundles/` (as `site-install-site.sh`; listed in the site SHA256SUMS).
- `smoke-test.sh` explains when `/api/ready` is unreadable from the current source (`INTERNAL=1`).
- RUNBOOK: restart web-1 and web-2 one at a time after bundle / key changes (no connector 502s).

## [1.0.0-rc2] - 2026-10-16

Second release candidate: first build cut by the release pipeline (`release/release.sh`), hosted multi-bank
topology, production hardening after the security and code reviews. Not yet validated on a real bank PC
(Windows Sandbox/VM unavailable on the build host) — see "Known limits".

### Added
- **Hosted, multi-bank platform** (docs/ARCHITECTURE-HOSTED.md): banks are tenants; PostgreSQL Row-Level
  Security per bank (`withTenant()` / `withPlatform()`), runtime DB role that is neither owner nor superuser,
  per-bank audit hash chains plus a platform chain, bank switcher for platform staff.
- **PatchGate Connector** (`patchgate-connector/`, single-file Node 24 bundle + container image): runs next to a
  bank site's offline Tactical RMM, outbound-only HTTPS, Ed25519-signed requests, two-phase enrolment with
  one-time codes and job-key fingerprint pinning (`init --job-key-fingerprint`), signed jobs with a 72 h
  maximum lifetime, bounded journal, local HTTPS package cache for the site's PCs, SIEM audit relay with
  hash chaining (`prevHash`), publisher / agent-hash trust policy, `check` health probe.
- **Connector API** `/api/connector/v1/*` (enrol, poll, results, heartbeat, packages) with per-connector rate
  limits, nonce replay protection and RLS-scoped persistence; connector revoke, edit limits and re-key in
  `/connectors`.
- **Job signer sidecar** (`deploy/signer`): sole holder of the per-bank job-signing keys; validates,
  rate-limits and audit-logs every signature (`JOB_SIGNER=remote|file|disabled`).
- **Windows updates through PatchGate** (no WSUS required): offline `wsusscn2.cab` scan on PCs (`WU_SCAN`),
  update files fetched from the Microsoft Update Catalog and bound authoritatively to the catalog, site cache,
  `WU_INSTALL`; WSUS remains selectable per bank (`Tenant.windowsUpdateSource`).
- **Local accounts**: scrypt passwords + mandatory TOTP MFA, lockout, session store in PostgreSQL, admin user
  management, self-service password change (`/account`), `AUTH_ENC_KEY` rotation CLI; optional OIDC.
- **Approval workflow**: maker-checker change requests with bank approvers, rings and maintenance windows,
  default rings on bank creation, target snapshot per change request, retries with failure classification,
  14-day deadline; emergency change requests (two approvers) and bank policy settings.
- **Notifications and reports**: outbox with SMTP / webhook delivery and back-off; compliance reports.
- **Operations**: `/operations` view, `/api/metrics` (token-protected), worker step history, structured JSON
  logs with secret redaction (`src/lib/log.ts`).
- **Production deployment** (`deploy/`): nginx edge (TLS, HSTS, rate limits, default-deny connector allow-list,
  internal-only `/api/ready`), two stateless web instances, internet-facing fetcher behind a squid egress
  allow-list (no private/loopback destinations), scheduler, PostgreSQL 16 with verified TLS (internal CA,
  `sslaccept=strict`), optional streaming replica, age-encrypted backups with restore drill, smoke test.
- **Installers**: `installers/server/install-patchgate.sh`, offline site bundle builder + `install-site.sh`
  (Tactical + connector, USB or online mode), `installers/pc/Install-PatchGateAgent.ps1`.
- **Release engineering**: single `VERSION` file, `release/release.sh` (quality gate, OCI-labelled images,
  CycloneDX SBOMs, vulnerability scan, optional cosign signing, checksums, generated release notes),
  `release/audit-tree.sh` secret/artifact audit, GitHub Actions CI and tag-driven release workflows,
  `/api/version` endpoint and version label in the sidebar footer.

### Changed
- Third-party packages are verified (hash + Authenticode via `osslsigncode` on Linux) and quarantined
  (`QUARANTINE_HOURS`) before they can be approved; package store quota `REPO_MAX_GB`; `/repo` is not public
  unless `REPO_PUBLIC=true` (legacy single-bank mode only).
- Legacy direct-Tactical variables (`TACTICAL_*`, `PATCH_REPO_URL`) are optional; banks are served through
  their connectors.
- Every worker tick step is isolated and reported individually (one failing step no longer returns 500).
- Database migrations run only as a one-shot `migrate` job (`patchgate-tools` image), never on web start.
- Base images moved to Debian 13 (trixie) with OS upgrades at build; `osslsigncode` 2.14 built from a pinned
  source release (Debian's 2.9: CVE-2025-70888); backup image rebuilt minimal (PGDG `postgresql-client-16` +
  `age` 1.3.2 built from source; no PostgreSQL server, `gosu` or `libxml2`). Release scan: 0 CRITICAL.
- Image names for the egress proxy and backup are configurable (`EGRESS_PROXY_IMAGE`, `BACKUP_IMAGE`,
  `BACKUP_BASE_IMAGE`).

### Security
- One-line site install requires a signed bundle: the server bakes `PATCHGATE_SITE_BUNDLE_PUBKEY`
  (`ed25519:<base64>`) into `/install/site.sh` and a downloaded bundle without a valid signature is refused
  (`--allow-unsigned`: lab only); USB installs take `--bundle-key`. `release.sh` signs the site bundle with
  `BUNDLE_SIGN_KEY`.
- PC installer restricts its staging directory (`C:\ProgramData\PatchGate`) to SYSTEM + Administrators before
  downloading and running the agent.
- Server and site installers pin Docker's apt signing-key fingerprint.

### Fixed
- A download aborted early (size limit) could leave its partial file behind and block the retry
  (`safeDownload` now waits for the file to close before deleting it).
- `deploy/scripts/generate-secrets.sh` had CRLF line endings (would not run on Linux).

### Security
- Fixes from the wave-3 security review (0 critical, 2 high): per-bank job-signing keys instead of one global
  key; Windows-update file binding from the Microsoft catalog instead of PC reports; immutable audit trigger;
  `tenant.select` audited on the bank chain; safe-regex for user-supplied patterns; bank admins cannot reset
  approvers.
- Containers run non-root with read-only root filesystems and least-privilege secret mounts and networks.

### Database migrations (all additive)
`20261015010000_tenancy_connectors_local_auth` … `20261015080000_backfill_default_rings`,
`20261016090000_notifications_reports`, `20261016100000_bank_policies_emergency`,
`20261016110000_worker_step_run`. Apply with `$DC run --rm migrate` before starting the new web image.

### Connector protocol
- `PROTOCOL_VERSION` 1 (unchanged within 1.0.0 pre-releases): `outcomeUnknown` results, `MAX_JOB_LIFETIME_MS`
  72 h, audit relay `prevHash`. Connectors built from 1.0.0-rc1 sources must be upgraded to this release.

### Known limits
- Real Windows PC end-to-end (agent from the site cache, approved install confirmed by inventory, offline
  Windows Update scan + install) still to be validated on a spare PC or the first bank pilot ring.
- Job-signing keys in HSM/KMS, keyed audit-chain segments for `AUDIT_HMAC_KEY` rotation: planned.
- Host firewall egress rules (RUNBOOK §4.3) must be verified on the real server (not testable on Docker Desktop).

## [1.0.0-rc1] - 2026-10-15

First release candidate (images `patchgate-web:rc1`, `patchgate-tools:rc1`, built by hand): hosted multi-bank
foundation, connector, local auth with TOTP, RLS, production compose stack; prod-stack smoke test and lab
end-to-end suite passing.
