# Changelog

All notable changes to PatchGate are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/) — see docs/RELEASE.md for what counts as breaking.
`release/release.sh` copies the section of the version being released into `release-notes.md`.

Components versioned together (single `VERSION` file): PatchGate server (web, tools/migrate), connector,
signer, egress proxy, backup, site bundle. The connector protocol has its own integer version
(`PROTOCOL_VERSION`, currently 1); a protocol change is always called out below.

## [Unreleased]

### Changed
- **User accounts are managed only by PatchGate platform admins.** Creating users, editing name / role / active,
  resetting password or MFA and unlocking now return 403 ("Accounts are managed by PatchGate platform
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
- **`AUTH_MFA=required|off`** (default `required`): `off` = local sign-in with the password only (stored TOTP
  secrets kept; temporary-password change, lockout and session rules unchanged). While off: banner for admins,
  `mfa:"off"` on `/api/health`, `checks.mfa=false` on `/api/ready`, warning on /operations, audit
  `auth.mfa_disabled` (platform chain) at every process start. Must be `required` for go-live.
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
