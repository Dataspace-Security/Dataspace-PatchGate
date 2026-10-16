# PatchGate — Security overview (hosted platform)

For bank information-security reviews. Architecture: ARCHITECTURE-HOSTED.md (hosted, multi-bank) and
ARCHITECTURE.md (patch pipeline, maker-checker). Operations: RUNBOOK.md. Status as of 2026-10-15; items
marked *planned* or *TO VERIFY* are not yet in place.

---

## 1. Threat model (summary)

**Assets**: integrity of what is installed on bank endpoints (the highest-impact asset); bank data
(endpoint inventory, patch state, change requests, users); audit chains (regulatory evidence); keys
(job-signing, audit HMAC, webhook-URL encryption); availability of patching inside maintenance windows.

**Trust boundaries**
1. Internet / bank networks → our edge (nginx): browsers (bank + our staff) and connectors (outbound from banks).
2. Edge → stateless web instances → PostgreSQL (internal Docker networks, no internet route).
3. Fetcher → vendors (the only internet egress, via an allow-listing proxy).
4. Our platform → bank connector (signed jobs; the connector is the bank's enforcement point).
5. Connector → bank Tactical RMM → endpoints (inside the bank; nothing connects into a bank).

| # | Threat (STRIDE) | Main mitigations | Residual |
|---|---|---|---|
| T1 | Malicious/tampered package delivered to PCs (T) | Vendor allow-list + SSRF guards; SHA-256 from catalogue; Authenticode chain + exact publisher pin (osslsigncode on Linux); quarantine (48 h default); maker-checker approval; connector + PC re-verify hash + signer | Vendor supply-chain compromise with a validly signed binary (mitigated by quarantine, rings, soak time) |
| T2 | Platform compromise queues malicious jobs (T/E) | Typed jobs only (no arbitrary scripts), connector validates each job, packages re-verified on the PC, bank approval recorded in the bank's own chain at its SIEM. Private keys only in the **signer** container (per-bank keys, envelope validation, rate limits, JSON audit of every signature); web holds a token, the internet-facing fetcher holds nothing (§5) | A compromised web tier can use the signer as an oracle while it is compromised (bounded by rate limits, visible in the signer audit); keys are files until HSM/KMS (R2) |
| T3 | Cross-bank data access (I) | Tenant-scoped data layer + PostgreSQL RLS (`FORCE`, NOBYPASSRLS role) + runtime DB role that is neither owner nor superuser | Code paths not yet using `withTenant/withPlatform` (R4) |
| T4 | Bank proxy TLS interception / MITM (T/I) | Connector requests signed (Ed25519, nonce, timestamp ±5 min, body hash); jobs signed by us; connector pins our CA/cert and job key | — |
| T5 | Credential stuffing / account takeover (S) | Local accounts (password-only by design): scrypt, ≥ 14 chars + deny-list, lockout 5 failures/15 min, password max age, inactivity disable, 15-min idle + 8-h absolute sessions, edge + app rate limits, every login audited; banks needing MFA use their SSO (IdP-enforced MFA) | Phished / reused passwords on local accounts — mitigated by lockout, rate limits, SIEM alerting; SSO (IdP MFA) for banks that need MFA |
| T6 | Audit tampering by a DB administrator (R) | Hash chain keyed with `AUDIT_HMAC_KEY` held outside the DB; continuous export + ANCHORs to SIEM; readiness flags a broken chain | Gap between last SIEM export and tampering (≤ 15 min alert) |
| T7 | SSRF / pivot from the fetcher (E/I) | https-only, exact host allow-list, public-DNS-only checks, egress proxy allow-list **and private/loopback/link-local/CGNAT/ULA destination deny at the proxy** (checked on the IPs squid connects to), firewall drops all other egress, fetcher isolated from the edge, the web tier and the signer (own `fetch-ctl` network), no signing material, cannot log in as the DB superuser | Compromised fetcher holds `AUDIT_HMAC_KEY` + the app DB role (can forge audit entries / write unsigned job rows — connectors reject unsigned jobs) |
| T8 | DoS on the edge / connector API (D) | nginx rate/conn limits, body-size limits, timeouts, per-class app limits, long-poll capped at 25 s, 2+ instances | Volumetric DDoS → upstream provider |
| T9 | Secret leakage via logs / images / repo (I) | Secrets as files (0600), never in images or env files; `.dockerignore`; logger redacts secret-looking keys and URL queries; scheduler token never on a command line | Operator mistakes — reviewed in change control |
| T10 | XSS / clickjacking in the admin UI (T/I) | React escaping, strict CSP (`default-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`), XFO DENY, nosniff, same-origin CSRF check on state-changing requests | `script-src 'unsafe-inline'` (R1) |
| T11 | Bank Tactical admin (or anyone with the site Tactical) approves / installs / runs scripts outside PatchGate (E/R) | **Tactical is sealed** (RUNBOOK §13): dashboard login blocked for every Tactical user except the service account (`tacticaladmin` = break-glass, `install-site.sh --break-glass on/off`, alerted), other API keys expired, service role least-privilege, every patch policy manual, auto-approve/install tasks off, agent auto-update off (agent version changes only via PatchGate). **Detected in real time**: the connector's Tactical guard reads Tactical's audit log every ~30 s and pushes every non-service action (signed `POST /tactical-events`); foreign update approvals (not audited by Tactical) are **reset automatically within ~30 seconds** on the site and reported — the guard trusts only approvals from signed jobs (DEPLOY_WINDOWS, TACTICAL_GUARD_SYNC baseline after a start; nothing is reset before it has them) and never touches an in-flight PatchGate deployment's approvals; TACTICAL_AUDIT_SYNC + the COLLECT comparison stay as backstop; each one → bank audit chain + SIEM, critical notification to platform + bank admins (bursts coalesced), Connectors page badge until an admin acknowledges | Root / Docker on the site VM can bypass everything (DB edits, log deletion) — only detectable indirectly (audit-log gap, connector offline, approval drift); an approval made and installed ("Install Approved Updates") within the same ~30 s guard round can still run once (it is then reported); with the connector stopped the guard does not run (CONNECTOR_OFFLINE after 10 min) |

---

## 2. Controls mapped to bank expectations

References: RBI Master Direction on IT Governance, Risk, Controls and Assurance Practices (2023) and
RBI Cyber Security Framework for banks (2016); ISO/IEC 27001:2022 Annex A; PCI DSS v4.0 (for banks whose
endpoints are in cardholder-data scope). Mapping is indicative for the bank's own assessment.

| Area | PatchGate control | RBI (IT governance / CSF) | ISO 27001:2022 | PCI DSS v4.0 |
|---|---|---|---|---|
| Patch & vulnerability management | Catalogue, applicability scan, rings, maintenance windows, compliance reporting | Patch/vulnerability management, CSF Annex 1 §7 | A.8.8, A.8.19 | 6.3.3, 11.3 |
| Change management | Maker-checker (maker ≠ checker enforced), at least one approving bank admin on every change request while "Approval required" is ON (default; switching it is ADMIN-only, audited and notified — R13), ticket reference, rings + soak, stop on failure threshold | Change management | A.8.32 | 6.5.1–6.5.2 |
| Software integrity | SHA-256 + Authenticode publisher pin at ingest, connector and PC; quarantine | Application/software integrity | A.8.7, A.8.28 | 6.3.2, 11.5 |
| Identity & MFA | Own accounts, password-only by design: scrypt, ≥ 14-char passwords, lockout, password max age, inactivity disable, session limits; bank OIDC SSO where the IdP enforces MFA (for banks that need MFA) | Access control, MFA for privileged access | A.5.15–5.18, A.8.5 | 8.3, 8.4, 8.2.8 |
| Least privilege | Two fixed roles in every scope: Admin and Auditor (read-only; never one-time secrets; 403 on every mutating route, tested route by route); user accounts are created and managed only by platform admins (bank admins / auditors: read-only user list; every account operation 403, tested route by route); DB CHECK `User_role_scope` refuses any other role; DB roles: owner (migrate only) / app (DML) / tenant (RLS) | User access management | A.8.2, A.8.3 | 7.2 |
| Tenant isolation | Tenant-scoped data layer + PostgreSQL RLS (FORCE) | Outsourcing: data segregation | A.8.3, A.5.23 | 7.2.1 (multi-tenant service provider) |
| Logging & monitoring | Tamper-evident audit chain per bank + platform, SIEM export (TLS syslog) + bank SIEM relay, JSON operational logs, alert list (RUNBOOK §8) | Audit logs, SOC integration | A.8.15, A.8.16 | 10.2–10.7 |
| Cryptography | TLS 1.2/1.3 (Mozilla intermediate), HSTS; Ed25519 job (per-bank keys in an isolated signer) + connector signatures; AES-256-GCM for notification webhook URLs; HMAC-SHA-256 audit chain; TLS to PostgreSQL; age (X25519) encrypted backups | Cryptographic controls | A.8.24 | 3.6, 4.2 |
| Network security | Outbound-only from banks; default-deny per-bank connector IP allow-list; internal-only DB/app/signer networks; egress allow-list proxy with private-destination deny; `/api/worker`, `/repo`, `/api/wsus` not exposed; DB TLS | Network segmentation, perimeter | A.8.20–8.22 | 1.2–1.4 |
| Secure configuration | Non-root containers, read-only root FS, all capabilities dropped (DB/edge: minimal set), no-new-privileges, resource limits, no secrets in images, fail-closed config validation | Secure configuration / hardening | A.8.9 | 2.2 |
| Backup & recovery | Nightly encrypted dumps (server holds only the public key), weekly package-store snapshot, tested restore drill, optional streaming replica | BCP/DR, backup testing | A.8.13, A.5.30 | 12.10.1 (IR plan), 9.4 (media) |
| Incident response | Playbooks: compromise, connector revoke, key rotation, chain failure (RUNBOOK §9) | Incident reporting (CERT-In 6 h; RBI) | A.5.24–5.28 | 12.10 |
| Third-party / supply chain | Vendor allow-list, publisher pins, quarantine, dependency audit (§4) | Outsourcing & vendor risk | A.5.19–5.22 | 6.3.2, 12.8 |
| Secure development | TypeScript, zod validation at boundaries, unit + integration + E2E tests, dependency audit, code review | SDLC | A.8.25–8.29 | 6.2 |

---

## 3. Residual risks (accepted or planned)

| ID | Risk | Why / compensating controls | Plan |
|---|---|---|---|
| R1 | **CSP allows `script-src 'unsafe-inline'`** | Next.js App Router streams inline RSC payload scripts and the app uses `cacheComponents` (prerendered shells), which Next.js documents as incompatible with nonce-based CSP. Compensating: no `unsafe-eval` in production, `default-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `connect-src 'self'`, React output escaping, no user-supplied HTML rendering | Re-evaluate when Next.js supports hashes/nonces with cache components |
| R2 | Job-signing keys are PEM files (in the signer container), not in an HSM/KMS | Per-bank keys; only the signer (uid 10002, internal network, no DB/internet) can read them; 0600, read-only FS, escrow; connectors only run typed jobs and re-verify packages | HSM (PKCS#11 EdDSA) / KMS Ed25519 behind the same signer API (RUNBOOK §9.7) |
| R3 | `AUDIT_HMAC_KEY` rotation and `AUTH_ENC_KEY` re-encryption not automated (procedure only, RUNBOOK §9.3/9.4) | Keys outside the DB host, escrowed, mounted only where used (`AUTH_ENC_KEY`: web + migrate; `AUDIT_HMAC_KEY`: web, fetcher, migrate); SIEM holds the authoritative copy | App support for keyed chain segments + re-encryption CLI |
| R4 | Some writes still occur outside `withTenant/withPlatform` | Found in deployment validation: under the production (non-superuser) DB role, an `auditEvent.create()` in the Tactical mirror failed with an RLS violation. Fails **closed**, not open | Route all writes through the tenancy layer; run integration tests as a non-superuser role |
| R5 | Single-host default stack | 2 web instances, health checks, nightly backups, optional replica | Tier M/L: replica + PITR + second host (RUNBOOK §1.2, §7.5) |
| R6 | Egress enforcement depends on host firewall rules | Docker networks + proxy allow-list + app allow-list; smoke test detects missing rules | Automate rules with the host configuration management |
| R7 | Connector allow-list is shared across banks (default deny; one file per bank) | Connector keys are per bank/site and each connector belongs to exactly one tenant (`Connector.tenantId`) | Per-bank connector hostnames if a bank requires source-IP binding |
| R8 | Local sign-in is password-only (no second factor) | Strong password policy, lockout, rate limits, password max age, inactivity disable, session limits, audit + SIEM alerting | Banks that need MFA use SSO (`AUTH_MODE=oidc`, MFA enforced by the IdP) |
| R9 | Dev-only dependency advisory (§4) | Not shipped in the runtime image | Track upstream fix |
| R10 | ~~PostgreSQL TLS is encrypt-only~~ — closed 2026-10-16: every DB client verifies the server certificate (chain to the internal DB CA + hostname `db`/`db-replica`). Remaining: the DB CA private key (`secrets/pg_ca_key`) lives on the host disk with the other secrets | Never mounted into a container; 0600, root/uid 10001; escrowed with `secrets/`; TLS mandatory (`hostssl`); superuser restricted to the backup network | Move DB CA issuance offline/HSM together with the job-signing keys (RUNBOOK §9.7) |
| R11 | The signer is a signing oracle for whoever holds the web tier | Envelope validation (typed job, ≤ 72 h lifetime, not expired, ≤ 90 days ahead, exact fields), per-bank and global rate limits, JSON audit line per signature (reconcilable with `ConnectorJob`), connectors validate payloads + re-verify packages | Per-bank approvals bound into the signing request (e.g. the signer checks a bank-approval reference for DEPLOY_* jobs) |
| R13 | A bank / platform admin can switch **Approval required** OFF for a bank: then a single person can raise AND deploy a change request (no checker) | Only ADMINs can switch it (auditors never); every switch is audited on the bank's chain (`bank_policy.approval_switched`) and notified to all bank + platform admins (critical, cannot be muted); every auto-approval is audited (`change_request.approval_skipped`) and visible on the request; amber "Approval is OFF" note on the dashboard and change-request pages; maintenance windows, rings, failure stop and eligibility checks still apply | Keep ON in production (GO-LIVE-CHECKLIST C1a); SIEM rule on `bank_policy.approval_switched` |
| R12 | Root / Docker access on a bank site VM can bypass the Tactical seal (edit Tactical's DB, delete its audit log, run code in its containers) | Seal + detection (RUNBOOK §13): audit-log gap and connector-offline alerts, approval-drift reset, bank SIEM receives every reported action; the site VM's root/Docker access is the bank's responsibility (named admins, syslog to SIEM) | Bank: restrict and monitor root on the site VM; PatchGate: optional host-integrity attestation of the site VM |

---

## 4. Dependency review (2026-10-15)

Command output from `patchgate-web` (no `npm audit fix` was run; `package.json` unchanged):

| Command | Result |
|---|---|
| `npm audit --omit=dev` (runtime dependencies) | **0 vulnerabilities** |
| `npm audit` (incl. dev dependencies) | **5 high** — one advisory, one chain |

Finding: **GHSA-vfj7-8cjw-p6xm** — `braces` ≤ 3.0.3, stack-exhaustion DoS via deeply nested brace
patterns (CVSS 7.5, CWE-674). Chain: `eslint-config-next@16.4.0 → @next/eslint-plugin-next@16.4.0 →
fast-glob@3.3.1 → micromatch@4.0.8 → braces@3.0.3`. The 5 "high" entries are this one advisory counted on
each package in the chain.

Assessment: **dev/lint-time only**. It is not in the production runtime image (Next.js `output:
"standalone"` ships only traced runtime files) and is never reached by untrusted input (patterns come
from our ESLint config). It is present in the one-shot `patchgate-tools` image (full `node_modules`), which
only runs `prisma migrate deploy` / admin CLIs with no network exposure.

Recommendation:
- Do **not** run `npm audit fix --force` — it would downgrade `eslint-config-next` to 14.2.x (breaking,
  mismatched with Next 16).
- No patched `braces` release exists (latest 3.0.3). Track the advisory; when a fix ships, pin it with
  `"overrides": { "braces": "<fixed>" }` and re-run `npm audit`.
- Optional hardening: build the tools image with `npm ci --omit=dev` plus only `prisma` and `tsx`
  (would also drop the advisory there).
- Add to CI: `npm audit --omit=dev --audit-level=high` as a **blocking** gate; full `npm audit` as
  informational; container image scan (Trivy/Grype) of `patchgate-web`, `patchgate-tools`, backup and
  egress-proxy images (OS packages: Debian bookworm, Alpine 3.22) — not run in this review.
- Base images are pinned by tag (`node:24-bookworm-slim`, `postgres:16-bookworm`, `nginx:1.28-alpine`,
  `alpine:3.22`, `curlimages/curl:8.11.1`); pin by digest in the release pipeline and rebuild monthly
  for OS security updates.

---

## 5. Deployment hardening summary (what the default stack enforces)

- Edge: TLS 1.2/1.3 only, HSTS (1 year), `server_tokens off`, no `X-Powered-By`, request-size limits per
  route, header/body timeouts, long-poll and download timeouts, per-IP rate and connection limits,
  `/api/worker/*` and dev-login routes return 404, unknown `Host` → connection dropped, X-Forwarded-For
  overwritten (not appended) to match `TRUST_PROXY_HOPS=1`.
- Containers: non-root (uid 10001), read-only root FS with tmpfs, `cap_drop: ALL`, `no-new-privileges`,
  CPU/memory limits, tini as PID 1, JSON logs with rotation.
- Data: DB and app networks `internal: true`; runtime DB role is not owner/superuser (RLS applies);
  `data-checksums` on; SCRAM-SHA-256; superuser only via local peer auth or the backup container.
- Secrets: generated with OpenSSL CSPRNG, files 0600, mounted read-only, fingerprints in backup manifests.
  **Least privilege per container** (`docker-compose.prod.yml` header): no container gets a secret it does
  not use; the job-signing private keys are readable only by the signer (uid 10002).
- Edge routes: `/api/connector/*` default-deny source-IP allow-list (one file per bank; "open" only for
  pilots); `/api/wsus/*` (legacy) and `/repo/*` return 404 unless the source IP is explicitly allow-listed;
  `/api/ready` only for the internal health network / load balancer (404 elsewhere), `/api/health` public.
- Egress proxy: vendor host allow-list **plus** a destination deny for RFC 1918, loopback, link-local
  (incl. metadata), CGNAT, reserved/multicast and IPv6 loopback/ULA/link-local addresses.
- Database: TLS required for every network connection (`hostssl`), and every client **verifies** the server:
  `generate-secrets.sh` issues the server certificate (SAN `db`, `db-replica`) from an internal DB CA whose
  key is never mounted into a container. Prisma (web, fetcher, migrate) uses `sslaccept=strict` +
  `sslcert=<DB CA>` (Prisma 6 ignores `sslmode=verify-full`, so it is not used); libpq clients (backup,
  replica) use `sslmode=verify-full` + `sslrootcert`. Tested: wrong CA and wrong hostname are refused
  (`deploy/scripts/test-db-tls.sh`). pg_hba generated on every start: superuser only from the `db-admin`
  network (backup), app/owner roles only to the PatchGate database, everything else rejected.

### 5.1 Job signing and key custody

| Container | Job-signing key | Signer token | `AUTH_ENC_KEY` | `AUDIT_HMAC_KEY` | Internet | SIEM net | Notes |
|---|---|---|---|---|---|---|---|
| signer | **yes** (per bank) | yes | — | — | no (internal net only) | no | validates, rate-limits, audit-logs every signature |
| web-1/2 | no | yes | yes | yes | no (`siem-out` firewalled to SIEM/IdP) | yes | `JOB_SIGNER=remote` |
| fetcher | no | no | random placeholder | yes (appends audit events) | via proxy allow-list only | no | `JOB_SIGNER=disabled`; cannot reach signer or web |
| migrate | no | no | yes (admin CLI) | yes (admin CLI) | no | no | one-shot, `JOB_SIGNER=disabled` |

- **Per-bank keys**: `job-signing-keys/<Tenant.id>.pem` (fallback `default.pem`, can be forbidden with
  `SIGNER_REQUIRE_TENANT_KEY=true`). Each bank's connectors pin only their bank's public key (fingerprint at
  connector init), so a leaked bank key cannot produce jobs other banks accept.
- **Signer rules** (`deploy/signer/server.mjs`, a dependency-free copy of `protocol.ts` rules that must stay
  in sync — a unit test in `keys.test.ts` compares job types, lifetime and canonical JSON): exact envelope
  fields, known job type, id/tenant/connector formats, ISO timestamps, lifetime ≤ 72 h, not expired,
  `notBefore` ≤ 90 days ahead. The web side verifies each returned signature against the bank's public key
  before storing the job.

| Item | Status |
|---|---|
| Signer service, per-bank keys, rate limits, JSON audit, `JOB_SIGNER=file/remote/disabled` | **Implemented** (unit-tested) |
| Per-bank key creation/rotation (`generate-secrets.sh --job-key/--rotate-job-key`, `kill -HUP signer`) | **Implemented** |
| Connector re-pin after rotation (`--job-key-fingerprint`) | Procedure (RUNBOOK §9.1); connector side owned by the connector workstream |
| HSM (PKCS#11 EdDSA) / cloud KMS Ed25519 behind the signer | **Planned** — integration path RUNBOOK §9.7 |
| `AUDIT_HMAC_KEY` rotation (keyed chain segments) | **Procedure only** (RUNBOOK §9.3) |
| `AUTH_ENC_KEY` rotation with re-encryption | Re-encryption CLI for webhook URLs (RUNBOOK §9.4) |
- Backups: encrypted before touching disk; private key offline; restore tested (RUNBOOK §7.3).
