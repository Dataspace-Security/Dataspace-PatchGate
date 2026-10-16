# PatchGate — Hosted, multi-bank architecture (v2)

Decided 2026-10-15. Supersedes the "PatchGate inside the bank" deployment in ARCHITECTURE.md §4/§8;
the patch pipeline, verification and maker-checker rules there still apply.

## 1. Decisions

| Topic | Decision |
|---|---|
| Hosting | PatchGate runs on **our** server and domain. Banks are clients. |
| Banks per server | **Several** (multi-tenant). A bank sees only its own PCs, requests, approvals and audit. |
| Network | Inside each bank, only the **PatchGate Connector** (on the Tactical host) talks to the outside, and only to our domain/IP, **outbound HTTPS**. Nothing connects into a bank. Tactical server and PCs stay offline. |
| Approvals | Our team **and** bank staff. Our admin (or a bank admin) prepares, a **bank admin** of that bank must approve — always (not configurable). |
| Login | PatchGate's own accounts: password + **mandatory MFA (TOTP)**, lockout, audited. No external IdP needed. |
| Internet | Only PatchGate (our server) downloads from vendors. Unchanged. |

## 2. Picture (production scale)

```
                  Vendors: Microsoft Update catalog · winget/GitHub · vendor CDNs
                                     │ https, allow-listed hosts, every byte verified
                                     ▼
┌═════════════════════ PatchGate platform — OUR data centre / cloud, our domain ═════════════════════┐
║                                                                                                     ║
║  Bank staff + our staff (browser, MFA)        Connectors (signed requests, outbound from banks)     ║
║                │ https                                       │ https                                ║
║                ▼                                             ▼                                      ║
║        ┌──────────────── Load balancer / WAF  (TLS, rate limits, IP allow-list per bank) ───┐      ║
║        └────────┬───────────────────────┬─────────────────────────┬──────────────────────────┘      ║
║                 ▼                       ▼                         ▼                                 ║
║        PatchGate web/API #1     PatchGate web/API #2  …  #N   (stateless, scale out)                ║
║                 │                       │                         │                                 ║
║                 └───────────┬───────────┴──────────┬──────────────┘                                 ║
║                             ▼                      ▼                                                ║
║   PostgreSQL primary ⇄ replica (RLS per bank)    Package store (object storage / NFS, SHA-256 named)║
║                             ▲                      ▲                                                ║
║   Fetch worker(s): catalog + downloads + verification (only component with internet egress)         ║
║   Job worker(s):   change requests → signed jobs per connector, timeouts, retries                   ║
║   Platform audit chain + per-bank audit chains · job-signing key in HSM/KMS · backups · monitoring  ║
╚═════════════════════════════════════▲═════════════════════════════════▲═════════════════════════════╝
                                      │ https OUTBOUND only              │
          ┌───────────────────────────┴──────────────┐      ┌───────────┴──────────────────────┐
          │ BANK A                                   │      │ BANK B  (fully separate tenant)  │
          │                                          │      │  … same layout, own connectors,  │
          │  Site: Head office / DC                  │      │  own users, own audit chain,     │
          │   Tactical server A1                     │      │  own SIEM                         │
          │   Connector A1 (+ standby A1b, HA)       │      └──────────────────────────────────┘
          │     job runner → local Tactical API      │
          │     package cache → serves PCs (https)   │
          │     audit relay  → Bank A SIEM           │
          │       ▲                                  │
          │   PCs / servers: thousands of agents     │
          │                                          │
          │  Site: Region / DR                       │
          │   Tactical server A2 + Connector A2      │
          │       ▲                                  │
          │   more agents (branches via bank WAN)    │
          │                                          │
          │  Branches: PCs reach their site's       │
          │  Tactical + package cache over the WAN   │
          └──────────────────────────────────────────┘
          Nothing connects INTO a bank. Tactical servers and PCs never reach the internet.
```

## 2A. Scale model

| Level | Count (design target) | Notes |
|---|---|---|
| Banks (tenants) per platform | tens | each fully isolated (RLS + own audit chain + own connectors) |
| Sites / Tactical servers per bank | 1 – 20 | each site has its own connector; an endpoint belongs to exactly one connector |
| Connectors per site | 1 active + optional standby | standby takes over jobs via lease; jobs are idempotent |
| Agents (PCs/servers) per Tactical | up to ~5,000 (Tactical's practical limit) | split large banks into more sites |
| Agents per bank | up to ~50,000 | |

Consequences for the design:
- **Endpoint identity:** `(tenant, connector, tactical agent id)`. The same agent id in two banks never collides.
- **Jobs are batched and paged:** e.g. one `COLLECT` job per 200 agents. Results stream back in pages.
  No request carries a whole bank.
- **Deployments fan out per site:** a change request targets rings/sites; the job worker splits it into per-connector,
  per-maintenance-window batches with a concurrency cap (e.g. 50 PCs at a time per site) and stops a ring on a failure threshold.
- **Package distribution:** each site cache downloads a package **once** from us, and thousands of PCs pull it locally.
  WAN and internet bandwidth stay flat as the number of PCs grows.
- **Ingest:** inventory uploads are diffed (only changes stored) and processed asynchronously from a queue.
- **Dashboards:** aggregated per bank → site → ring, with paged tables. No page lists 50,000 rows.
- **Platform scaling:** web/API instances are stateless (sessions in Postgres). Workers use DB leases, so several can run.
  Postgres has a replica, and packages live in shared storage, not on one server's disk.

## 3. Connector protocol (v1)

- **Transport:** HTTPS to our domain; the connector pins our CA / certificate.
- **Connector identity:** at enrolment the connector generates an **Ed25519 key pair locally** (the private key
  never leaves the bank) and registers the public key using a **one-time enrolment code** created by our admin
  for that bank (expires in 24 h, single use). Every request carries `connector id + timestamp + nonce +
  body SHA-256`, signed. Replays and clock skew > 5 min are rejected. Works through any bank proxy.
- **Job authenticity:** every job is **signed by PatchGate's job-signing key**. The connector pins its public key
  at enrolment and refuses unsigned or modified jobs, even if TLS is intercepted by a bank proxy.
- **Typed jobs only.** The connector never executes arbitrary Tactical API calls. It accepts these job types:
  `SYNC_AGENTS`, `SCAN`, `COLLECT` (updates + software + agent version), `DEPLOY_WINDOWS` (exact GUID list),
  `DEPLOY_PACKAGE` (fixed install script + package metadata), `RESET_APPROVALS`.
  It validates each one locally: fixed script ID, GUID format, package present in the cache with a matching SHA-256.
- **Endpoints** (all under `/api/connector/v1`, rate limited per connector):
  `POST enroll` · `GET jobs` (long poll) · `POST jobs/{id}/result` · `POST inventory` ·
  `GET packages/{sha256}` · `GET audit?after=` (for SIEM relay) · `POST heartbeat`.
- **Package cache:** the connector downloads an approved package once, re-checks SHA-256, and stores it.
  It serves the cache to PCs over the bank's internal HTTPS. PCs verify SHA-256 + Authenticode signer again.
- **Health:** a missed heartbeat for more than 10 min raises an alert on our dashboard. Jobs wait and are never lost.

## 4. Multi-tenancy

- `Tenant` (a bank). **Tenant-owned:** endpoints, rings, windows, change requests, deployments, jobs, patch
  states, installed software, discovery, connector, audit chain, bank users.
- **Shared (ours):** the patch catalog, apps, verified packages, Tactical mirror, signer trust decisions.
  Each bank opts in to the apps it wants managed.
- **Isolation, two layers:**
  1. Every query goes through a tenant-scoped data layer.
  2. **PostgreSQL Row-Level Security** on every tenant table (`tenant_id = current_setting('app.tenant_id')`).
     A missed filter cannot leak another bank's data.
- **Audit:** one tamper-evident chain **per bank**, exported to that bank's SIEM via its connector, plus our own
  chain for platform actions (trust decisions, user admin).

## 5. Users and roles

Two fixed roles, the same for our team and inside every bank (`src/lib/auth/roles.ts`; DB CHECK `User_role_scope`):

| Role | Scope | Can |
|---|---|---|
| Platform admin | all banks | onboard banks, enrol connectors, manage all users, trust decisions, rings/windows/settings for any bank, create change requests (maker), second approver of two-approver requests |
| Platform auditor | all banks | read-only: every list a platform admin sees (banks, users, endpoints, patches, requests, connectors, audit chains, reports, operations); never one-time secrets |
| Bank admin | own bank | manage bank users and settings, create change requests, **approve / reject** them (checker) |
| Bank auditor | own bank | read-only, reports |

Maker ≠ checker is always enforced. Every change request needs at least one approving admin from the bank itself — a platform rule that no admin can turn off (DB CHECK `Tenant_requireBankApproval_always`). Emergency / large requests need two distinct admins (at least one from the bank).
Login: scrypt-hashed password (≥ 14 chars) + TOTP (`AUTH_MFA=required`, the default; `off` = password only, pre-go-live only), lockout after 5 failures, 15-min idle and 8-h absolute sessions.
Every login is audited.

## 6. Delivery phases

| # | Phase | Result |
|---|---|---|
| 1 | Tenancy + own login | Tenant model + RLS, tenant-scoped data layer, users/roles above, password + TOTP login, bank switcher for our staff |
| 2 | Connector protocol on PatchGate | enrolment, signed requests, signed job queue, inventory/result ingestion; worker produces jobs instead of calling Tactical |
| 3 | Connector service | standalone `patchgate-connector` (Node, single binary/container): job runner over the local Tactical API, package cache + internal HTTPS, SIEM relay, heartbeat |
| 4 | Lab | PatchGate on the host = "our server"; Tactical + connector on an isolated bank network whose only egress is the host; Sandbox PC end-to-end |
| 5 | Production | Docker images, deployment + onboarding runbook, backups, monitoring, security review, full test pass |

## 7. Risks

- **Bank proxy TLS inspection:** solved by signed jobs/requests (integrity end-to-end, not only TLS).
- **Our server compromise:** an attacker could queue jobs, but the connector still runs only typed jobs. Packages
  are re-verified (hash + signer pin) on the PC, and bank-side maker-checker approvals are recorded in the
  bank's own audit chain at its SIEM. The job-signing key belongs in an HSM/KMS in production.
- **Connector offline:** jobs queue. The dashboard shows "connector last seen" per bank.
