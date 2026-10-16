# PatchGate — Operations Runbook (hosted platform)

Audience: Dataspace platform operators. Scope: the PatchGate platform we host for client banks
(ARCHITECTURE-HOSTED.md). Deployment files: `deploy/` (Docker Compose), image: `patchgate-web/Dockerfile`.
Security posture and control mapping: `docs/SECURITY.md`.

Items marked **TO VERIFY** depend on work that was still in progress when this runbook was written.

---

## 1. Server requirements and sizing

### 1.1 Base platform

| Item | Requirement |
|---|---|
| OS | Linux x86-64 (Ubuntu 24.04 LTS / RHEL 9), CIS level 1 hardened, automatic security updates |
| Runtime | Docker Engine ≥ 26 + Compose v2 (≥ 2.24 for `env_file.required`) |
| Network | Public IP / DNS name for `PATCHGATE_HOSTNAME`; inbound 443 (and 80 for redirect/ACME) only; SSH from the management VPN only |
| Egress | Firewall allow-list: vendor hosts (via the egress proxy), our SIEM, NTP, DNS, container registry. Nothing else |
| Time | NTP synchronised (connector signatures reject clock skew > 5 min; TOTP needs ±30 s) |
| Storage | Separate volumes for Docker data (PostgreSQL), package store (`repo` volume) and backups (off-host) |

### 1.2 Sizing by number of banks (N) and agents (M)

Estimates; validate with a load test before each tier change. Inventory is the dominant DB cost
(~150 installed-software rows + ~300 patch-state rows per agent, diffed on ingest).

| Tier | Banks (N) | Agents (M) | Host(s) | DB | Package store | Web instances |
|---|---|---|---|---|---|---|
| S | ≤ 5 | ≤ 10,000 | 1 × 8 vCPU / 16 GB | on host, 100 GB SSD | 500 GB | 2 (default) |
| M | ≤ 20 | ≤ 100,000 | 1 × 16 vCPU / 32 GB | on host, 300 GB NVMe, `PG_SHARED_BUFFERS=4GB`, `PG_EFFECTIVE_CACHE_SIZE=12GB`, replica profile on | 1–2 TB | 3 |
| L | tens | ≤ 500,000 | 2 app hosts (8 vCPU / 16 GB) + dedicated DB host (16 vCPU / 64 GB) + replica | 1 TB NVMe, PITR (§7.5) | NFS / object-backed, 2–4 TB | 4+ across hosts |

Rules of thumb:
- Connections: each PatchGate container uses `connection_limit=10` → keep `PG_MAX_CONNECTIONS` ≥ 3 × instances × 10 + 20.
- Connectors hold one long-poll (≤ 25 s) each — hundreds of connectors are trivial for nginx/Node.
- Package store ≈ Σ apps × versions kept × average installer size (e.g. 50 apps × 3 × 150 MB ≈ 22 GB) + Tactical releases; plan for 5× headroom and alert at 80 %.
- Multi-host (tier L): the `repo` volume must be shared storage (NFS 4.1 / CIFS / object gateway) mounted on every host; the compose file shows the NFS `driver_opts`.

---

## 2. Deployment architecture

```
 Internet ──443──► nginx (TLS 1.2/1.3, HSTS, rate limits; default-deny connector allow-list;
                     │         404 for /api/worker, /api/dev-login, /repo, /api/wsus; /api/ready internal only)
                     │  network "app" (internal)
                     ├──► web-1 ─┐   stateless Next.js standalone (node server.js), non-root, read-only rootfs
                     └──► web-2 ─┤   sessions in PostgreSQL → no sticky sessions
 web-1/2 ──network "signer" (internal)──► signer   ONLY holder of the job-signing private keys (per bank)
 scheduler ──"app"──► web-1|web-2 /api/worker/tick        (x-worker-token, DB lease)
           ──"fetch-ctl" (internal)──► fetcher /api/worker/fetch   (x-worker-token, DB lease, ≤ 2 h)
 fetcher ──network "fetch-egress"──► egress-proxy (squid: CONNECT :443 to allowed-hosts.txt, never to
                                     private/loopback/link-local/CGNAT/ULA addresses) ──► vendors
 web-1/2 ──network "siem-out"──► platform SIEM (tls://…:6514) — host firewall allows nothing else
 web-*/fetcher/migrate ──network "data" (internal, TLS)──► db (PostgreSQL 16) ──► db-replica (profile)
 backup ──network "db-admin" (internal, TLS)──► db   (the only source the postgres superuser may log in from)
 backup ──► nightly pg_dump | age  →  ${BACKUP_DIR}   (+ weekly package-store snapshot)
 shared volume "repo" (REPO_DIR=/data/repo) mounted by web-1, web-2, fetcher (rw) and backup (ro)
```

| Container | Image | Purpose | Notes |
|---|---|---|---|
| nginx | nginx:1.28-alpine | edge | config `deploy/nginx/`, cert `deploy/tls/` |
| web-1, web-2 | patchgate-web | UI + API + connector API | `HEALTHCHECK /api/health` |
| fetcher | patchgate-web | only internet-facing worker | `HTTPS_PROXY` + `NODE_USE_ENV_PROXY=1`; `JOB_SIGNER=disabled`; no signing token, no `AUTH_ENC_KEY` |
| signer | built from `deploy/signer` | job signing (per-bank Ed25519 keys) | uid 10002, network `signer` only; validates, rate-limits and audit-logs every signature |
| egress-proxy | built from `deploy/egress-proxy` | vendor allow-list | logs every CONNECT (JSON) |
| scheduler | curlimages/curl | tick/fetch loop | token read from file, never on a command line |
| db / db-replica | postgres:16-bookworm | data | roles §4.2, replica = profile `replica` |
| backup | built from `deploy/backup` | encrypted dumps | `patchgate-backup now|repo|prune|decrypt` |
| migrate | patchgate-tools | **one-shot** `prisma migrate deploy` + admin CLI | profile `ops`; never part of web start |

Database roles (created by `deploy/postgres/initdb/10-patchgate-roles.sh` on first start):
`postgres` (superuser: DB container, backup, restore only) · `patchgate_owner` (owns schema, used only by
`migrate`) · `patchgate_app` (runtime login: DML only, not owner, not superuser) · `patchgate_tenant`
(NOLOGIN, NOBYPASSRLS; the app `SET LOCAL ROLE`s to it inside `withTenant()/withPlatform()`) · `replicator`.

---

## 3. First-time installation

```bash
# 0. Host: Docker installed, firewall (§4.3) prepared, DNS for PATCHGATE_HOSTNAME → this host
git clone <repo> /opt/patchgate && cd /opt/patchgate

# 1. Pull the signed release images (preferred: built by release/release.sh — test gate, SBOM,
#    grype scan that FAILS on any CRITICAL finding, cosign signatures; see docs/RELEASE.md), e.g.
#      cosign verify --key release.pub registry.example.com/patchgate-web:$VER
#    Building by hand is for development only. PATCHGATE_BUILD_ID must not contain dots (Next.js build id):
#    release.sh encodes 1.0.0-rc2 as 1_0_0-rc2. Run `npx next typegen` before a standalone `tsc` typecheck.
VER=1.0.0
BUILD_ID=$(echo "$VER" | tr . _)
docker build -t registry.example.com/patchgate-web:$VER   --build-arg PATCHGATE_BUILD_ID=$BUILD_ID patchgate-web
docker build -t registry.example.com/patchgate-tools:$VER --build-arg PATCHGATE_BUILD_ID=$BUILD_ID --target tools patchgate-web

# 2. Secrets (§4.2) and configuration (§4.1)
cd deploy
sudo ./scripts/generate-secrets.sh
cp .env.production.example .env.production && chmod 600 .env.production && $EDITOR .env.production
#    certificate: tls/fullchain.pem + tls/privkey.pem (0600 root)
#    CA files:    ca/siem-ca.pem, ca/internal-ca.pem, ca/codesign-ca.pem (§4.4)
#    backups:     age key pair generated OFFLINE; only the public key goes into BACKUP_AGE_RECIPIENTS
sudo mkdir -p backups   # or mount off-host storage at BACKUP_DIR

# 3. Database + schema (one-shot migrate job; never on web start)
DC="docker compose -f docker-compose.prod.yml --env-file .env.production"
$DC build backup egress-proxy signer     # signer tests: docker build --target test deploy/signer
$DC up -d db
$DC run --rm migrate                      # prisma migrate deploy as patchgate_owner

# 4. Start everything and verify
$DC up -d
$DC ps                                    # all healthy
CA_FILE=… INTERNAL=1 ./scripts/smoke-test.sh https://$PATCHGATE_HOSTNAME
```

`smoke-test.sh` checks TLS (chain, expiry, protocol versions, http→https), `/api/health`, `/api/ready`
(all checks), security headers, that `/api/worker/*` and `/api/dev-login` are not reachable from outside,
that the login page loads, and with `INTERNAL=1`: worker endpoints return 401 without a token, web
instances have no direct internet, the fetcher reaches allow-listed vendors only via the proxy, and
`osslsigncode` is present. Exit code = number of failed checks.

Shell scripts must keep LF line endings and the exec bit on the server (`chmod +x deploy/scripts/*.sh`
after copying from Windows; `deploy/.gitattributes` enforces LF).

---

## 4. Configuration

### 4.1 Environment (`deploy/.env.production`)

Every variable of `src/lib/env.ts` is listed with an explanation in `deploy/.env.production.example`.
Key rules: optional settings stay **commented out** (an empty value is rejected); secrets never go in
this file; `NODE_ENV=production`, `TRUST_PROXY_HOPS=1`, `REPO_DIR=/data/repo` and the `JOB_SIGNER*`
variables are fixed per container by the compose file (web: `remote`; fetcher/migrate: `disabled`).
`REPO_PUBLIC=false` in the hosted deployment (connectors use the signed packages endpoint). Invalid configuration makes the container exit with
`Invalid PatchGate configuration: <field names>` (values are never printed).

Settings for notifications, monitoring and the one-line site install:

| Variable | Where | Meaning |
|---|---|---|
| `SMTP_URL` | `.env.production`, or better a secret file → `SMTP_URL_FILE` | `smtps://user:pass@host:465` (implicit TLS) or `smtp://user:pass@host:587` (STARTTLS; required in production). Unset = e-mails stay in the outbox as `SKIPPED` (§8) |
| `SMTP_FROM` | `.env.production` | sender, e.g. `PatchGate <patchgate@example.com>` (required together with `SMTP_URL`) |
| `NOTIFY_WEBHOOK_ALLOWED_HOSTS` | `.env.production` | exact Teams/Slack webhook host names, comma-separated. Unset = webhooks disabled. Webhook URLs are stored **encrypted** with `AUTH_ENC_KEY` (§9.4) |
| `METRICS_TOKEN` | secret `metrics_token` → `METRICS_TOKEN_FILE` (compose, web-1/2) | bearer token for `GET /api/metrics`; the same file is Prometheus' `credentials_file` (§8). Never also set `METRICS_TOKEN` in the env file |
| `PATCHGATE_SITE_BUNDLE_DIR` | fixed in compose: `/data/site-bundles` (volume `site-bundles`, read-only) | site bundles for `/install/*` (§6.1). Unset = 404 "site bundles not configured" |
| `PATCHGATE_SITE_BUNDLE_LATEST` | `.env.production` (optional) | version served as `latest` and as `site.sh`; unset = first line of `<dir>/LATEST` (switching needs no restart) |
| `AUTH_MFA` | `.env.production` (optional) | `required` (default): local sign-in = password **+ 6-digit TOTP**. `off`: password only — no TOTP step, no forced enrolment; stored TOTP secrets are kept, so switching back to `required` works at once (users without one enrol at the next sign-in). While `off`: warning banner for admins, `mfa:"off"` on `/api/health`, `checks.mfa=false` on `/api/ready` (report-only), warning on /operations, `auth.mfa_disabled` on the platform audit chain at every process start. Temporary-password change, lockout and session limits are unchanged. **Must be `required` before go-live.** Not used with `AUTH_MODE=oidc` (the IdP does MFA) |
| `PATCHGATE_SITE_BUNDLE_PUBKEY` | `.env.production` (required for web install) | `ed25519:<base64>` from `bundle-signing.pub.txt`; baked into `site.sh`. Unset = `site.sh` refuses downloaded bundles (sites would need `--bundle-key` or the lab-only `--allow-unsigned`) |

### 4.1a Roles (fixed — two roles, the same everywhere)

| Role | Platform (our team, `tenantId` empty) | Bank (`tenantId` set) |
|---|---|---|
| **Admin** (`ADMIN`) | everything, for every bank: banks, users, connectors, apps/patches, rings/windows, notification settings; raises change requests (maker); may be the **second** approver of a two-approver request | its own bank: users, settings; raises change requests **and approves them** (the bank's checker) |
| **Auditor** (`AUDITOR`) | read-only across every bank: banks, users, endpoints, patches, change requests, connectors, audit chains (incl. per-bank), reports/exports, operations | read-only within its bank: the same pages for its own bank |

Rules: an auditor never changes anything (only its own password / sessions; it may switch the bank it reads and
check a SIEM anchor — both change no data) and never sees one-time secrets (temporary passwords, enrolment codes,
webhook URLs are shown masked). Maker ≠ checker always; every change request needs ≥ 1 approving **admin of that
bank**; emergency / large requests need two distinct admins, at least one from the bank. A bank admin may reset
the password / authenticator of its bank's **auditors** only — resetting another admin needs a platform admin
(audited on the bank's chain; a bank admin must not take over a second admin account and approve its own work).
The database refuses the retired roles `VIEWER` / `OPERATOR` / `APPROVER` (CHECK `User_role_scope`).
SSO: `OIDC_ROLE_MAP` may map only to `ADMIN` / `AUDITOR` (start-up fails otherwise).

### 4.2 Secrets (`deploy/secrets/`, generated by `scripts/generate-secrets.sh`)

| File | Becomes | Notes |
|---|---|---|
| `audit_hmac_key` | `AUDIT_HMAC_KEY` | keys the audit chain. Loss = chain unverifiable. Never rotate casually (§9.3) |
| `auth_enc_key` | `AUTH_ENC_KEY` (64 hex) | AES-256-GCM key for TOTP secrets at rest (§9.4) |
| `job-signing-keys/default.pem`, `job-signing-keys/<tenantId>.pem` (+ `.pub.pem`, `FINGERPRINTS.txt`) | **signer only** (`SIGNER_KEY_DIR`) | Ed25519, one per bank (fallback `default`); dir 0700 / files 0600 owned by uid **10002** — no web/fetcher process can read them. Connectors pin the bank's key (§6, §9.1) |
| `job_signer_token` | `JOB_SIGNER_TOKEN_FILE` (web-1/2), `SIGNER_TOKEN_FILE` (signer) | bearer token web → signer; 0640, group 10001 |
| `pg_ca_cert` (+ CA key kept by `generate-secrets.sh`), `pg_tls_key`, `pg_tls_cert` | DB server TLS (`postgres/db-entrypoint.sh`) + CA every DB client verifies against | internal DB CA; server cert for `db` + `db-replica` signed by it. Clients VERIFY the server (Prisma `sslaccept=strict`, libpq `verify-full`) — §12 item 2 |
| `worker_token` | `WORKER_TOKEN` | scheduler ↔ worker endpoints |
| `metrics_token` | `METRICS_TOKEN_FILE` (web-1/2) + Prometheus `credentials_file` | 0640, uid/gid 10001; Prometheus runs as `65534:10001` to read it |
| `grafana_admin_password` | `GF_SECURITY_ADMIN_PASSWORD__FILE` (profile `monitoring`) | 0600, owned by uid 472 (Grafana) |
| `wsus_token` | `WSUS_TOKEN` | WSUS connector scripts |
| `tactical_api_key` | `TACTICAL_API_KEY` | placeholder in the hosted model (connectors call Tactical) |
| `db_app_password`, `db_owner_password` | `DATABASE_URL` (built by the entrypoint) | hex, URL-safe |
| `postgres_superuser_password`, `replication_password` | DB container / backup / replica | |
| `fingerprints.sha256` | — (not secret) | SHA-256 of each secret; copied into every backup manifest |

Mechanics: files are 0600, owned by uid 10001; compose mounts them at `/run/secrets/*`; the image
entrypoint turns `VAR_FILE=/run/secrets/x` into `VAR` (setting both aborts start). **Each container gets
only the secrets it uses** (list in the header of `docker-compose.prod.yml`): the fetcher gets
`db_app_password`, `audit_hmac_key` (it appends audit events) and `worker_token` only; config validation
still needs `AUTH_ENC_KEY`/`TACTICAL_API_KEY`, so the entrypoint fills those with random per-start values
(`PATCHGATE_EPHEMERAL_SECRETS`) that decrypt/authenticate nothing. Optional secrets
(`OIDC_CLIENT_SECRET`, `GITHUB_TOKEN`): add a file, a `secrets:` entry and `OIDC_CLIENT_SECRET_FILE` /
`GITHUB_TOKEN_FILE` in the service environment. **Escrow** an encrypted copy of `secrets/` offline
with two custodians — a database backup is useless without `audit_hmac_key` and `auth_enc_key`.

Job signing (`JOB_SIGNER`, `src/lib/connector/keys.ts`):

| Mode | Where the private key lives | Use |
|---|---|---|
| `remote` (production compose) | signer container only; web holds a bearer token | hosted platform |
| `file` | `JOB_SIGNING_KEY_FILE` inside the web process (one key for all banks) | lab / development only |
| `disabled` | nowhere — every signing call fails closed | fetcher, migrate |

Production target: keys in an HSM/KMS behind the same signer API (§9.7). Until then the per-bank PEM files
in the signer container (encrypted disk, uid 10002) are the interim control (residual risk, SECURITY.md R2).

Database TLS: every network connection to PostgreSQL must use TLS (`hostssl`) and VERIFIES the server
certificate against the internal DB CA (`pg_ca_cert`): Prisma via `sslaccept=strict&sslcert=<CA>` (Prisma 6.12
silently ignores `sslmode=verify-full` — do not rely on it), libpq clients via `sslmode=verify-full`. A wrong CA
or hostname is refused (proof: `scripts/test-db-tls.sh`). The superuser `postgres` can log in over the network **only** from
`DB_ADMIN_SUBNET` (the backup container); web/fetcher/migrate cannot, even with the password.

### 4.3 Host firewall (egress enforcement) — REQUIRED

Docker networks alone do not stop egress from `siem-out`, `fetch-egress` and `edge` (they need DNS and
NAT). Enforce in the `DOCKER-USER` chain (Docker never flushes it) and persist with `iptables-persistent`
or the nftables equivalent. Defaults: `SIEM_OUT_SUBNET=172.30.10.0/24`, `FETCH_EGRESS_SUBNET=172.30.20.0/24`,
`EGRESS_PROXY_IP=172.30.20.10`.

```bash
SIEM_IP=10.20.30.40; DNS1=10.0.0.53
# Rules are inserted at the top, so add the DROPs first and the ACCEPTs after them.
iptables -I DOCKER-USER -s 172.30.10.0/24 ! -d 172.30.10.0/24 -j DROP
iptables -I DOCKER-USER -s 172.30.20.0/24 ! -d 172.30.20.0/24 -j DROP
iptables -I DOCKER-USER -s 172.30.10.0/24 -d $SIEM_IP -p tcp --dport 6514 -j ACCEPT
iptables -I DOCKER-USER -s 172.30.20.10   -p tcp --dport 443 -j ACCEPT          # egress proxy → vendors
for net in 172.30.10.0/24 172.30.20.0/24; do
  iptables -I DOCKER-USER -s $net -d $DNS1 -p udp --dport 53 -j ACCEPT
  iptables -I DOCKER-USER -s $net -d $DNS1 -p tcp --dport 53 -j ACCEPT
done
# With AUTH_MODE=oidc also allow the IdP from 172.30.10.0/24 (tcp/443).
```

The networks `app`, `data`, `signer`, `fetch-ctl` and `db-admin` are `internal: true` (no route out at all),
so the signer and the database never need firewall exceptions. Web instances reach the outside only through
`siem-out`, which the rules above restrict to the SIEM (and IdP) — **web must have no general internet egress**.

Verify with `INTERNAL=1 ./scripts/smoke-test.sh …`: "web-1 has no direct internet egress", "fetcher
cannot bypass the proxy", "signer has no internet egress" and the key-isolation checks must PASS (they FAIL on a host without these rules — that was observed in the
validation run). The vendor allow-list itself is `deploy/egress-proxy/allowed-hosts.txt`; squid logs
`result=TCP_DENIED` for blocked hosts (alert §8). squid also refuses to connect to private, loopback,
link-local (incl. cloud metadata), CGNAT and IPv6 ULA/link-local addresses even for an allow-listed name
(DNS rebinding / hijacked vendor DNS); it checks the addresses it actually connects to. Apps with `strictHosts=false` follow redirects to mirror
networks — add reviewed mirror hosts or downloads fail closed.

### 4.4 Authenticode CA bundle (`ca/codesign-ca.pem`)

On Linux the fetcher verifies signatures with `osslsigncode verify -CAfile $CODESIGN_CA_FILE` and fails
closed without it. The Debian TLS bundle is **not** sufficient: build a bundle containing the roots that
issue code-signing certificates for the catalogue's vendors — at least *Microsoft Root Certificate
Authority 2010/2011* and *Microsoft Identity Verification Root CA 2020* (Microsoft binaries), DigiCert
(Assured ID / Trusted Root G4), Sectigo/USERTrust, GlobalSign, Entrust — plus their timestamping roots.
Keep the bundle under change control; test a known-good installer of each app after every change.

### 4.5 TLS certificate

`deploy/tls/fullchain.pem` + `privkey.pem` (0600 root). Public CA or our corporate CA — connectors pin
our CA/certificate at enrolment, so **coordinate renewals that change the CA or the pinned key** with all
banks (ARCHITECTURE-HOSTED §3). Reload: `$DC exec nginx nginx -s reload`. Alert 21 days before expiry.

---

## 5. First platform admin (TO VERIFY)

The bootstrap CLI is `patchgate-web/scripts/admin/create-user.ts` (another workstream). In production it
runs in the tools image via the one-shot `migrate` service:

```bash
$DC run --rm -it migrate node node_modules/tsx/dist/cli.mjs scripts/admin/create-user.ts \
    --upn admin@patchgate.example --name "First Admin" --role ADMIN --generate
```

TO VERIFY before go-live: (a) the command works in the tools image (tsx path aliases, `server-only` hook);
(b) it runs as `patchgate_owner` — check that its audit write is allowed under RLS (see §12, open item 1);
(c) the one-time password is shown once and must be changed at first sign-in, then TOTP enrolment.
Two named admins minimum; record the creation in the change ticket.

---

## 6. Onboarding a bank and enrolling connectors (high level)

1. **Contract & data-processing** agreement signed; bank security contact and change process recorded.
2. **Tenant**: platform admin creates the bank (short code, every change request then needs at least one approving
   admin from that bank — fixed platform rule, cannot be turned off) in Admin → Banks.
3. **Bank users**: create the bank admin (`create-user.ts --tenant <code> --role ADMIN`); the bank admin
   creates further admins / auditors (§4.1a). Bank admins are the bank's checkers and maker ≠ checker is enforced,
   so each bank needs at least **two** admins if bank staff also raise requests (one if only our team raises them).
4. **Network**: get the bank's egress NAT ranges for each connector site; create
   `deploy/nginx/allowlists/connectors.d/<bank-slug>.conf` (template `example-bank.conf.example`) with the
   change ticket, add its `include` line to `allowlists/connectors.conf`, reload nginx. The list is
   **default deny**; `default 1;` ("open") is for pilots/labs only and must be recorded as an exception.
   Legacy WSUS scripts (`/api/wsus/*`) and `/repo` return 404 at the edge unless the source IP is added to
   `allowlists/wsus.conf` / `allowlists/repo.conf` (legacy banks only, change ticket).
   **Job-signing key** (recommended for every production bank): `sudo ./scripts/generate-secrets.sh
   --job-key <Tenant.id>` then `$DC kill -s HUP signer` — **before** the first enrolment. Without it the
   bank uses the `default` key (`SIGNER_REQUIRE_TENANT_KEY=true` forbids that fallback).
5. **Enrolment code**: platform admin creates a one-time code (24 h, single use) per connector site and
   sends it out-of-band (not by the same channel as the connector package).
6. **Connector install** (bank side, on the Tactical host): install the signed connector package, give it
   `PUBLIC_BASE_URL`, the enrolment code, our CA/certificate pin and the bank's **job-signing key
   fingerprint** (`--job-key-fingerprint` at connector init: SHA-256 hex of the raw 32-byte Ed25519 public
   key, listed in `secrets/job-signing-keys/FINGERPRINTS.txt`, same value as `fingerprint` from the
   signer's `GET /v1/public-key?tenantId=…`), confirmed by phone with the bank. The enrolment response
   returns that bank's public key; the connector refuses it if it does not match the fingerprint.
7. **Verify**: connector shows "last seen" < 1 min; heartbeats every minute; a `SYNC_AGENTS` job returns
   the agent count the bank expects; the bank's SIEM receives the bank audit chain via the connector relay.
8. **Pilot ring** (≤ 10 PCs) through one full maintenance window before wider rings.

### 6.1 One-line site install (bundle upload)

"Connectors → Enrol a site connector" shows, next to the code, the command bank IT runs on the fresh site VM:
`curl -fsSL https://<PATCHGATE_HOSTNAME>/install/site.sh | sudo bash -s -- --code <code> --fingerprint <fp>`
(`--online` on a VM with internet). Send command and fingerprint over **two channels**; the fingerprint is read
back by phone. The VM must reach us from an address in the bank's connector allow-list (nginx `location ^~ /install/`
uses the same `$connector_ip_allowed` gate, `limit_req pg_connector`, unbuffered, 600 s). The code is checked
(unused, unexpired, active bank) but **not consumed** by the download; every served file is audited on the bank chain
(`connector.bundle_downloaded`: site, version, file, source IP, code-hash prefix — never the code). Wrong codes get a
uniform 403; 10 wrong codes from one address block it for 15 min (429). After the site enrols, PatchGate queues
`CACHE_PACKAGE` for the newest VERIFIED Tactical agent build (amd64 + 386) at that connector.

Uploading a new bundle (output of `installers/site/build-site-bundle.sh --sign-key <offline key>`): copy the
four files plus `SHA256SUMS.sig` into a new version directory, verify, then move the `LATEST` pointer. Production
bundles MUST be signed: `site.sh` refuses a downloaded bundle that has no valid signature from
`PATCHGATE_SITE_BUNDLE_PUBKEY`. USB installs: `--bundle-key ed25519:…` (value in TEAM-GUIDE) checks the same.

```bash
V=2026.10.1                                   # bundle version ([A-Za-z0-9._-], max 40)
VOL=$(docker volume inspect -f '{{.Mountpoint}}' patchgate_site-bundles)
sudo install -d -o 10001 -g 10001 -m 0755 "$VOL/$V"
sudo install -o 10001 -g 10001 -m 0444 out/SHA256SUMS out/patchgate-site-$V.tar.gz out/patchgate-site-$V-online.tar.gz out/install-site.sh "$VOL/$V/"
[ -f out/SHA256SUMS.sig ] && sudo install -o 10001 -g 10001 -m 0444 out/SHA256SUMS.sig "$VOL/$V/"
(cd "$VOL/$V" && sha256sum -c SHA256SUMS)     # verify BEFORE switching
echo "$V" | sudo tee "$VOL/LATEST.tmp" >/dev/null && sudo mv "$VOL/LATEST.tmp" "$VOL/LATEST"   # atomic switch
curl -fsS -o /dev/null -w '%{http_code}\n' https://$PATCHGATE_HOSTNAME/install/site.sh       # from an allow-listed IP: 200
```

Only names listed in that version's `SHA256SUMS` are served (`/install/bundle/<v>/<file>`, Range/206 for resume).
Keep the previous version directory until no site install is running (rollback = write the old version to `LATEST`).
`PATCHGATE_SITE_BUNDLE_LATEST` in `.env.production` overrides `LATEST` (then restart one at a time so connectors never see 502: `$DC up -d --no-deps web-1`, wait until healthy, then `web-2`). The same applies after changing `PATCHGATE_SITE_BUNDLE_PUBKEY`.

Offboarding: revoke all connectors (§9.2), export the bank's audit chain and reports, disable users,
remove allow-list entries, then delete tenant data per contract retention.

---

## 7. Backups and restore

### 7.1 What is backed up

| Data | How | When | Retention |
|---|---|---|---|
| PostgreSQL (everything incl. audit chains) | `pg_dump -Fc` streamed through `age` (public key only on the server) | daily `BACKUP_HOUR_UTC` (default 01:00) | `BACKUP_RETENTION_DAYS` (35) |
| Package store (`repo` volume) | `tar | age` | weekly (Sunday) — `BACKUP_REPO=weekly` | `BACKUP_REPO_RETENTION_WEEKS` (4) |
| Secrets | **manual escrow** (encrypted, offline, two custodians) after every rotation | on change | forever (previous versions too) |
| Config | `deploy/` in git (minus `.env.production`, `secrets/`, `tls/`), `.env.production` escrowed with secrets | on change | — |

Each DB backup has `.sha256` and `.manifest.json` (size, server version, migration head, secrets
fingerprints). `backups/last-run.json` is the heartbeat. Copy `BACKUP_DIR` off-host (object storage with
object lock / WORM, different region) — a backup on the same disk is not a backup.

The package store can also be rebuilt by re-fetching (packages are SHA-256 named and re-verified), but
Tactical releases and apps whose vendor URL rolled forward cannot always be re-fetched — keep the snapshot.

### 7.2 Manual backup

```bash
$DC exec backup patchgate-backup now     # DB (+repo if BACKUP_REPO=always)
$DC exec backup patchgate-backup repo    # package store
```

### 7.3 Restore drill (quarterly, and after every major upgrade) — non-disruptive

```bash
./scripts/restore.sh --file backups/db/patchgate-<ts>.dump.age --identity /media/usb/patchgate-backup.agekey --drop
```

The script checks the checksum, compares secret fingerprints with the manifest, creates a scratch DB
next to production, streams `age -d | pg_restore` (no plaintext on disk), grants the runtime role,
verifies the migration head and prints exact row counts per table, then drops the scratch DB. Record
the output in the drill log. **Validated** (2026-10-15, local Docker): backup → drill restore → row
counts, including rows in FORCE-RLS tables; full `--swap` restore → `/api/ready` all true.

### 7.4 Real restore (disaster) — disruptive

```bash
./scripts/restore.sh --file … --identity … --swap
```
Restores into a scratch DB, verifies, asks for `RESTORE`, stops scheduler/fetcher/web, renames the live
DB to `patchgate_pre_restore_<ts>` (kept), renames the restored DB into place, starts the app and waits
for `/api/ready`. Then: check `checks.auditChain=true`, run the smoke test, reconcile with the SIEM
(events after the backup time exist only in the SIEM — record the gap in the incident), and tell banks
which window was lost (jobs created after the backup are gone; connectors re-sync inventory).
Full host loss: provision host (§3 steps 0–2 with the **escrowed** secrets), `up -d db`, then restore.

### 7.5 Point-in-time recovery (tier M/L)

Nightly dumps give RPO ≤ 24 h. For RPO minutes, add WAL archiving (pgBackRest or WAL-G to object
storage) and keep the replica profile on; that is a separate change, not in the default stack.

---

## 8. Monitoring and alerts

Three sources, all from the monitoring network (outside the PatchGate host for paging):

1. **Metrics** — `GET /api/metrics` (Prometheus text format) on every web instance, `Authorization: Bearer $METRICS_TOKEN`.
   `METRICS_TOKEN` comes from the secret file `secrets/metrics_token` (`METRICS_TOKEN_FILE` on web-1/2; the same file is
   Prometheus' `credentials_file`); without it the endpoint is disabled (404). nginx serves it only to IPs in
   `nginx/allowlists/health.conf` (others 404). Aggregates only (per bank / per chain / per step) — never PC rows or secrets.
   Fast figures are cached 15 s, fleet-wide compliance and 24 h totals 5 min, the TLS probe 1 h.
2. **Readiness / liveness** — `GET /api/ready` (same allow-list) and `GET /api/health`; also exported as `patchgate_ready`.
3. **Logs** — JSON lines (§11); match on `msg`.

**Bundled stack (optional)** — compose profile `monitoring`: Prometheus (scrapes `web-1`/`web-2` directly on the
internal `app` network), Alertmanager and Grafana with the provisioned *PatchGate — Operations* dashboard.

```bash
sudo ./scripts/generate-secrets.sh                        # creates metrics_token + grafana_admin_password if missing
                                                          # (never overwrites; --rotate metrics_token replaces it)
$EDITOR monitoring/alertmanager.yml                       # receivers: pager for P1, team channel for P2/P3
docker compose -f docker-compose.prod.yml --env-file .env.production --profile monitoring up -d
ssh -L 3001:127.0.0.1:3001 <host>                         # Grafana UI (bound to 127.0.0.1 only)
```

**Notifications** (e-mail + Teams/Slack webhooks; outbox in the database, delivered by the `notifyDeliver` tick step):
`SMTP_URL` + `SMTP_FROM` enable e-mail (`smtp://…:587` STARTTLS or `smtps://…:465`; the URL contains the SMTP password, so
put it into a secret file and pass `SMTP_URL_FILE` to web-1/2). `NOTIFY_WEBHOOK_ALLOWED_HOSTS` lists the exact webhook
hosts admins may add (unset = webhooks off). Webhook URLs embed a secret token: they are stored encrypted with
`AUTH_ENC_KEY` and shown masked; rows from before that change are encrypted by the next tick (step status
`webhook URLs encrypted N`, audit `notification.webhooks_encrypted`). Unconfigured channels mark rows `SKIPPED`; failures
retry with backoff, then `DEAD` (Admin → Notifications outbox, manual retry).

Files: `monitoring/prometheus.yml`, `monitoring/alerts.yml` (rules below), `monitoring/alertmanager.yml`,
`monitoring/grafana/**`. Validate after edits:
`docker run --rm -v "$PWD/monitoring:/cfg" --entrypoint promtool prom/prometheus:v3.5.0 check rules /cfg/alerts.yml`.
An external Prometheus can scrape through nginx instead (from an allow-listed IP, same bearer token).

**Operations dashboard** — `/operations` (platform staff only; bank users get 403): every bank on one page, worst
first (connectors, job backlog, failures 24 h, approvals, compliance, SIEM relay) plus platform tiles (worker steps,
fetch runs, audit chains, SIEM export, repository quota, certificate). Same thresholds as the alerts
(`src/lib/metrics/thresholds.ts`). Opening a bank from there switches the acting bank (audited vendor access).

| Signal | Metric / source | Alert (`alerts.yml`) |
|---|---|---|
| Readiness | `patchgate_ready == 0`, `up{job="patchgate"} == 0`; `/api/ready` from the health allow-list | `PatchGateNotReady` / `PatchGateInstanceDown` 2 min → **P1** |
| Worker (scheduler) | `patchgate_worker_step_last_success_timestamp_seconds{step}` (`step="tick"` = whole tick), `_last_duration_seconds`, `_failures_total`; log `worker.tick.step_failed` (`step`, `durationMs`) | any step not succeeded for > 5 min → `PatchGateWorkerStepStale` **P1** (deployments / SIEM export stop) |
| Audit chain integrity | `patchgate_audit_chain_valid{chain} == 0` (also `/api/ready` `checks.auditChain=false`) | `PatchGateAuditChainBroken` → **P1 security incident** — §9.5 |
| SIEM export | `patchgate_siem_export_lag_seconds{chain}` (age of the oldest un-exported event) | > 15 min → P2; > 2 h → P1 (evidence gap) |
| Connector last seen | `patchgate_connector_last_seen_age_seconds{bank,connector}` (+Inf = never), `patchgate_connectors{state}` | > 10 min → P2 to the bank contact; > 4 h → P1 if a window is open |
| Job backlog | `patchgate_jobs_oldest_queued_age_seconds{bank}` (due jobs only), `patchgate_jobs_open{bank,type,status}` | oldest due job > 1 h → P2; queued grew > 100 in 1 h → P2 |
| Job failure rate | `patchgate_jobs_failed_24h` / (`_failed_24h` + `patchgate_jobs_succeeded_24h`) per bank | > 10 % (≥ 20 jobs) → P2; any `EXPIRED` deploy job inside a window → P2 (check `/operations`) |
| Change approvals | `patchgate_change_requests_pending_approval_oldest_age_seconds{bank}` | waiting > 24 h → P3 (bank admins = checkers) |
| Compliance | `patchgate_compliance_ratio{bank}`, `patchgate_endpoints_missing_severity{severity}` | dashboard only (amber < 95 % or any critical, red < 80 %) |
| Notifications | `patchgate_notification_outbox{bank,status}`, `_oldest_age_seconds` | undelivered > 30 min → P3 |
| Repository quota | `patchgate_repo_used_bytes` / `patchgate_repo_quota_bytes`, `patchgate_repo_quota_ok` | > 85 % → P3; exceeded (downloads paused) → P2 |
| TLS certificate | `patchgate_tls_cert_expiry_timestamp_seconds` (probe of `PUBLIC_BASE_URL`, best effort) — keep a blackbox probe too | < 21 days → P2; < 7 days → P1 |
| Fetch | `patchgate_fetch_runs_failed_24h{source}`, `patchgate_fetch_last_success_timestamp_seconds`; log `scheduler.fetch.failed` | no success in 26 h → P3; P2 on Patch Tuesday |
| Held packages | `patchgate_packages_held{kind}` | dashboard only (platform trust decisions waiting) |
| Monitoring itself | `patchgate_metrics_collect_errors{part}`, `patchgate_metrics_collect_duration_seconds{tier}`; log `metrics.collect.part_failed` | part failing 15 min → P3 |
| Job signer | `signer` container health; log `signer.denied` (reason `rate limited`, `unauthorized`, validation) and `signer.signed` volume per bank | signer unhealthy → P1 (no jobs can be created); any `unauthorized` → P2 security; rate-limit hits or unusual per-bank volume → P2 |
| Liveness | `GET /api/health`, container health, restart count | P1 if both web instances unhealthy; P2 single instance |
| Egress denials | egress-proxy `result=TCP_DENIED` | P3 (new vendor host) — P2 if from an unexpected client |
| Disk: package store | `df` on the `repo` volume | > 80 % P3, > 90 % P2 |
| Disk: DB / backups | volume usage; `backups/last-run.json` older than 26 h or `status=failed` | P2 |
| Replication | `pg_stat_replication` missing / `replay_lag` > 5 min; slot retained WAL > 10 GB | P2 |
| Edge | nginx 5xx rate > 1 % (5 min), 429 spikes, 403 on `/api/connector/*` from unknown IPs | P2 / P3 |
| Security events | audit: login failures/lockouts, MFA resets, role changes, trust decisions, connector enrol/revoke | forwarded to SIEM; SIEM correlation rules |

---

## 9. Incident playbooks and key rotation

General: open an incident, preserve evidence first (`docker compose logs > …`, DB snapshot via
`patchgate-backup now`), contain, then rotate. Inform affected banks within the contractual window
(India: CERT-In Directions 2022 require reporting within 6 hours; banks have their own short RBI
reporting deadlines — support them with evidence from the audit chain. Confirm timelines with Legal).

### 9.1 Job-signing key exposure / platform compromise — and routine per-bank key rotation

Blast radius by component (signer split): **web compromise** = the attacker can ask the signer to sign
well-formed jobs while they control web (rate-limited, every signature in the signer audit log) but cannot
steal a key; **fetcher compromise** = no signing ability (no key, no token, no route to the signer) — it can
only write unsigned job rows, which connectors reject; **signer/host compromise** = keys stolen → rotate every
affected bank key.

1. **Contain**: stop job dispatch — `$DC stop scheduler`; restrict nginx to management IPs
   (`allowlists/connectors.conf` → `default 0;`, comment out every bank include, reload) so connectors stop
   fetching jobs. If the signer itself is suspect: `$DC stop signer` (all signing fails closed).
2. Preserve evidence: signer audit (`$DC logs signer`; volume `signer-audit` → `audit.jsonl`, one JSON line
   per signature/denial with tenant, connector, job id, type, key fingerprint, envelope SHA-256), audit
   chains (platform + per bank), SIEM. A `ConnectorJob` row without a matching signer line was not signed by
   us. Cancel unexpected `QUEUED`/`DELIVERED` jobs.
3. **Rotate the affected key(s)** — per bank (*implemented*):
   ```bash
   sudo ./scripts/generate-secrets.sh --rotate-job-key <Tenant.id>   # or "default"; old key kept as *.retired-<ts>
   $DC kill -s HUP signer                                            # reload keys without restart
   cat secrets/job-signing-keys/FINGERPRINTS.txt                     # the bank's new fingerprint
   ```
   Escrow. Give the new fingerprint to the bank out-of-band (phone + ticket). Each of that bank's
   connectors must **re-pin**: re-run connector init with the new `--job-key-fingerprint` and a fresh
   enrolment code (the enrolment response carries the new public key; the connector refuses a key whose
   fingerprint does not match). Until re-pinned, its connectors reject jobs signed with the new key —
   rotate outside maintenance windows; cancel/re-create jobs still queued under the old key. Other banks
   are unaffected.
4. Rotate all other secrets (§9.6); rebuild the host from a known-good image if the host is suspect.
5. Re-open the allow-list per bank after each bank confirms the new pin.

Routine rotation (e.g. yearly per bank, or on staff change): steps 3 and 5 only.

### 9.2 Revoke a connector (lost/compromised connector host)

Platform admin sets the connector to `REVOKED` (UI/API — TO VERIFY); its signature is rejected from then
on. Remove its IP from the allow-list if the site is decommissioned. Cancel its queued jobs. The bank
reinstalls and re-enrols with a new one-time code (new key pair generated on the connector).

### 9.3 `AUDIT_HMAC_KEY` (do not rotate routinely) — PROCEDURE ONLY (no app support yet)

The chain verifies with the key it was written with. Rotate only if the key is exposed: (1) verify the
current chain and export it + the latest ANCHOR to the SIEM; (2) record the rotation as an audit event
with the old key; (3) switch the key and start a new chain segment — **requires app support for keyed
segments (not implemented at the time of writing)**. Until then, exposure means: keep the old
key in escrow for verifying history, and treat the SIEM copy as the authoritative record.
Containers holding this key: web-1/2, fetcher (it appends audit events) and migrate (admin CLI) — not the
signer, scheduler, nginx or backup. A fetcher compromise therefore triggers this procedure.

### 9.4 `AUTH_ENC_KEY` rotation (TOTP secrets at rest)

No user re-enrols. The app always **encrypts** with `AUTH_ENC_KEY` and **decrypts** with `AUTH_ENC_KEY` or the
optional, decrypt-only `AUTH_ENC_KEY_PREVIOUS` (64 hex, must differ). Every ciphertext names its key by an
8-hex key id (`v1.<iv>.<tag>.<ct>.<kid>`; older ciphertexts without a key id still decrypt with either key).
The re-encryption CLI is `patchgate-web/scripts/admin/rotate-auth-enc-key.ts`.

1. **Generate the new key**, keeping the old one: `cp -p secrets/auth_enc_key secrets/auth_enc_key_previous`,
   then `generate-secrets.sh --rotate auth_enc_key`. Escrow both files.
2. **Deploy with both keys**: `AUTH_ENC_KEY` = new, `AUTH_ENC_KEY_PREVIOUS` = old, on web-1/2 and migrate,
   then `$DC up -d`. Sign-in keeps working for everyone (old secrets decrypt with the previous key; new
   enrolments use the new key).
3. **Re-encrypt** (tools image, same env as step 2):
   `$DC run --rm migrate node node_modules/tsx/dist/cli.mjs scripts/admin/rotate-auth-enc-key.ts --dry-run`,
   then the same command without `--dry-run`. The CLI rewrites every `User.totpSecretEnc` and pending
   `AuthChallenge.pendingSecretEnc` under the new key in batches (one transaction per batch, `--batch-size`,
   default 100), and every notification webhook URL (`NotificationSetting.webhookUrlsEnc`, any remaining legacy
   plaintext, `WEBHOOK` outbox targets). It prints counts only and writes one platform audit event `auth.enc_key_rotated`. It is
   idempotent: run it again and check `re-encrypted 0`. Exit code 1 = some secrets were undecryptable with
   either key; reset MFA for those users (they re-enrol at next sign-in).
4. **Remove the previous key**: unset `AUTH_ENC_KEY_PREVIOUS`, `$DC up -d`, delete
   `secrets/auth_enc_key_previous` once the escrow holds the new key. Check that a test user signs in.

Deploy wiring: `generate-secrets.sh --rotate auth_enc_key` moves the current key to `secrets/auth_enc_key_previous`
(never overwrites a different previous key without `--force`); add `-f docker-compose.rotation.yml` to the compose
command for steps 2–3 (it passes `AUTH_ENC_KEY_PREVIOUS_FILE` to web-1/2 and migrate); drop that override in step 4.
Containers holding these keys: web-1/2 and migrate only (the fetcher gets a random placeholder).
Compromised key: same procedure, but in step 4 also reset MFA for every user. An attacker with the old key
and a database copy taken before the rotation can still read the old TOTP seeds.

### 9.5 Audit chain verification failed (`auditChain=false`)

Treat as tampering until proven otherwise. Freeze DB access (revoke interactive DB logins), snapshot the
DB, compare with the SIEM copy (events + ANCHORs), identify the first bad link, inform affected banks. Do
not "fix" rows — restore is a decision for the incident lead.

### 9.6 Other secrets

`worker_token`, `wsus_token`, `job_signer_token`, DB passwords: `generate-secrets.sh --rotate <name>`, then
for DB passwords `ALTER ROLE … PASSWORD` with the new value (as `postgres`), then `$DC up -d` (recreates
containers with the new secret; for `job_signer_token` signer and web restart together). DB TLS
certificate: `--rotate pg_tls`, then `$DC restart db`. Update escrow and run the smoke test.

### 9.7 HSM / KMS integration path (target — not implemented)

The signer API (`POST /v1/sign`, `GET /v1/public-key`) is the integration seam: the web tier does not
change. Replace the PEM loading in `deploy/signer/server.mjs` with one of:

- **PKCS#11 HSM** (e.g. Thales Luna, Entrust nShield, YubiHSM 2, AWS CloudHSM): Ed25519 via `CKM_EDDSA`
  (PKCS#11 v3.0) on current firmware; one non-exportable key object per bank (label = Tenant.id,
  `CKA_SIGN` only); the signer logs in as a crypto user with a PIN from a secret file. Confirm the
  vendor's EdDSA support before purchase.
- **Cloud KMS with Ed25519** (e.g. Google Cloud KMS `EC_SIGN_ED25519`; Azure Managed HSM / AWS KMS:
  verify Ed25519 availability in the region, otherwise use the vendor's PKCS#11 HSM): the signer sends
  `canonicalJson(envelope)` for a raw-message signature and keeps only key IDs. Use workload identity, not
  long-lived cloud credentials; IAM limited to `sign` + `getPublicKey` on the bank keys.
- Keep envelope validation, rate limits and the JSON audit trail in the signer; the HSM/KMS log is a second,
  independent trail (ship both to the SIEM). Rotation stays per bank (§9.1): new key version → new
  fingerprint → connectors re-pin.



---

## 10. Upgrades and rollback

1. Read the release notes; check whether migrations are **additive** (expand/contract). Destructive
   migrations need a maintenance window.
2. Build/pull `patchgate-web:<new>` and `patchgate-tools:<new>` (same `PATCHGATE_BUILD_ID` →
   Next.js `deploymentId`, so browsers on the old version hard-reload instead of breaking).
3. `$DC exec backup patchgate-backup now` and copy it off-host.
4. Set the new tags in `.env.production`; `$DC run --rm migrate`.
5. Rolling restart: `$DC up -d --no-deps web-1` → wait healthy → `web-2` → `fetcher` → `scheduler`.
   nginx retries idempotent failures on the other instance.
6. Smoke test; watch 5xx/readiness for 30 min.

Rollback: if the migration was additive, set the previous tags and repeat step 5. If a migration failed
or was destructive: `restore.sh --swap` from the step-3 backup (Prisma has no down-migrations), then the
previous tags. Never edit `_prisma_migrations` by hand without the dev team.

---

## 11. Logging and retention

- **Format**: JSON lines on stdout/stderr: `{"ts","level","msg",…fields}`. New code uses
  `src/lib/log.ts` (`log.info("area.event", { … })`, `log.child({ component })`); `msg` is a stable dotted
  event name, data goes in fields, secret-looking keys (password, token, secret, authorization, cookie,
  api key, private key, session, totp, …) are redacted automatically, URL query strings are dropped.
  `LOG_LEVEL` = debug | info | warn | error | silent (default info). The scheduler, backup, nginx and
  egress-proxy emit the same shape. Existing `console.*` calls in the app will migrate over time.
- **Collection**: Docker `json-file` with rotation (50 MB × 10 per container) as a local buffer; ship to
  the central log platform (Fluent Bit/Vector reading the Docker logs). Do not rely on the host buffer.
- **Retention**: application/access logs 90 days hot + 1 year archive (bank audit expectations); the
  **audit chain** (DB + SIEM) is the system of record for security events — retained per contract,
  minimum 5 years (align with each bank's record-retention policy / RBI expectations); backups 35 days
  rolling + monthly copies for 12 months if contracts require.
- Never log secrets, package contents, full request bodies, TOTP codes or enrolment codes.

---

## 12. Open items (updated 2026-10-15, after the review-fix round)

Resolved since the first validation run (kept for history):
- ~~Writes outside `withTenant/withPlatform` fail under the production DB role~~ — fixed: `appendAudit` scopes
  itself; every connector path uses the helpers; integration tests run as a NON-owner role (`app-role`,
  `deploy-pipeline`, `tenancy` suites) and pass.
- ~~`next build` fails / routes read `env()` during prerender~~ — fixed (`await connection()` in the auth
  callback and login routes); `patchgate-web:rc1` builds with type-checking ON.
- ~~One failing tick step returns 500~~ — fixed: every worker step is isolated and reported per step.
- ~~Tenant creation / connector revoke / re-pin procedures~~ — implemented: new banks get default rings,
  connector revoke + edit limits in /connectors, re-enrolment is two-phase (old key valid until the new key
  signs), the init command carries `--job-key-fingerprint`.

Still open:
1. Job-signing keys in HSM/KMS (§9.7; the signer service is in place); keyed audit-chain segments for
   `AUDIT_HMAC_KEY` rotation; `AUTH_ENC_KEY` re-encryption CLI.
2. ~~PostgreSQL TLS is encrypt-only~~ — **done (2026-10-16): DB TLS is verified.** `generate-secrets.sh`
   creates an internal DB CA (`pg_ca_key` stays on the host, never mounted; `pg_ca_cert` is the public
   secret every client gets) and a server certificate for `db` + `db-replica` signed by it (`pg_tls_*`,
   825 days; re-issued automatically if missing, still the old self-signed one, without both SANs, or
   expiring within 30 days). Clients verify chain **and** hostname:
   - Prisma (web-1/2, fetcher, migrate): `DB_URL_PARAMS=…&sslmode=require&sslaccept=strict&sslcert=/run/secrets/pg_ca_cert`
     (`sslcert` is Prisma's name for the CA file). **Prisma 6.12 accepts `sslmode=verify-full` silently and
     does NOT verify** (tested: a wrong CA still connected) — never use it; keep this form if you override
     `DB_URL_PARAMS` in `.env.production`.
   - libpq: backup `PGSSLMODE=verify-full` + `PGSSLROOTCERT`; db-replica the same for `pg_basebackup` and
     `primary_conninfo` (rewritten on every start, so existing replicas pick it up). The replica also
     serves TLS with the same certificate, so clients keep verifying after a promotion. `restore.sh` uses
     the db container's Unix socket (no network hop, no TLS).
   Upgrade: `sudo ./scripts/generate-secrets.sh` (adds the CA, re-issues `pg_tls_*`), then
   `$DC up -d` so db, db-replica and every client restart with the new secret mounts; run the smoke test
   (the "all network clients use TLS" check). Rotation: `--rotate pg_tls` (new server cert, same CA:
   restart db + db-replica) or `--rotate pg_ca` (new CA + cert: restart db, db-replica **and** all clients
   together). Proof: `./scripts/test-db-tls.sh` runs the real compose file on an isolated throw-away project
   — verify-full / `sslaccept=strict` pass with the right CA and fail with a wrong CA or a wrong hostname,
   `sslmode=disable` is rejected, the replica streams over verify-full. Remaining: the replica still uses the
   image's default pg_hba (not the generated one).
3. Upgrading an existing installation to the signer layout: run `generate-secrets.sh` once (it migrates
   `job_signing_key.pem` → `job-signing-keys/default.pem`, so existing connector pins stay valid, and
   creates `job_signer_token` + `pg_tls_*`), `$DC build signer`, `$DC up -d`. The DB applies TLS and the
   generated pg_hba on its next start. Delete `secrets/job_signing_key.pem` after verifying the signer.
4. Real Windows PC end-to-end (agent from site cache, discovery, approved install confirmed by inventory,
   offline Windows Update scan + install) is validated in the lab's Windows Sandbox — see
   lab/sandbox/AFTER-RESTART.md — before the first bank pilot.
5. Host firewall egress rules (§4.3) cannot be verified on Docker Desktop; verify them on the real server.
