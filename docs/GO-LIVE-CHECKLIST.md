# PatchGate — Go-live checklist

One page, in order. Details are in RUNBOOK.md (§ numbers below), security background in SECURITY.md,
architecture in ARCHITECTURE-HOSTED.md.

Legend: **[YOU]** = your decision or action · **[OPS]** = your server admin · **[BANK]** = the bank's IT/security team

## A. Before the first pilot

| # | Who | Step | Done |
|---|---|---|---|
| A1 | YOU | Restart the dev PC once, then run the real-PC lab test: `lab/sandbox/AFTER-RESTART.md` (agent from site cache, discovery, maker→checker install confirmed by inventory, offline Windows Update scan). This is the only flow not yet proven on a real Windows PC. | ☐ |
| A2 | YOU | Decide the server: Linux VM or bare metal (sizing RUNBOOK §1.2), a public DNS name, and a TLS certificate. | ☐ |
| A3 | YOU | Decide where the job-signing keys live: the signer container with key files (works now), or HSM/KMS (RUNBOOK §9.7 — not built yet). | ☐ |
| A4 | YOU | Confirm the commercial/licensing position for Tactical RMM (its licence is not plain open source; commercial use needs AmidaWare's terms). | ☐ |
| A5 | YOU | Set an off-site backup destination and generate the backup key pair OFFLINE (RUNBOOK §7). | ☐ |

## B. Production server (our platform)

| # | Who | Step | Done |
|---|---|---|---|
| B1 | OPS | Install Docker, apply the host firewall egress rules (§4.3) — only the egress proxy may reach the internet. | ☐ |
| B2 | OPS | Build or pull the images `patchgate-web` + `patchgate-tools` (same version) and the signer, egress-proxy and backup images (§3). | ☐ |
| B3 | OPS | `deploy/scripts/generate-secrets.sh`, fill `deploy/.env.production` from `.env.production.example`, TLS cert, CA files (§4). | ☐ |
| B4 | OPS | One-shot `migrate`, then `docker compose up -d` (§3). | ☐ |
| B5 | OPS | `deploy/scripts/smoke-test.sh` — every check PASS. | ☐ |
| B6 | OPS | Create the first platform admin with the tools image (§5); sign in and enrol the authenticator. | ☐ |
| B7 | OPS | Monitoring: alerts from RUNBOOK §8 (readiness auditChain/siemExport/repoQuota, connector offline > 10 min, job failure rate, disk, certificate expiry). | ☐ |
| B8 | OPS | Restore drill once (§7.3) and record the result. | ☐ |

## C. Onboarding each bank

| # | Who | Step | Done |
|---|---|---|---|
| C1 | YOU | Admin → Banks: create the bank (gets rings Test/Pilot/Production automatically). Choose: approval by bank staff required (default ON), Windows updates via PatchGate (default) or the bank's own WSUS. | ☐ |
| C2 | YOU | Admin → Users: create the bank's admin and approvers (temporary passwords handed over out of band; they must enrol an authenticator). | ☐ |
| C3 | BANK | Provide a small Linux VM (or Docker host) next to their Tactical server for the connector; internal TLS certificate for the package cache; firewall: outbound 443 ONLY to our domain/IP, inbound from PC subnets to the cache port. | ☐ |
| C4 | YOU | Connectors → Enrol: create a one-time code for the site. Send the init command and the **job-key fingerprint** to the bank over two different channels. | ☐ |
| C5 | BANK | Run the init command on the connector host. The connector refuses to enrol if the fingerprint does not match. Register the three PatchGate PowerShell scripts in their Tactical and put the script ids in the connector config (connector README). | ☐ |
| C6 | BANK | Optional but recommended: set the bank-held trust policy in the connector config (`trust.publishers`, `trust.agentSha256`) so even a compromised vendor platform could not push other software. | ☐ |
| C7 | BANK | Point their SIEM at the connector's audit relay (TLS syslog) and enable the chain-break/regression/silence rules (SECURITY.md). | ☐ |
| C8 | YOU | Connectors page shows the site ONLINE; set LAN limits for the site (concurrent installs, bandwidth cap). | ☐ |
| C9 | BANK + YOU | Pilot: Ring0 (a few test PCs) → maker creates a change request, bank approver approves, install inside the maintenance window, check inventory confirmation and the bank SIEM. Then Ring1, then Ring2. | ☐ |

## D. Known limits at go-live (accepted or planned)

- Job-signing keys are files in the signer container until HSM/KMS integration (§9.7).
- PostgreSQL TLS is encrypt-only (server certificate not verified) on the internal network.
- `AUDIT_HMAC_KEY` / `AUTH_ENC_KEY` rotation are documented procedures, not one-click.
- Windows updates delivered through PatchGate: only updates listed in the Microsoft Update Catalog with
  language-neutral files (all security/cumulative updates are); others need the bank's WSUS mode.
- Unsigned third-party installers (e.g. 7-Zip MSI) are rejected by design.
- CSP allows inline scripts (framework limitation with prerendered pages); no XSS sinks were found in review.
