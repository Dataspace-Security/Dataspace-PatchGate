# PatchGate

Patch approval and delivery for banks: PatchGate (hosted by Dataspace Security) verifies Windows and
third-party updates, a bank admin approves them, and the bank's own offline Tactical RMM installs them
through the PatchGate Connector. Nothing reaches a bank PC without verification, maker-checker approval
and an audit trail.

| Folder | What it is |
|---|---|
| `patchgate-web/` | PatchGate server: web UI, API, worker (Next.js, PostgreSQL) |
| `patchgate-connector/` | Connector at each bank site (outbound-only, signed jobs, package cache) |
| `deploy/` | Production stack: nginx, web ×2, fetcher, signer, Postgres, backups, monitoring |
| `installers/` | Server, bank site and PC installers |
| `release/` | Release pipeline (tests, images, SBOM, vulnerability scan, signing) |
| `kits/colleague-test/` | One-script test install on your own PC (all in Docker) |
| `lab/` | Development lab |
| `docs/` | RUNBOOK, TEAM-GUIDE, SECURITY, GO-LIVE-CHECKLIST, architecture |

**Try PatchGate on your own PC (test setup, all in Docker):**

```bash
curl -fsSLO https://raw.githubusercontent.com/Dataspace-Security/Dataspace-PatchGate/main/kits/colleague-test/install-patchgate-test.sh
bash install-patchgate-test.sh
```

Accounts, start over (`--reinstall`) and cleanup: [kits/colleague-test/START-HERE.md](kits/colleague-test/START-HERE.md)

**One bank, everything on one bank server (one link):** [docs/BANK-INSTALL.md](docs/BANK-INSTALL.md)

```bash
curl -fsSL https://raw.githubusercontent.com/Dataspace-Security/Dataspace-PatchGate/main/installers/bank/install.sh | sudo bash -s -- --domain bank.local
```

**Real installation:** [docs/TEAM-GUIDE.md](docs/TEAM-GUIDE.md) (step by step) and [docs/RUNBOOK.md](docs/RUNBOOK.md).
Version: see [VERSION](VERSION) and [CHANGELOG.md](CHANGELOG.md).
