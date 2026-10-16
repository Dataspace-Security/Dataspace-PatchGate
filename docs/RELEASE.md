# PatchGate — Release process

How a PatchGate release is versioned, built, verified, shipped and rolled back. Operations detail for the
server upgrade itself is in RUNBOOK.md §10; this document is the release-engineering side.

## 1. What a release is

One version number for everything we ship, kept in the repository's **`VERSION`** file (e.g. `1.0.0-rc2`):

| Component | Where the version shows up |
|---|---|
| PatchGate server (`patchgate-web`, `patchgate-tools`) | image tag; build arg `PATCHGATE_BUILD_ID` (= Next.js `deploymentId`, which allows only `[A-Za-z0-9_-]`, so dots are encoded: `1.0.0-rc2` → `1_0_0-rc2`); `GET /api/version` and the sidebar footer label decode it back |
| Connector (`patchgate-connector`) | image tag; bundle name; `patchgate-connector version`; heartbeat. Comes from `patchgate-connector/package.json` (owned by the connector) — `release.sh` **refuses to release** if it differs from `VERSION` |
| Signer, egress proxy, backup | image tags `patchgate-signer:<v>`, `patchgate-egress-proxy:<v>`, `patchgate-backup:<v>` |
| Site bundle | `patchgate-site-<v>.tar.gz` (+ `-online`) when the installers can build it |

`GET /api/version` returns `{ version, buildId, gitSha, protocolVersion }` (no secrets, no auth, like
`/api/health`). `gitSha` is filled when the container gets `PATCHGATE_GIT_SHA` (the image also carries it as
the OCI label `org.opencontainers.image.revision`).

The connector protocol has its own integer `PROTOCOL_VERSION` (`patchgate-web/src/lib/connector/protocol.ts`,
byte-identical copy in the connector — `npm test` in the connector enforces that).

## 2. Versioning policy (SemVer 2.0)

| Bump | When |
|---|---|
| **MAJOR** | Anything an operator or a bank cannot take with a plain rolling upgrade: a `PROTOCOL_VERSION` change that old connectors cannot speak, a destructive / non-expand-contract migration, removed or renamed configuration (env vars, secrets, compose services), removed API endpoints that connectors or scripts use. |
| **MINOR** | New features, new optional configuration, **additive** migrations (new tables/columns with defaults, backfills), new protocol fields that old connectors ignore. |
| **PATCH** | Bug and security fixes only. Migrations only if additive and required for the fix. |
| `-rc.N` / `-rcN` | Release candidates for the next version; published as GitHub *pre-releases*; never on bank production without the pilot sign-off in GO-LIVE-CHECKLIST.md. |

Rules: tags are `v<VERSION>`; a tag is never moved or re-used; every release has a `## [<version>]`
section in `CHANGELOG.md` (the release fails without it) that lists migrations and protocol changes
explicitly; the connector version equals `VERSION` for every release.

## 3. Cut a release (3 commands)

Prerequisites: Docker (BuildKit), Node 24, bash (Git Bash on Windows works), internet (base images,
vulnerability DB). The connector owner bumps `patchgate-connector/package.json` to the same version.

```bash
# 1. Bump VERSION, write the CHANGELOG section (move "Unreleased" items), commit.
echo 1.0.0 > VERSION && $EDITOR CHANGELOG.md && git commit -am "chore: release 1.0.0"
# 2. Build + verify locally (full gate incl. integration tests, images, SBOMs, scans, bundles).
release/release.sh 1.0.0
# 3. Tag and push: .github/workflows/release.yml rebuilds, pushes, signs and publishes the GitHub release.
git tag -s v1.0.0 -m "PatchGate 1.0.0" && git push origin main v1.0.0
```

Without GitHub (air-gapped build host): step 2 with `--push <registry>` and `COSIGN_KEY=…`, then hand over
`release/out/<version>/`.

### `release/release.sh` options

| Option | Effect |
|---|---|
| `--skip-int` | skip integration tests (no throwaway Postgres) — for quick local iterations only |
| `--push <registry>` | tag + push all images as `<registry>/<name>:<version>`; digests go into `manifest.json` |
| `--allow-vulns` | do not fail on CRITICAL findings (still reported) |
| `--allow-dirty` | allow uncommitted changes (recorded in the manifest) |
| `--allow-version-skew` | allow connector version ≠ `VERSION` (test builds only; flagged in the notes) |
| `--site-bundle auto\|yes\|no` | `auto` (default): build the site bundle only when `installers/site/build-site-bundle.sh` and its inputs (Tactical agent installers, Tactical compose file, Tactical images) exist; otherwise skip with the reason |
| `--site-args "<args>"` | passed to the site bundle builder (e.g. `--agent-dir … --agent-sha256 … --pull`) |
| `--ci-install` | `npm ci` in both projects first |
| `--no-pull` | do not refresh base images (default refreshes them for patched bases) |
| `--out <dir>` | output root (default `release/out`) |

Environment: `COSIGN_KEY` (+ `COSIGN_PASSWORD`, `COSIGN_PUB`, `COSIGN_TLOG=true` to also log to the public
Rekor), `PATCHGATE_SOURCE_URL` (OCI source label), tool image overrides `SYFT_IMAGE`, `GRYPE_IMAGE`,
`COSIGN_IMAGE`, `SHELLCHECK_IMAGE`, `POWERSHELL_IMAGE`, `POSTGRES_TEST_IMAGE`.

### What it does

1. **Preflight**: semver argument = `VERSION`; CHANGELOG section present; connector version = `VERSION`;
   in a git tree: clean tree, no nested repositories, tag check, git sha recorded.
2. **Quality gate** (stops at the first failure, prints the tail of the log; full logs in
   `release/.work/<v>/logs/`): web typecheck · lint · unit · `prisma migrate deploy` + integration tests on a
   throwaway `postgres:16-alpine` container (free port, random password, tmpfs, always removed) · connector
   protocol sync + tests + bundle build (bundle must report the expected version) · signer tests ·
   `release/check-scripts.sh` (PowerShell parser on every `.ps1`, `bash -n` + shellcheck on every `.sh`;
   shellcheck fails on errors, lists warnings).
3. **Images** with OCI labels (`title`, `version`, `revision`, `created`, `vendor`, `source`), web/tools with
   `PATCHGATE_BUILD_ID=<version with "." → "_">`. Building by hand: use the same encoding —
   `next build` rejects a `deploymentId` containing dots (RUNBOOK §3's `VER=1.0.0` example needs it too).
4. **SBOM + scan**: `docker save` → syft CycloneDX JSON → grype (from the SBOM; DB cached in the Docker
   volume `patchgate-grype-db`). Fails on any CRITICAL unless `--allow-vulns`.
5. **Bundles**: `patchgate-connector-<v>.tar.gz` (bundle, README, example config/compose, systemd unit) and
   the plain `.mjs`; the site bundle when possible.
6. Optional **push** and **signing**; then `manifest.json`, `release-notes.md`, `SHA256SUMS`
   (+ `SHA256SUMS.sig`). Everything is built in `<v>.partial/` and swapped in at the end, so re-running is
   safe and a failed run never leaves a half-written release.

Output: `release/out/<version>/{images,sbom,scans,bundles}/`, `manifest.json`, `release-notes.md`,
`SHA256SUMS*` (`release/out/` and `release/.work/` are git-ignored).

## 4. CI

- `.github/workflows/ci.yml` (PRs + `main`): web gate with a Postgres service container (migrations, unit,
  integration), connector gate (incl. version warning), script checks + secret audit + actionlint, docker
  build of every image (no push, GHA cache).
- `.github/workflows/release.yml` (tags `v*`): `release.sh --ci-install --push <REGISTRY>`, cosign
  **keyless** (GitHub OIDC) for image digests, CycloneDX attestations and `SHA256SUMS` — or key-based when
  the `COSIGN_PRIVATE_KEY` secret exists — then a GitHub release with bundles, SBOMs, scan summaries,
  manifest, notes and checksums. Image tarballs stay in the registry (asset size limits).
- `.github/dependabot.yml`: weekly updates for actions, npm (both projects) and base images. Pinning actions
  to commit SHAs is recommended once the repository exists (Dependabot keeps them current).

## 5. Verify a release

```bash
cd release/out/1.0.0 && sha256sum -c SHA256SUMS                    # or --ignore-missing for GitHub assets
cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig --insecure-ignore-tlog=true SHA256SUMS   # key-based
cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/.+/.github/workflows/release.yml@refs/tags/v1.0.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS                      # keyless
cosign verify <registry>/patchgate-web@sha256:… --certificate-identity-regexp … --certificate-oidc-issuer …
curl -s https://<patchgate-host>/api/version                        # after deployment
```

## 6. Upgrade order (always)

1. **Server first** (RUNBOOK §10): read the notes (migrations additive?) → `$DC exec backup patchgate-backup now`
   and copy off-host → load/pull the new images → set `PATCHGATE_IMAGE` / `PATCHGATE_TOOLS_IMAGE` (and
   `SIGNER_IMAGE`) to the new tag → `$DC run --rm migrate` → rolling restart `web-1` → healthy → `web-2` →
   `fetcher` → `scheduler` (signer / egress-proxy / backup when their images changed) → smoke test →
   `/api/version` shows the new version → watch 5xx / readiness for 30 min.
   Offline host: `docker load -i images/<name>-<v>.tar.gz` for each image. `deploy/docker-compose.prod.yml`
   currently names the egress proxy and backup images `:local`; until it takes variables for them, tag the
   loaded images: `docker tag patchgate-egress-proxy:<v> patchgate-egress-proxy:local` (same for backup).
2. **Connectors** next, bank by bank / site by site (bundle or image; `patchgate-connector check` after the
   restart). A server release accepts connectors of the previous release with the same `PROTOCOL_VERSION`;
   a protocol bump is a MAJOR release and its notes give the cut-over.
3. **Site bundles** last (`install-site.sh` from the new `patchgate-site-<v>` bundle), only when the bundle
   changed (Tactical / agent / endpoint scripts).

## 7. Rollback

- **Server, additive migrations**: set the previous image tags and repeat the rolling restart (the old code
  ignores new columns/tables). Next.js `deploymentId` makes browsers hard-reload instead of mixing versions.
- **Server, failed or destructive migration**: `restore.sh --swap` from the pre-upgrade backup (Prisma has no
  down-migrations), then the previous tags. Never edit `_prisma_migrations` by hand.
- **Connector**: reinstall the previous bundle/image; its state directory is compatible within a
  `PROTOCOL_VERSION`. Re-enrolment is not needed.
- **Site bundle**: re-run the previous bundle's `install-site.sh`.
- A broken release is never re-tagged: fix forward with the next PATCH (or `-rcN+1`) and mark the GitHub
  release as such in its notes.

## 8. Vulnerability policy

CRITICAL (grype) blocks the release unless consciously overridden with `--allow-vulns` (CI: the
`allow_vulns` input of a manual re-run) and the reason is written into the CHANGELOG section. HIGH findings
are listed in the console, `scans/*.summary.json` and the release notes; fix them in the next PATCH when a
fixed version exists. Base images are refreshed (`--pull`) on every release.

## 9. Secret hygiene

- The root `.gitignore` makes accidental commits of secrets and bulky artifacts impossible by default: every
  `*.pem/*.key/*.crt/*.p12/…`, every `.env*` except `*.example`, every `secrets*` path, `deploy/secrets/`,
  `deploy/tls/*`, `deploy/ca/*` (README only), lab credentials and generated folders, `node_modules`,
  `.next*`, `dist`, `coverage`, `test-results`, e2e reports, `*.tar.gz` and installer binaries,
  `repo-data/`, `release/out/`, logs.
- The only negated key material are the connector **test fixtures** (self-signed, CN "PatchGate Connector
  Test CA" / localhost, used only by `patchgate-connector/test/helpers/common.ts`):
  `patchgate-connector/test/fixtures/localhost.key`, `localhost.pem`, `test-ca.pem`.
- `release/audit-tree.sh` lists what `git add -A` would commit (scratch repository in `$TMPDIR`, never a
  `.git` in the tree) and scans that set for private keys, cloud/GitHub/Slack tokens, PatchGate secret
  assignments (`AUDIT_HMAC_KEY`, `AUTH_ENC_KEY`, `WORKER_TOKEN`, `WSUS_TOKEN`, `METRICS_TOKEN`, …), password
  literals, credentials in URLs and enrolment codes. It prints only `file:line rule`, never values. HIGH
  findings fail it (CI runs it on every PR); documented false positives go into
  `release/secret-scan-allowlist.txt` with a reason.
- Before the first `git init` at the repository root: `patchgate-web/.git` (left over from
  `create-next-app`, one commit) must be removed or moved, otherwise the root repository stores
  `patchgate-web` as a gitlink and none of its files. `audit-tree.sh` warns about it and `release.sh`
  refuses to run in a git tree that has nested repositories.
