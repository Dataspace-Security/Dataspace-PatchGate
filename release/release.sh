#!/usr/bin/env bash
# PatchGate release build.
#
#   release/release.sh <version> [options]
#
# Builds, tests, scans and packages one release into release/out/<version>/ :
#   images/<name>-<version>.tar.gz     `docker save` of every image (load with `docker load -i`)
#   sbom/<name>-<version>.cdx.json     CycloneDX SBOM per image (syft)
#   scans/<name>-<version>.grype.json  vulnerability report per image (grype) + .summary.json
#   bundles/                           connector bundle (+ site bundle when the installers can build it)
#   release-notes.md                   generated from CHANGELOG.md + artifact tables
#   manifest.json                      versions, image ids/digests, SBOM counts, vuln counts, timings
#   SHA256SUMS (+ SHA256SUMS.sig, cosign.pub when signing)
#
# Steps: preflight → quality gate (web typecheck/lint/unit/integration on a throwaway Postgres, connector
# test+build, signer tests, script checks) → images (OCI labels) → SBOM → scan → bundles → [push] →
# [sign] → checksums. Idempotent: everything is rebuilt into <version>.partial and swapped in at the end.
#
# Options
#   --skip-int                 skip the integration tests (no Postgres container)
#   --push <registry>          also tag + push images to <registry>/<name>:<version> (docker login first)
#   --allow-vulns              do not fail on CRITICAL vulnerabilities (they are still reported)
#   --allow-dirty              allow uncommitted changes (git trees only; recorded in the manifest)
#   --allow-version-skew       do not fail when the connector version differs from VERSION (NOT for prod)
#   --site-bundle auto|yes|no  site bundle: auto = only if installers/site + its inputs exist (default)
#   --site-args "<args>"       extra arguments for installers/site/build-site-bundle.sh (e.g. --agent-dir …)
#   --ci-install               run `npm ci` in both projects first (CI / clean machines)
#   --no-pull                  do not refresh base images (default: --pull for patched bases)
#   --out <dir>                output root (default release/out)
#
# Signing (optional): COSIGN_KEY=<path to cosign.key> [COSIGN_PASSWORD] [COSIGN_PUB=<cosign.pub>]
#   [COSIGN_TLOG=true to also upload to the public Rekor log]. Without COSIGN_KEY signing is skipped
#   with a warning (CI release.yml signs keyless instead).
# Site bundle signing: BUNDLE_SIGN_KEY=<Ed25519 PEM> (build-site-bundle.sh --sign-key); production web installs
#   refuse unsigned bundles. Without it the site bundle is built unsigned (warning).
# Source URL label: PATCHGATE_SOURCE_URL (default: none).
set -euo pipefail
# shellcheck source=release/lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
ROOT="$RELEASE_ROOT"
REPORT="node $ROOT/release/lib/report.mjs"

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

VERSION_ARG=""; SKIP_INT=0; PUSH=""; ALLOW_VULNS=0; ALLOW_DIRTY=0; ALLOW_SKEW=0
SITE_MODE=auto; SITE_ARGS=""; CI_INSTALL=0; PULL=1; OUT_ROOT="$ROOT/release/out"
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-int) SKIP_INT=1; shift ;;
    --push) PUSH="${2:?--push needs a registry}"; shift 2 ;;
    --allow-vulns) ALLOW_VULNS=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    --allow-version-skew) ALLOW_SKEW=1; shift ;;
    --site-bundle) SITE_MODE="${2:?}"; shift 2 ;;
    --site-args) SITE_ARGS="${2:-}"; shift 2 ;;
    --ci-install) CI_INSTALL=1; shift ;;
    --no-pull) PULL=0; shift ;;
    --out) OUT_ROOT="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option $1 (see --help)" ;;
    *) [ -z "$VERSION_ARG" ] || die "only one version argument"; VERSION_ARG="$1"; shift ;;
  esac
done
[ -n "$VERSION_ARG" ] || { usage; die "missing <version>"; }
case "$SITE_MODE" in auto|yes|no) ;; *) die "--site-bundle must be auto, yes or no" ;; esac
VERSION="${VERSION_ARG#v}"
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
[[ "$VERSION" =~ $SEMVER_RE ]] || die "version '$VERSION' is not semver (MAJOR.MINOR.PATCH[-prerelease])"
[ -z "$PUSH" ] || [[ "$PUSH" =~ ^[A-Za-z0-9.:-]+(/[A-Za-z0-9._-]+)*$ ]] || die "invalid registry '$PUSH'"

T0=$SECONDS
OUT="$OUT_ROOT/$VERSION"
STAGE="$OUT_ROOT/$VERSION.partial"
WORK="$ROOT/release/.work/$VERSION"
LOGS="$WORK/logs"
PG_CONTAINER=""
cleanup() {
  local rc=$?
  if [ -n "$PG_CONTAINER" ]; then docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true; fi
  rm -rf "$WORK/tar"
  if [ "$rc" -ne 0 ]; then printf '\n%sRELEASE FAILED%s (exit %s). Logs: %s\n' "$C_R" "$C_0" "$rc" "$LOGS" >&2; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# run <log-name> <description> <command...>: quiet on success, tail of the log on failure.
run() {
  local name="$1" desc="$2"; shift 2
  local log="$LOGS/$name.log" s=$SECONDS
  if "$@" >"$log" 2>&1 </dev/null; then
    ok "$desc ($((SECONDS - s))s)"
  else
    printf '    %sFAIL%s  %s — last lines of %s:\n' "$C_R" "$C_0" "$desc" "$log" >&2
    tail -n 40 "$log" | sed 's/^/      /' >&2
    return 1
  fi
}

# ================================================================== 1. preflight
step "Preflight — PatchGate $VERSION"
timer_start preflight
for t in docker node npm tar gzip sha256sum awk sed find; do command -v "$t" >/dev/null || die "$t is required"; done
docker info >/dev/null 2>&1 || die "Docker daemon not reachable"
rm -rf "$WORK"; mkdir -p "$LOGS" "$WORK/tar"
FILE_VERSION="$(tr -d ' \r\n' < "$ROOT/VERSION")"
[ "$FILE_VERSION" = "$VERSION" ] || die "VERSION file says '$FILE_VERSION', argument says '$VERSION' — bump VERSION first"
ok "VERSION file = $VERSION"
$REPORT changelog-has "$ROOT/CHANGELOG.md" "$VERSION" || die "CHANGELOG.md has no '## [$VERSION]' section"
ok "CHANGELOG.md has a $VERSION section"

# Connector: its version comes from patchgate-connector/package.json, injected by scripts/build.mjs into
# src/version.ts (__CONNECTOR_VERSION__). Both are owned by the connector — we only read and compare.
CONNECTOR_VERSION="$(node -e 'console.log(require(process.argv[1]).version)' "$ROOT/patchgate-connector/package.json")"
grep -q '__CONNECTOR_VERSION__' "$ROOT/patchgate-connector/src/version.ts" \
  || die "patchgate-connector/src/version.ts no longer reads the injected __CONNECTOR_VERSION__ — update release.sh"
VERSION_SKEW=0
if [ "$CONNECTOR_VERSION" != "$VERSION" ]; then
  [ "$ALLOW_SKEW" = 1 ] || die "connector version is '$CONNECTOR_VERSION' (patchgate-connector/package.json), VERSION is '$VERSION' — the connector owner must bump it (or pass --allow-version-skew for a test build)"
  VERSION_SKEW=1; warn "connector version $CONNECTOR_VERSION != $VERSION (--allow-version-skew: test build only)"
else
  ok "connector version = $VERSION"
fi
PROTOCOL_VERSION="$(sed -n 's/^export const PROTOCOL_VERSION = \([0-9][0-9]*\);.*/\1/p' "$ROOT/patchgate-web/src/lib/connector/protocol.ts")"
[ -n "$PROTOCOL_VERSION" ] || die "cannot read PROTOCOL_VERSION from patchgate-web/src/lib/connector/protocol.ts"
ok "connector protocol v$PROTOCOL_VERSION"

GIT_SHA=""; DIRTY=0
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ "$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" -ef "$ROOT" ]; then
  GIT_SHA="$(git -C "$ROOT" rev-parse HEAD)"
  nested="$(cd "$ROOT" && find . -mindepth 2 -name node_modules -prune -o -name .git -print | sed 's|^\./||')"
  [ -z "$nested" ] || die "nested git repositories would be committed as gitlinks (their files missing from the repo): $nested"
  if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
    [ "$ALLOW_DIRTY" = 1 ] || die "working tree is not clean (commit or stash, or --allow-dirty)"
    DIRTY=1; warn "working tree is dirty (--allow-dirty)"
  else
    ok "git tree clean at ${GIT_SHA:0:12}"
  fi
  tag="$(git -C "$ROOT" describe --exact-match --tags HEAD 2>/dev/null || true)"
  [ "$tag" = "v$VERSION" ] && ok "HEAD is tagged v$VERSION" || warn "HEAD is not tagged v$VERSION (tag: ${tag:-none})"
else
  warn "not a git repository: no clean-tree check, git sha unknown"
fi
CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Next.js deploymentId (= PATCHGATE_BUILD_ID) allows only [A-Za-z0-9_-]: encode "." as "_"
# (patchgate-web/src/lib/version.ts decodes it for /api/version and the UI label).
BUILD_ID="${VERSION//./_}"
ok "PATCHGATE_BUILD_ID = $BUILD_ID"
timer_stop preflight

# ================================================================== 2. quality gate
step "Quality gate"
timer_start gate
if [ "$CI_INSTALL" = 1 ] || [ ! -d "$ROOT/patchgate-web/node_modules" ]; then
  run web-npm-ci "web: npm ci" bash -c "cd '$ROOT/patchgate-web' && npm ci --no-audit --no-fund"
fi
if [ "$CI_INSTALL" = 1 ] || [ ! -d "$ROOT/patchgate-connector/node_modules" ]; then
  run connector-npm-ci "connector: npm ci" bash -c "cd '$ROOT/patchgate-connector' && npm ci --no-audit --no-fund"
fi
# PageProps / LayoutProps / RouteContext and next-env.d.ts are generated (git-ignored): a clean checkout
# needs `next typegen` before tsc.
run web-typegen   "web: next typegen" bash -c "cd '$ROOT/patchgate-web' && npx next typegen"
run web-typecheck "web: typecheck" bash -c "cd '$ROOT/patchgate-web' && npm run -s typecheck"
run web-lint      "web: lint"      bash -c "cd '$ROOT/patchgate-web' && npm run -s lint"
run web-unit      "web: unit tests" bash -c "cd '$ROOT/patchgate-web' && npm test"
grep -E 'Tests +[0-9]+' "$LOGS/web-unit.log" | tail -1 | sed 's/^/          /' || true

INTEGRATION="skipped"
if [ "$SKIP_INT" = 0 ]; then
  port="$(free_port)"; pw="$(rand_hex 24)"
  PG_CONTAINER="pg-release-it-$$-$port"
  dk run -d --rm --name "$PG_CONTAINER" -p "127.0.0.1:$port:5432" \
    -e POSTGRES_USER=patchgate -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=patchgate_test \
    --tmpfs /var/lib/postgresql/data:rw,size=1g "$POSTGRES_TEST_IMAGE" >/dev/null
  info "throwaway Postgres $PG_CONTAINER on 127.0.0.1:$port"
  # Ready = Postgres answers inside the container AND the published port answers from the host, twice in a
  # row (Docker Desktop's port forward can lag the container; the image's init restart can blip once).
  pg_ready() {
    docker exec "$PG_CONTAINER" pg_isready -q -h 127.0.0.1 -U patchgate -d patchgate_test 2>/dev/null \
      && node -e "const s=require('net').connect($port,'127.0.0.1',()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),2000)"
  }
  ok_in_row=0
  for _ in $(seq 1 90); do
    if pg_ready; then ok_in_row=$((ok_in_row + 1)); [ "$ok_in_row" -ge 2 ] && break; else ok_in_row=0; fi
    sleep 1
  done
  [ "$ok_in_row" -ge 2 ] || die "test Postgres did not become ready on 127.0.0.1:$port"
  export TEST_DATABASE_URL="postgresql://patchgate:$pw@127.0.0.1:$port/patchgate_test?schema=public"
  run web-migrate "web: prisma migrate deploy (test DB)" bash -c "cd '$ROOT/patchgate-web' && DATABASE_URL=\"\$TEST_DATABASE_URL\" npx prisma migrate deploy"
  run web-int     "web: integration tests" bash -c "cd '$ROOT/patchgate-web' && npm run -s test:int"
  grep -E 'Tests +[0-9]+' "$LOGS/web-int.log" | tail -1 | sed 's/^/          /' || true
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true; PG_CONTAINER=""; unset TEST_DATABASE_URL
  INTEGRATION="passed"
else
  warn "integration tests skipped (--skip-int)"
fi

run connector-test  "connector: protocol sync + tests" bash -c "cd '$ROOT/patchgate-connector' && npm test"
grep -E 'Tests +[0-9]+' "$LOGS/connector-test.log" | tail -1 | sed 's/^/          /' || true
run connector-build "connector: build bundle" bash -c "cd '$ROOT/patchgate-connector' && npm run -s build"
built="$(node "$ROOT/patchgate-connector/dist/patchgate-connector.mjs" version)"
[ "$built" = "$CONNECTOR_VERSION" ] || die "connector bundle reports '$built', expected '$CONNECTOR_VERSION'"
ok "connector bundle reports $built"
run signer-test "signer: unit tests (docker build --target test)" docker build --target test --progress=plain "$ROOT/deploy/signer"
run scripts "scripts: PowerShell parse + bash -n + shellcheck" bash "$ROOT/release/check-scripts.sh"
timer_stop gate

# ================================================================== 3. images
step "Images"
timer_start images
rm -rf "$STAGE"; mkdir -p "$STAGE"/{images,sbom,scans,bundles,.meta}
# name|context|target|extra build args
IMAGES=(
  "patchgate-web|patchgate-web|runner|--build-arg PATCHGATE_BUILD_ID=$BUILD_ID"
  "patchgate-tools|patchgate-web|tools|--build-arg PATCHGATE_BUILD_ID=$BUILD_ID"
  "patchgate-connector|patchgate-connector||"
  "patchgate-signer|deploy/signer|runtime|"
  "patchgate-egress-proxy|deploy/egress-proxy||"
  "patchgate-backup|deploy/backup||"
)
PULL_FLAG=(); [ "$PULL" = 1 ] && PULL_FLAG=(--pull)
for spec in "${IMAGES[@]}"; do
  IFS='|' read -r name ctx target extra <<<"$spec"
  ref="$name:$VERSION"
  args=(build "${PULL_FLAG[@]}" --progress=plain -t "$ref"
    --label "org.opencontainers.image.title=$name"
    --label "org.opencontainers.image.version=$VERSION"
    --label "org.opencontainers.image.created=$CREATED"
    --label "org.opencontainers.image.vendor=Dataspace"
    --label "org.opencontainers.image.revision=${GIT_SHA:-unknown}"
    --label "org.opencontainers.image.description=PatchGate $name $VERSION")
  [ -z "${PATCHGATE_SOURCE_URL:-}" ] || args+=(--label "org.opencontainers.image.source=$PATCHGATE_SOURCE_URL")
  [ -z "$target" ] || args+=(--target "$target")
  # shellcheck disable=SC2206 # intentional word splitting of fixed build args
  [ -z "$extra" ] || args+=($extra)
  run "build-$name" "build $ref" docker "${args[@]}" "$ROOT/$ctx"
done
timer_stop images

# ================================================================== 4. save + SBOM + scan
step "Save, SBOM (syft, CycloneDX) and vulnerability scan (grype)"
timer_start sbom_scan
dk pull -q "$SYFT_IMAGE" >/dev/null && dk pull -q "$GRYPE_IMAGE" >/dev/null || die "cannot pull $SYFT_IMAGE / $GRYPE_IMAGE"
tool_digest() { docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' "$1"; }
CRITICAL_TOTAL=0
: > "$STAGE/.meta/images.tsv"
for spec in "${IMAGES[@]}"; do
  IFS='|' read -r name _ _ _ <<<"$spec"
  ref="$name:$VERSION"; base="$name-$VERSION"
  id="$(docker image inspect --format '{{.Id}}' "$ref")"; size="$(docker image inspect --format '{{.Size}}' "$ref")"
  docker save -o "$WORK/tar/$base.tar" "$ref"
  dk run --rm -v "$(hostpath "$WORK/tar"):/in:ro" "$SYFT_IMAGE" -q "docker-archive:/in/$base.tar" -o cyclonedx-json \
    > "$STAGE/sbom/$base.cdx.json" 2>"$LOGS/sbom-$name.log" || { tail -n 20 "$LOGS/sbom-$name.log" >&2; die "syft failed for $ref"; }
  components="$($REPORT sbom-count "$STAGE/sbom/$base.cdx.json")"
  dk run --rm -v patchgate-grype-db:/cache -e GRYPE_DB_CACHE_DIR=/cache -v "$(hostpath "$STAGE/sbom"):/sbom:ro" \
    "$GRYPE_IMAGE" -q "sbom:/sbom/$base.cdx.json" -o json > "$STAGE/scans/$base.grype.json" 2>"$LOGS/scan-$name.log" \
    || { tail -n 20 "$LOGS/scan-$name.log" >&2; die "grype failed for $ref"; }
  summary="$($REPORT vuln-summary "$STAGE/scans/$base.grype.json" "$STAGE/scans/$base.summary.json")"
  crit="$(node -e 'console.log(require(process.argv[1]).counts.Critical)' "$STAGE/scans/$base.summary.json")"
  CRITICAL_TOTAL=$((CRITICAL_TOTAL + crit))
  gzip -1 -c "$WORK/tar/$base.tar" > "$STAGE/images/$base.tar.gz"; rm -f "$WORK/tar/$base.tar"
  asize="$(wc -c < "$STAGE/images/$base.tar.gz" | tr -d ' ')"
  printf '%s\t%s\t%s\t%s\t%s\t\t%s\n' "$name" "$ref" "$id" "$size" "images/$base.tar.gz" "$asize" >> "$STAGE/.meta/images.tsv"
  info "$ref  image $((size / 1024 / 1024)) MiB, archive $((asize / 1024 / 1024)) MiB  sbom=$components  $(printf '%s\n' "$summary" | head -1)"
  printf '%s\n' "$summary" | tail -n +2
done
if [ "$CRITICAL_TOTAL" -gt 0 ]; then
  if [ "$ALLOW_VULNS" = 1 ]; then warn "$CRITICAL_TOTAL CRITICAL vulnerabilities (--allow-vulns)"
  else die "$CRITICAL_TOTAL CRITICAL vulnerabilities — fix (rebuild with patched bases / bump deps) or --allow-vulns. Reports: $STAGE/scans"; fi
else
  ok "no CRITICAL vulnerabilities"
fi
timer_stop sbom_scan

# ================================================================== 5. bundles
step "Bundles"
timer_start bundles
CB="patchgate-connector-$VERSION"
mkdir -p "$WORK/$CB/deploy"
cp "$ROOT/patchgate-connector/dist/patchgate-connector.mjs" "$WORK/$CB/"
cp "$ROOT/patchgate-connector/README.md" "$ROOT/patchgate-connector/config.example.json" "$ROOT/patchgate-connector/docker-compose.example.yml" "$WORK/$CB/"
cp "$ROOT/patchgate-connector/deploy/"* "$WORK/$CB/deploy/"
printf '%s\n' "$CONNECTOR_VERSION" > "$WORK/$CB/VERSION"
tar -C "$WORK" --owner=0 --group=0 --numeric-owner --mtime="$CREATED" --sort=name -czf "$STAGE/bundles/$CB.tar.gz" "$CB"
cp "$ROOT/patchgate-connector/dist/patchgate-connector.mjs" "$STAGE/bundles/$CB.mjs"
ok "bundles/$CB.tar.gz (+ $CB.mjs)"

SITE="skipped"
SITE_BUILDER="$ROOT/installers/site/build-site-bundle.sh"
site_ready() {
  [ -f "$SITE_BUILDER" ] || { echo "installers/site/build-site-bundle.sh not present (installers not finished)"; return 1; }
  [ -n "$SITE_ARGS" ] && return 0     # caller supplies the inputs explicitly
  local agent_dir="$ROOT/lab/patchgate/repo-data/tactical/agent/2.11.0" compose="$ROOT/../tacticalrmm/docker/docker-compose.yml"
  [ -d "$agent_dir" ] || { echo "no Tactical agent installers at ${agent_dir#"$ROOT"/} (pass --site-args \"--agent-dir … --agent-sha256 …\")"; return 1; }
  [ -f "$compose" ] || { echo "Tactical compose file not found at ../tacticalrmm/docker/docker-compose.yml (pass --site-args \"--tactical-compose …\")"; return 1; }
  docker image inspect tacticalrmm/tactical:latest >/dev/null 2>&1 || { echo "Tactical images not present locally (pass --site-args \"--pull\")"; return 1; }
}
if [ "$SITE_MODE" = no ]; then
  info "site bundle: skipped (--site-bundle no)"
elif reason="$(site_ready)"; then
  SIGN_ARGS=()
  if [ -n "${BUNDLE_SIGN_KEY:-}" ]; then SIGN_ARGS=(--sign-key "$BUNDLE_SIGN_KEY"); else warn "site bundle UNSIGNED (set BUNDLE_SIGN_KEY): production web installs will refuse it"; fi
  # shellcheck disable=SC2086 # SITE_ARGS is a caller-supplied argument list
  run site-bundle "site bundle (installers/site/build-site-bundle.sh)" \
    bash "$SITE_BUILDER" --version "$VERSION" --out "$WORK/site" --connector-image "patchgate-connector:$VERSION" "${SIGN_ARGS[@]}" $SITE_ARGS
  cp "$WORK/site/"patchgate-site-"$VERSION"*.tar.gz "$STAGE/bundles/"
  for f in SHA256SUMS SHA256SUMS.sig bundle-signing.pub.txt install-site.sh; do if [ -f "$WORK/site/$f" ]; then cp "$WORK/site/$f" "$STAGE/bundles/site-$f"; fi; done
  SITE="built"
else
  [ "$SITE_MODE" = yes ] && die "site bundle requested but not buildable: $reason"
  warn "site bundle SKIPPED: $reason"
fi
timer_stop bundles

# ================================================================== 6. push (optional)
if [ -n "$PUSH" ]; then
  step "Push to $PUSH"
  timer_start push
  : > "$STAGE/.meta/images.tsv.new"
  while IFS=$'\t' read -r name ref id size file _ asize; do
    remote="$PUSH/$ref"
    docker tag "$ref" "$remote"
    run "push-$name" "push $remote" docker push "$remote"
    digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$remote" | grep -m1 "^$PUSH/$name@" || true)"
    [ -n "$digest" ] || die "no registry digest for $remote after push"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$ref" "$id" "$size" "$file" "$digest" "$asize" >> "$STAGE/.meta/images.tsv.new"
    info "$digest"
  done < "$STAGE/.meta/images.tsv"
  mv "$STAGE/.meta/images.tsv.new" "$STAGE/.meta/images.tsv"
  timer_stop push
fi

# ================================================================== 7. notes, manifest, checksums, signing
step "Release notes, manifest, checksums, signing"
timer_start finalize
SIGNING="none"
if [ -n "${COSIGN_KEY:-}" ]; then
  if [ -n "$PUSH" ]; then SIGNING="cosign key (SHA256SUMS.sig + pushed images)"; else SIGNING="cosign key (SHA256SUMS.sig)"; fi
fi
{
  printf 'VERSION=%s\nGIT_SHA=%s\nCREATED=%s\nCONNECTOR_VERSION=%s\nPROTOCOL_VERSION=%s\n' "$VERSION" "$GIT_SHA" "$CREATED" "$CONNECTOR_VERSION" "$PROTOCOL_VERSION"
  printf 'INTEGRATION=%s\nVERSION_SKEW=%s\nDIRTY=%s\nSITE_BUNDLE=%s\nSIGNING=%s\n' "$INTEGRATION" "$VERSION_SKEW" "$DIRTY" "$SITE" "$SIGNING"
  printf 'ALLOW_VULNS=%s\nCRITICAL_TOTAL=%s\n' "$ALLOW_VULNS" "$CRITICAL_TOTAL"
  printf 'TOOL_SYFT=%s\nTOOL_GRYPE=%s\nTOOL_POSTGRES_TEST=%s\n' "$(tool_digest "$SYFT_IMAGE")" "$(tool_digest "$GRYPE_IMAGE")" "$POSTGRES_TEST_IMAGE"
} > "$STAGE/.meta/release.env"
timer_stop finalize
for t in "${TIMINGS[@]}"; do printf '%s\t%s\n' "${t%%=*}" "${t#*=}"; done > "$STAGE/.meta/timings.tsv"
$REPORT manifest "$STAGE"
$REPORT notes "$ROOT/CHANGELOG.md" "$VERSION" "$STAGE" > "$STAGE/release-notes.md"
rm -rf "$STAGE/.meta"
(cd "$STAGE" && find . -type f ! -name 'SHA256SUMS*' | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
ok "SHA256SUMS ($(wc -l < "$STAGE/SHA256SUMS" | tr -d ' ') files)"

if [ -n "${COSIGN_KEY:-}" ]; then
  [ -f "$COSIGN_KEY" ] || die "COSIGN_KEY=$COSIGN_KEY not found"
  keydir="$(cd "$(dirname "$COSIGN_KEY")" && pwd)"; keyfile="$(basename "$COSIGN_KEY")"
  tlog="${COSIGN_TLOG:-false}"
  cosign() { dk run --rm -e COSIGN_PASSWORD -v "$(hostpath "$keydir"):/keys:ro" -v "$(hostpath "$STAGE"):/work" "$@"; }
  cosign "$COSIGN_IMAGE" sign-blob --yes --key "/keys/$keyfile" --tlog-upload="$tlog" \
    --output-signature /work/SHA256SUMS.sig /work/SHA256SUMS >"$LOGS/cosign-blob.log" 2>&1 \
    || { tail -n 20 "$LOGS/cosign-blob.log" >&2; die "cosign sign-blob failed"; }
  ok "SHA256SUMS.sig (cosign, tlog upload: $tlog)"
  [ -z "${COSIGN_PUB:-}" ] || { cp "$COSIGN_PUB" "$STAGE/cosign.pub"; ok "cosign.pub included"; }
  if [ -n "$PUSH" ]; then
    while IFS= read -r digest; do
      dk run --rm -e COSIGN_PASSWORD -v "$(hostpath "$keydir"):/keys:ro" -v "$(hostpath "$HOME/.docker"):/root/.docker:ro" \
        "$COSIGN_IMAGE" sign --yes --key "/keys/$keyfile" --tlog-upload="$tlog" "$digest" >>"$LOGS/cosign-images.log" 2>&1 \
        || { tail -n 20 "$LOGS/cosign-images.log" >&2; die "cosign sign failed for $digest"; }
      ok "signed $digest"
    done < <(node -e 'for (const i of require(process.argv[1]).images) if (i.pushed) console.log(i.pushed)' "$STAGE/manifest.json")
  fi
else
  warn "signing skipped: COSIGN_KEY not set (CI release.yml signs keyless)"
fi

rm -rf "$OUT"; mv "$STAGE" "$OUT"
rm -rf "$WORK/$CB" "$WORK/site"

# ================================================================== summary
step "Release $VERSION ready: ${OUT#"$ROOT"/}"
node -e '
const m = require(process.argv[1]);
const mib = (b) => (b / 1048576).toFixed(0).padStart(6) + " MiB";
console.log("    image                                 image     archive    sbom   crit  high   med");
for (const i of m.images) {
  const v = i.vulnerabilities || {};
  console.log("    " + i.ref.padEnd(34) + mib(i.sizeBytes) + " " + mib(i.archiveBytes || 0) + String(i.sbom ? i.sbom.components : "-").padStart(7) +
    String(v.Critical ?? "-").padStart(7) + String(v.High ?? "-").padStart(6) + String(v.Medium ?? "-").padStart(6));
}
console.log("    bundles: " + (m.bundles.join(", ") || "none"));
console.log("    timings: " + m.timings.map((t) => t.step + " " + t.seconds + "s").join(" · "));
console.log("    integration: " + m.qualityGate.integration + " · signing: " + m.signing + " · git: " + (m.gitSha || "n/a"));
' "$OUT/manifest.json"
info "total $((SECONDS - T0))s"
