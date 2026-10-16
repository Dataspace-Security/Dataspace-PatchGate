#!/usr/bin/env bash
# PatchGate — test install FROM GITHUB on your own PC, with ONE script (TEST SETUP ONLY).
#
#   ./install-patchgate-test.sh                 clone (or update) the repo, build PatchGate from source, install the
#                                               whole system in Docker (server + bank site with Tactical from Docker Hub)
#   ./install-patchgate-test.sh --reinstall     erase ONLY the test install (asks first; --yes skips) and do it again
#   ./install-patchgate-test.sh --status        is it running? connector healthy?
#   ./install-patchgate-test.sh --cleanup       erase ONLY the test install (containers/network/volumes with the kit label)
# Options: --ref <branch|tag|sha> (default main)  --dir <folder> (default ~/patchgate-test)  --rebuild (force image builds)
#          --repo <owner/name> (default Dataspace-Security/Dataspace-PatchGate)
#          --kit-from <kits/colleague-test folder>  (developers: use local, not yet pushed kit scripts with the clone)
#
# Needs: Git (Git Bash on Windows), Docker (Docker Desktop with WSL2 on Windows), 16 GB RAM, 30 GB free disk, internet.
# GitHub access: none for a public repo; for a private one the GitHub CLI if you are signed in (`gh auth login`), otherwise a read-only
# fine-grained token (Repository access: this repo; Permissions: Contents = Read). The token is asked for without
# echo, kept only in this process's memory, handed to git through a temporary askpass helper that holds no
# secret, never written to disk, never put into the remote URL or the logs, and unset afterwards.
#
# What it reuses from the clone (no logic is duplicated here): kits/colleague-test/{lib/build-online-bundle.sh,
# build-kit.sh,test-on-my-pc.sh} — the same all-in-Docker install as the offline test kit (START-HERE.md).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

REPO_SLUG="Dataspace-Security/Dataspace-PatchGate"
REF="main"
BASE="${PATCHGATE_TEST_DIR:-$HOME/patchgate-test}"
REBUILD=0
KIT_FROM=""
PASS=()
MODE=install
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:?--ref needs a value}"; shift 2 ;;
    --dir) BASE="${2:?--dir needs a value}"; shift 2 ;;
    --repo) REPO_SLUG="${2:?--repo needs a value}"; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    --kit-from) KIT_FROM="${2:?--kit-from needs a folder}"; shift 2 ;;   # developers: test unpushed kit changes
    --reinstall|--fresh) MODE=install; PASS+=(--reinstall); shift ;;
    --status|--cleanup) MODE=passthrough; PASS+=("$1"); shift ;;
    --code|--totp) echo "$1 was removed: sign-in is password-only (see logins.txt)"; exit 2 ;;
    --yes|-y|--resume) PASS+=("$1"); shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "unknown option $1 (see --help)"; exit 2 ;;
  esac
done
[[ "$REF" =~ ^[A-Za-z0-9._/-]{1,100}$ ]] || { echo "invalid --ref"; exit 2; }
[[ "$REPO_SLUG" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || { echo "invalid --repo"; exit 2; }
CLONE="$BASE/$(basename "$REPO_SLUG")"
LOGS="$BASE/logs"; mkdir -p "$LOGS"

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B=""; G=""; Y=""; R=""; N=""; fi
PHASES=(); T0=0; PNAME=""
phase() { end_phase; PNAME="$1"; T0=$(date +%s); printf '\n%s==> %s%s   (%s)\n' "$B" "$1" "$N" "$(date +%H:%M:%S)"; }
end_phase() { [ "$T0" -gt 0 ] || return 0; local s=$(( $(date +%s) - T0 )); PHASES+=("$(printf '%-44s %3dm%02ds' "$PNAME" $((s / 60)) $((s % 60)))"); T0=0; }
ok()   { printf '    %sOK%s   %s\n' "$G" "$N" "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    %sWARN%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%sFAILED%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

latest_kit() { ls -dt "$CLONE"/kits/colleague-test/out/PatchGate-*-test-kit 2>/dev/null | head -1 || true; }

# ------------------------------------------------------------------ --status / --cleanup: use the built kit
if [ "$MODE" = passthrough ]; then
  KIT="$(latest_kit)"
  [ -n "$KIT" ] && [ -f "$KIT/test-on-my-pc.sh" ] || die "no test install built from $CLONE yet (run without options first)"
  exec bash "$KIT/test-on-my-pc.sh" "${PASS[@]}"
fi

LOG_FILE="$LOGS/install-patchgate-test-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
RUN0=$(date +%s)
echo "PatchGate test install from GitHub ($REPO_SLUG @ $REF) — $(date '+%Y-%m-%d %H:%M:%S') — log $LOG_FILE"
echo "TEST SETUP ONLY: everything runs in Docker on this PC (docs/TEAM-GUIDE.md describes a real bank installation)."

# ------------------------------------------------------------------ 1. preflight
phase "1. Preflight"
for t in git docker curl tar gzip sha256sum awk sed; do command -v "$t" >/dev/null 2>&1 || die "$t is required (Windows: Git for Windows + Docker Desktop)"; done
docker info >/dev/null 2>&1 || die "Docker is not running (start Docker Desktop and wait for 'Engine running')"
mem_gb=$(( $(docker info --format '{{.MemTotal}}') / 1024 / 1024 / 1024 ))
[ "$mem_gb" -ge 11 ] || die "Docker can use only ${mem_gb} GB RAM; 12 GB minimum (16 GB recommended): Docker Desktop -> Settings -> Resources"
ok "git $(git --version | awk '{print $3}'), Docker $(docker version --format '{{.Server.Version}}'), ${mem_gb} GB RAM for Docker"
# The Dockerfiles need BuildKit (heredocs, COPY --chmod). Docker Desktop has it; Ubuntu's docker.io package
# ships without the buildx plugin, so install it there (docker-ce -> docker-buildx-plugin, docker.io -> docker-buildx).
export DOCKER_BUILDKIT=1
if ! docker buildx version >/dev/null 2>&1; then
  if [ "$(id -u)" = 0 ] && command -v apt-get >/dev/null 2>&1; then
    pkg=docker-buildx; dpkg -s docker-ce >/dev/null 2>&1 && pkg=docker-buildx-plugin
    echo "    Docker BuildKit (buildx) missing: installing $pkg"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null 2>&1 \
      || { apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null 2>&1; } \
      || die "could not install $pkg — install Docker's buildx plugin, then re-run"
  fi
  docker buildx version >/dev/null 2>&1 || die "Docker BuildKit (buildx plugin) is required: Ubuntu/Debian 'apt install docker-buildx' (docker.io) or 'docker-buildx-plugin' (docker-ce); Docker Desktop has it"
fi
ok "Docker BuildKit $(docker buildx version 2>/dev/null | awk '{print $2}')"
mkdir -p "$BASE"
free_gb="$(df -Pk "$BASE" | awk 'NR==2 {printf "%d", $4/1024/1024}')"
[ "${free_gb:-0}" -ge 10 ] || die "only ${free_gb} GB free in $BASE (the clone + image archives need about 10 GB, Docker another 20 GB)"
ok "$free_gb GB free in $BASE"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://github.com/ || true)"
[ "$code" = 200 ] || die "github.com not reachable (HTTP ${code:-none}): proxy/firewall?"
ok "github.com reachable"

# ------------------------------------------------------------------ 2. clone / update (public or private repo)
phase "2. Source: $REPO_SLUG @ $REF"
GIT_AUTH=()
ASKPASS=""
cleanup_auth() { [ -n "$ASKPASS" ] && rm -f "$ASKPASS"; unset PG_GH_TOKEN 2>/dev/null || true; }
trap cleanup_auth EXIT
if GIT_TERMINAL_PROMPT=0 git -c credential.helper= ls-remote --quiet "https://github.com/$REPO_SLUG.git" HEAD >/dev/null 2>&1; then
  # Public repository: no sign-in, no token.
  GIT_AUTH=(-c credential.helper=)
  export GIT_TERMINAL_PROMPT=0
  ok "GitHub access: public repository (no sign-in needed)"
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  # Git asks the GitHub CLI for credentials (its own secure store); nothing is copied anywhere.
  GIT_AUTH=(-c credential.helper= -c 'credential.helper=!gh auth git-credential')
  ok "GitHub access: GitHub CLI ($(gh api user --jq .login 2>/dev/null || echo signed-in))"
else
  [ -t 0 ] || die "GitHub CLI not signed in and no terminal to ask for a token: run 'gh auth login' first"
  echo "    GitHub CLI not signed in. Paste a READ-ONLY fine-grained token (Contents: Read on $REPO_SLUG)."
  printf '    Token (not shown): '; IFS= read -rs PG_GH_TOKEN; echo
  [ -n "$PG_GH_TOKEN" ] || die "no token given"
  export PG_GH_TOKEN
  # The helper holds no secret: it prints the token from this process's environment when git asks.
  ASKPASS="$(mktemp "${TMPDIR:-/tmp}/pg-askpass.XXXXXX")"
  printf '#!/bin/sh\ncase "$1" in Username*) echo x-access-token ;; *) printf "%%s\\n" "$PG_GH_TOKEN" ;; esac\n' > "$ASKPASS"
  chmod 0700 "$ASKPASS"
  export GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0
  GIT_AUTH=(-c credential.helper=)
  ok "GitHub access: token (memory only)"
fi
URL="https://github.com/$REPO_SLUG.git"
if [ -d "$CLONE/.git" ]; then
  git "${GIT_AUTH[@]}" -C "$CLONE" fetch --quiet --tags --prune origin || die "git fetch failed (access to $REPO_SLUG?)"
  ok "updated existing clone $CLONE"
else
  git "${GIT_AUTH[@]}" clone --quiet "$URL" "$CLONE" || die "git clone failed (access to $REPO_SLUG? token needs Contents: Read)"
  ok "cloned into $CLONE"
fi
if git -C "$CLONE" rev-parse --verify --quiet "origin/$REF^{commit}" >/dev/null; then target="origin/$REF"
elif git -C "$CLONE" rev-parse --verify --quiet "$REF^{commit}" >/dev/null; then target="$REF"
else die "ref $REF not found in $REPO_SLUG"; fi
git -C "$CLONE" -c advice.detachedHead=false checkout --quiet --force --detach "$target"
cleanup_auth; trap - EXIT
SHA="$(git -C "$CLONE" rev-parse --short=7 HEAD)"
BASEV="$(tr -d '\r\n' < "$CLONE/VERSION")"
KV="$BASEV-g$SHA"                       # image tag + kit version, e.g. 1.0.0-rc3-g1a2b3c4
BUILD_ID="${KV//./_}"                   # Next.js deploymentId: [A-Za-z0-9_-] only
ok "checked out $target = $SHA ($(git -C "$CLONE" log -1 --format='%cd, %s' --date=short | cut -c1-80))"
ok "version $KV"
KITSRC="$CLONE/kits/colleague-test"
if [ -n "$KIT_FROM" ]; then
  # Developer option: the product comes from the clone, the kit scripts from a local folder (unpushed changes).
  [ -f "$KIT_FROM/test-on-my-pc.sh" ] || die "--kit-from $KIT_FROM is not a kits/colleague-test folder"
  mkdir -p "$KITSRC/lib"
  cp "$KIT_FROM"/*.sh "$KIT_FROM"/*.md "$KITSRC/"; cp "$KIT_FROM"/lib/* "$KITSRC/lib/"
  warn "kit scripts taken from $KIT_FROM (--kit-from), product from $SHA"
fi
for f in test-on-my-pc.sh build-kit.sh lib/build-online-bundle.sh; do
  [ -f "$KITSRC/$f" ] || die "$REF has no kits/colleague-test/$f (this branch predates the test kit)"
done

# ------------------------------------------------------------------ 3. images from source
phase "3. Build PatchGate images from source (no prebuilt images)"
cd "$CLONE"
IMAGES=(
  "patchgate-web|patchgate-web|runner|--build-arg PATCHGATE_BUILD_ID=$BUILD_ID"
  "patchgate-tools|patchgate-web|tools|--build-arg PATCHGATE_BUILD_ID=$BUILD_ID"
  "patchgate-connector|patchgate-connector||"
  "patchgate-signer|deploy/signer|runtime|"
  "patchgate-egress-proxy|deploy/egress-proxy||"
  "patchgate-backup|deploy/backup||"
)
for spec in "${IMAGES[@]}"; do
  IFS='|' read -r name ctx target extra <<<"$spec"
  ref="$name:$KV"
  if [ "$REBUILD" = 0 ] && docker image inspect "$ref" >/dev/null 2>&1; then ok "$ref (already built)"; continue; fi
  args=(build -q -t "$ref" --label "org.opencontainers.image.version=$KV" --label "org.opencontainers.image.revision=$SHA")
  [ -z "$target" ] || args+=(--target "$target")
  # shellcheck disable=SC2206 # fixed build args
  [ -z "$extra" ] || args+=($extra)
  t=$(date +%s)
  docker "${args[@]}" "$(hostpath "$CLONE/$ctx")" > "$LOGS/build-$name.log" 2>&1 || { tail -30 "$LOGS/build-$name.log"; die "docker build $ref failed (log $LOGS/build-$name.log)"; }
  ok "$ref built ($(( $(date +%s) - t ))s)"
done

# ------------------------------------------------------------------ 4. site bundle + release-like folder + kit
phase "4. Online site bundle, image archives, test kit"
REL="$CLONE/release/out/$KV"
if [ "$REBUILD" = 0 ] && [ -s "$REL/SHA256SUMS" ] && (cd "$REL" && sha256sum --quiet --strict -c SHA256SUMS) 2>/dev/null; then
  ok "release folder $REL already complete"
else
  rm -rf "$REL"; mkdir -p "$REL/images" "$REL/bundles" "$REL/.site"
  bash "$KITSRC/lib/build-online-bundle.sh" --repo "$CLONE" --version "$KV" --connector-image "patchgate-connector:$KV" --out "$REL/.site"
  cp "$REL/.site/patchgate-site-$KV-online.tar.gz" "$REL/bundles/"
  cp "$REL/.site/SHA256SUMS" "$REL/bundles/site-SHA256SUMS"
  cp "$REL/.site/install-site.sh" "$REL/bundles/site-install-site.sh"
  rm -rf "$REL/.site"
  for spec in "${IMAGES[@]}"; do
    name="${spec%%|*}"
    docker save "$name:$KV" | gzip -1 > "$REL/images/$name-$KV.tar.gz"
    info "images/$name-$KV.tar.gz ($(du -h "$REL/images/$name-$KV.tar.gz" | cut -f1))"
  done
  (cd "$REL" && find images bundles -type f | LC_ALL=C sort | xargs -d '\n' sha256sum > SHA256SUMS)
  ok "release-like folder $REL (built from $SHA, not signed: test only)"
fi
bash "$KITSRC/build-kit.sh" "$KV" | sed 's/^/    /'
KIT="$KITSRC/out/PatchGate-$KV-test-kit"
[ -f "$KIT/test-on-my-pc.sh" ] || die "kit not built"
end_phase

# ------------------------------------------------------------------ 5. the all-in-Docker install (same as the offline kit)
phase "5. Install (kits/colleague-test/test-on-my-pc.sh ${PASS[*]:-})"
rc=0
bash "$KIT/test-on-my-pc.sh" "${PASS[@]}" || rc=$?
end_phase
echo
echo "${B}Time per phase${N}"
for p in "${PHASES[@]}"; do echo "    $p"; done
tot=$(( $(date +%s) - RUN0 )); echo "    total: $((tot / 60))m$((tot % 60))s"
echo "    kit folder: $KIT   (logins.txt, logs/, patchgate-test-ca.pem)"
echo "    later:  $0 --status | --reinstall | --cleanup"
exit "$rc"
