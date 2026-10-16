#!/usr/bin/env bash
# Shared helpers for release/*.sh (sourced, not executed). Works on Linux CI runners and Git Bash on Windows.
# shellcheck shell=bash

RELEASE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export RELEASE_ROOT

# Pinned tool images (override via env). Record of the digest actually used goes into manifest.json.
SHELLCHECK_IMAGE="${SHELLCHECK_IMAGE:-koalaman/shellcheck:stable}"
POWERSHELL_IMAGE="${POWERSHELL_IMAGE:-mcr.microsoft.com/powershell:lts-alpine-3.20}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:latest}"
GRYPE_IMAGE="${GRYPE_IMAGE:-anchore/grype:latest}"
COSIGN_IMAGE="${COSIGN_IMAGE:-gcr.io/projectsigstore/cosign:v2.4.1}"
POSTGRES_TEST_IMAGE="${POSTGRES_TEST_IMAGE:-postgres:16-alpine}"
ACTIONLINT_IMAGE="${ACTIONLINT_IMAGE:-rhysd/actionlint:latest}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_B=$'\033[1m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_0=$'\033[0m'
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_0=""
fi
step() { printf '\n%s==> %s%s\n' "$C_B" "$*" "$C_0"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %sok%s    %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '    %sWARN%s  %s\n' "$C_Y" "$C_0" "$*" >&2; }
die()  { printf '%sERROR%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

# Host path for `docker run -v` (Docker Desktop on Windows needs a Windows path; Git Bash must not rewrite it).
hostpath() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}
# docker without MSYS path mangling of container-side paths like /work.
dk() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker "$@"; }

# A free TCP port on 127.0.0.1 (asks the OS; the tiny race is acceptable for a throwaway container).
free_port() {
  node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})'
}

# Random hex (for throwaway credentials; never printed).
rand_hex() { node -e "console.log(require('crypto').randomBytes(${1:-24}).toString('hex'))"; }

# Repo-relative list of shell / PowerShell scripts that ship or run in CI (generated + dependency dirs excluded).
list_scripts() { # sh|ps1
  (cd "$RELEASE_ROOT" && find deploy installers lab release patchgate-web/scripts patchgate-connector/scripts \
      \( -name node_modules -o -name generated -o -name out -o -name dist \) -prune -o -type f -name "*.$1" -print 2>/dev/null \
    | sed 's|^\./||' | sort)
}

# Elapsed-time bookkeeping: timer_start <name>; ...; timer_stop <name>
declare -a TIMINGS=()
timer_start() { eval "T_$1=$SECONDS"; }
timer_stop() { local s; eval "s=\${T_$1:-$SECONDS}"; TIMINGS+=("$1=$((SECONDS - s))"); }
