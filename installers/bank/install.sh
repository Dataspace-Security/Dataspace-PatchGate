#!/usr/bin/env bash
# PatchGate ALL-IN-ONE bank server: PatchGate + official Tactical RMM + MeshCentral + PatchGate connector +
# package cache on ONE Linux server inside the bank. Only PatchGate's fetcher reaches the internet.
#
#   curl -fsSL https://raw.githubusercontent.com/Dataspace-Security/Dataspace-PatchGate/main/installers/bank/install.sh \
#     | sudo bash -s -- --domain bank.local
#
#   sudo ./install.sh --domain bank.local [--bank-name "Bank"] ...   first install, or safe re-run / resume
#   sudo ./install.sh --status                                       health of both parts + egress lockdown
#   sudo ./install.sh --upgrade [--ref <branch|tag|sha>]             new source -> rebuild -> backup -> migrate ->
#                                                                    rolling restart (PatchGate, then the site)
#   sudo ./install.sh --uninstall [--purge]                          keeps all data unless --purge (asks)
#
# Names (bank DNS -> this server's LAN IP): patchgate.<domain> (PatchGate), rmm./api./mesh.<domain> (Tactical),
# pg-cache.<domain> (package cache for the PCs). One IP, port 443 shared by a small SNI router (pg-bank-edge).
# What it does: preflight -> source (clone of the public repo, or --source-dir) -> bank TLS (your certificate or a
# bank CA made here) -> Microsoft code-signing roots (pinned) -> installers/server/install-patchgate.sh (images
# built from source, nginx on 127.0.0.1:8444) -> bank + accounts (2 ADMINs: maker + checker, optional AUDITOR)
# -> installers/site/install-site.sh --online (Tactical from Docker Hub, digest-pinned; bound to 127.0.0.2) ->
# SNI router -> connector allow-list + enrolment (fingerprint pinned automatically) -> host egress lockdown
# (DOCKER-USER: only the fetcher's egress proxy may leave) -> self-check -> summary.
# Log: /var/log/patchgate-bank-install.log (no secrets). Logins: /opt/patchgate-bank/logins.txt (root, 0600).
set -euo pipefail
umask 027

BANK_INSTALLER_VERSION="1.0.0"
REPO_SLUG="${PG_BANK_REPO:-Dataspace-Security/Dataspace-PatchGate}"
REF="${PG_BANK_REF:-main}"
BANK_DIR="${PG_BANK_DIR:-/opt/patchgate-bank}"
LOG_FILE="${PG_BANK_LOG:-/var/log/patchgate-bank-install.log}"
SITE_DIR=/opt/patchgate-site
PG_INSTALL_DIR=/opt/patchgate
DEPLOY="$PG_INSTALL_DIR/deploy"
EDGE_NAME=pg-bank-edge
# Official nginx image (stream + ssl_preread), pinned by digest (nginx:1.28-alpine).
EDGE_IMAGE="nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236"
PG_HTTPS_LOCAL="127.0.0.1:8444"   # PatchGate nginx (HTTPS) behind the router
PG_HTTP_LOCAL="127.0.0.1:8080"    # PatchGate nginx (HTTP -> HTTPS redirect)
SITE_BIND="127.0.0.2"             # Tactical / cache ingress (install-site.sh --bind-ip)
HOSTS_MARK="# patchgate-bank"
FW_CHAIN="PG-BANK-EGRESS"
# Microsoft code-signing roots (RUNBOOK §4.4), DER from microsoft.com, SHA-256 of the DER pinned. Fails closed.
MS_ROOTS=(
  "http://www.microsoft.com/pki/certs/MicRooCerAut2011_2011_03_22.crt 847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61 microsoft-root-2011.pem"
  "http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e microsoft-root-2010.pem"
)

# ------------------------------------------------------------------ settings (flags > state > defaults)
MODE=install
NONINTERACTIVE="${PG_NONINTERACTIVE:-0}"
ASSUME_YES=0
PURGE=0
SOURCE_DIR="${PG_BANK_SOURCE_DIR:-}"
MANAGED_CLONE="${PG_BANK_MANAGED:-0}"
REF_GIVEN=0
DOMAIN=""
BANK_NAME=""
BANK_SLUG=""
SITE_NAME=""
OP_EMAIL=""; OP_NAME=""
A1_EMAIL=""; A1_NAME=""
A2_EMAIL=""; A2_NAME=""
AU_EMAIL=""; AU_NAME=""
CERT=""; KEY=""; CA=""
LAN_IP=""
ALLOW_CIDRS=""
SIEM_URL=""; SIEM_CA=""; SIEM_IP=""
NO_FIREWALL=0
ORIG_ARGS=("$@")

if [ -t 1 ]; then C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[1m'; C_0=$'\e[0m'; else C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""; fi
WARNINGS=()
step() { printf '\n%s==> %s%s\n' "$C_B" "$*" "$C_0"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %sOK%s  %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '    %sWARN%s %s\n' "$C_Y" "$C_0" "$*"; WARNINGS+=("$*"); }
die()  { printf '\n%sERROR%s %s\n' "$C_R" "$C_0" "$*" >&2; printf '      Log: %s   (re-run the same command to resume)\n' "$LOG_FILE" >&2; exit 1; }
# shellcheck disable=SC1091
os_field() { ( . /etc/os-release 2>/dev/null && printf "%s" "${!1:-}" ); }

PHASES=(); PH_T0=0; PH_NAME=""
phase() { end_phase; PH_NAME="$1"; PH_T0=$(date +%s); printf '\n%s######## %s%s   (%s)\n' "$C_B" "$1" "$C_0" "$(date +%H:%M:%S)"; }
end_phase() { [ "$PH_T0" -gt 0 ] || return 0; local s=$(( $(date +%s) - PH_T0 )); PHASES+=("$(printf '%-46s %3dm%02ds' "$PH_NAME" $((s / 60)) $((s % 60)))"); PH_T0=0; }

usage() {
  awk 'NR > 1 && /^set -euo/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null || true
  cat <<'TXT'

Options:
  --domain NAME            bank internal domain, e.g. bank.local (PatchGate = patchgate.<domain>)
  --bank-name "NAME"       the bank's name in PatchGate (default "Bank"); --bank-slug short code (default from name)
  --site-name "NAME"       Tactical site / connector name (default "Head office")
  --admin1-email UPN --admin1-name "N"   bank ADMIN #1 (maker)   (default admin1@<domain>)
  --admin2-email UPN --admin2-name "N"   bank ADMIN #2 (checker) (default admin2@<domain>)
  --auditor-email UPN --auditor-name "N" optional bank AUDITOR (read-only)
  --operator-email UPN     PatchGate platform operator (connectors, enrolment) (default patchgate-operator@<domain>)
  --cert F --key F --ca F  the bank's certificate (SAN: patchgate/rmm/api/mesh/pg-cache.<domain>), key, root CA.
                           Without them a bank CA is generated here (the PC kit carries it as bank-ca.pem).
  --lan-ip IP              this server's LAN address the PCs use (default: source address of the default route)
  --allow-cidrs "C ..."    who may connect to the router (default: 10/8 172.16/12 192.168/16 127/8)
  --siem-url tls://H:P --siem-ca F [--siem-ip IP]   bank SIEM (PatchGate audit export + site audit relay)
  --no-firewall            do NOT apply the host egress lockdown (not recommended: loud warning)
  --source-dir DIR         use this checkout instead of cloning (developers / offline copy)
  --ref REF  --repo OWNER/NAME   what to clone (default main of Dataspace-Security/Dataspace-PatchGate)
  --non-interactive        never ask (defaults are used; --domain is required)
  --yes                    confirm --purge
TXT
}

need_val() { [ $# -ge 2 ] && [ -n "$2" ] || die "option $1 needs a value"; }
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --domain) need_val "$@"; DOMAIN="$2"; shift 2 ;;
      --bank-name) need_val "$@"; BANK_NAME="$2"; shift 2 ;;
      --bank-slug) need_val "$@"; BANK_SLUG="$2"; shift 2 ;;
      --site-name) need_val "$@"; SITE_NAME="$2"; shift 2 ;;
      --operator-email|--admin-email) need_val "$@"; OP_EMAIL="$2"; shift 2 ;;
      --operator-name) need_val "$@"; OP_NAME="$2"; shift 2 ;;
      --admin1-email) need_val "$@"; A1_EMAIL="$2"; shift 2 ;;
      --admin1-name) need_val "$@"; A1_NAME="$2"; shift 2 ;;
      --admin2-email) need_val "$@"; A2_EMAIL="$2"; shift 2 ;;
      --admin2-name) need_val "$@"; A2_NAME="$2"; shift 2 ;;
      --auditor-email) need_val "$@"; AU_EMAIL="$2"; shift 2 ;;
      --auditor-name) need_val "$@"; AU_NAME="$2"; shift 2 ;;
      --cert) need_val "$@"; CERT="$2"; shift 2 ;;
      --key) need_val "$@"; KEY="$2"; shift 2 ;;
      --ca) need_val "$@"; CA="$2"; shift 2 ;;
      --lan-ip) need_val "$@"; LAN_IP="$2"; shift 2 ;;
      --allow-cidrs) need_val "$@"; ALLOW_CIDRS="$2"; shift 2 ;;
      --siem-url) need_val "$@"; SIEM_URL="$2"; shift 2 ;;
      --siem-ca) need_val "$@"; SIEM_CA="$2"; shift 2 ;;
      --siem-ip) need_val "$@"; SIEM_IP="$2"; shift 2 ;;
      --source-dir) need_val "$@"; SOURCE_DIR="$2"; shift 2 ;;
      --ref) need_val "$@"; REF="$2"; REF_GIVEN=1; shift 2 ;;
      --repo) need_val "$@"; REPO_SLUG="$2"; shift 2 ;;
      --non-interactive) NONINTERACTIVE=1; shift ;;
      --no-firewall) NO_FIREWALL=1; shift ;;
      --yes|-y) ASSUME_YES=1; shift ;;
      --status) MODE=status; shift ;;
      --upgrade) MODE=upgrade; shift ;;
      --uninstall) MODE=uninstall; shift ;;
      --purge) PURGE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done
  [[ "$REF" =~ ^[A-Za-z0-9._/-]{1,100}$ ]] || die "invalid --ref"
  [[ "$REPO_SLUG" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "invalid --repo"
}

ask() { # var "question" [default]
  local __var="$1" __q="$2" __def="${3:-}" __ans=""
  if [ -n "${!__var:-}" ]; then return 0; fi
  if [ "$NONINTERACTIVE" = 1 ] || [ ! -r /dev/tty ]; then
    [ -n "$__def" ] && { printf -v "$__var" '%s' "$__def"; return 0; }
    die "missing value for ${__var} (non-interactive): pass it as an option, see --help"
  fi
  if [ -n "$__def" ]; then printf '    %s [%s]: ' "$__q" "$__def" >/dev/tty; else printf '    %s: ' "$__q" >/dev/tty; fi
  IFS= read -r __ans </dev/tty || true
  printf -v "$__var" '%s' "${__ans:-$__def}"
  [ -n "${!__var}" ] || die "a value for '${__q}' is required"
}

setup_logging() {
  [ -n "${PG_BANK_LOGGING:-}" ] && return 0
  mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; chmod 0600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE") 2>&1
  export PG_BANK_LOGGING=1
  printf '\n===== %s installers/bank/install.sh %s (mode=%s) =====\n' "$(date -u +%FT%TZ)" "$BANK_INSTALLER_VERSION" "$MODE"
}

# ------------------------------------------------------------------ state (non-secret answers)
STATE="$BANK_DIR/bank.conf"
STATE_KEYS=(DOMAIN BANK_NAME BANK_SLUG SITE_NAME OP_EMAIL OP_NAME A1_EMAIL A1_NAME A2_EMAIL A2_NAME AU_EMAIL AU_NAME LAN_IP ALLOW_CIDRS SIEM_URL SIEM_IP SOURCE_DIR MANAGED_CLONE REF TLS_SOURCE TENANT_ID VERSION HOSTS_ENTRY)
TLS_SOURCE=""; TENANT_ID=""; VERSION=""; HOSTS_ENTRY=""
load_state() {
  [ -f "$STATE" ] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in ''|\#*) continue ;; esac
    for want in "${STATE_KEYS[@]}"; do
      if [ "$k" = "$want" ]; then
        if [ "$k" = REF ]; then [ "$REF_GIVEN" = 1 ] || REF="$v"
        elif [ "$k" = MANAGED_CLONE ]; then [ "$v" = 1 ] && MANAGED_CLONE=1
        elif [ -z "${!k:-}" ]; then printf -v "$k" '%s' "$v"; fi
      fi
    done
  done < "$STATE"
}
save_state() {
  install -d -m 0700 "$BANK_DIR"
  local tmp k; tmp="$(mktemp "$BANK_DIR/.bank.XXXXXX")"
  { echo "# installers/bank/install.sh — non-secret answers for re-runs/upgrades"
    for k in "${STATE_KEYS[@]}"; do printf '%s=%s\n' "$k" "${!k}"; done; } > "$tmp"
  chmod 0600 "$tmp"; mv -f "$tmp" "$STATE"
}

# ------------------------------------------------------------------ child installers (secrets diverted)
# Runs an installer with its output shown/logged line by line. The line after a "password (shown ONCE" marker
# is a one-time password: it is written to $BANK_DIR/secret/<name> (0600) and replaced by a placeholder.
run_child() { # secret-name cmd...
  local name="$1"; shift
  local rc
  set +e
  "$@" 2>&1 < /dev/null | {
    grab=0
    while IFS= read -r line; do
      if [ "$grab" = 1 ] && [ -n "${line// /}" ]; then
        (umask 077; printf '%s\n' "${line#"${line%%[! ]*}"}" > "$BANK_DIR/secret/$name")
        printf '        <one-time password hidden: written to %s/logins.txt>\n' "$BANK_DIR"; grab=0; continue
      fi
      case "$line" in *"Temporary password for"*|*"password (shown ONCE"*) grab=1 ;; esac
      [[ "$line" =~ ^\ *[0-9a-f]{12}\ (Pulling|Waiting|Downloading|Verifying|Download|Extracting|Pull\ complete|Already) ]] && continue
      printf '%s\n' "$line"
    done; }
  rc=${PIPESTATUS[0]}
  set -e
  return "$rc"
}

DCP=(docker compose -f docker-compose.prod.yml --env-file .env.production)
dcp() { (cd "$DEPLOY" && "${DCP[@]}" "$@"); }
psql_q() { dcp exec -T -u postgres db psql -d patchgate -qtAc "$1"; }
env_get() { sed -n "s/^$1=//p" "$DEPLOY/.env.production" 2>/dev/null | tail -1; }

# ------------------------------------------------------------------ 1. preflight
preflight() {
  phase "1. Preflight"
  [ "$(id -u)" = 0 ] || die "run as root (sudo ...)"
  [ "$(uname -m)" = x86_64 ] || die "x86-64 required (found $(uname -m))"
  local id ver; id="$(os_field ID)"; ver="$(os_field VERSION_ID)"
  case "$id:$ver" in
    ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ok "OS $(os_field PRETTY_NAME)" ;;
    *) die "supported: Ubuntu 22.04/24.04/26.04, Debian 12/13 (found $(os_field PRETTY_NAME))" ;;
  esac
  local cpus mem_gb; cpus="$(nproc)"; mem_gb="$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)"
  [ "$cpus" -ge 2 ] || die "at least 2 CPUs required (found $cpus; 4+ recommended)"
  [ "$mem_gb" -ge 10 ] || die "at least 12 GB RAM required (found ${mem_gb} GB; 16 GB recommended)"
  if [ "$cpus" -ge 4 ] && [ "$mem_gb" -ge 15 ]; then ok "$cpus CPUs, ${mem_gb} GB RAM"
  else warn "$cpus CPUs, ${mem_gb} GB RAM (4 CPUs / 16 GB recommended: it works, but slowly)"; fi
  local missing=() t
  for t in curl git openssl gpg ss ip iptables awk sed tar gzip sha256sum; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
  if [ ${#missing[@]} -gt 0 ]; then
    info "installing base tools (${missing[*]})"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq ca-certificates curl git openssl gnupg iproute2 iptables procps >/dev/null || die "apt-get install of the base tools failed"
  fi
  ok "base tools present"
  check_foreign
  # The Dockerfiles need BuildKit (heredocs, COPY --chmod). install-patchgate.sh installs docker-ce WITH buildx
  # when Docker is missing; an existing Ubuntu docker.io lacks it (docker.io -> docker-buildx).
  if command -v docker >/dev/null 2>&1 && ! docker buildx version >/dev/null 2>&1; then
    local pkg=docker-buildx; dpkg -s docker-ce >/dev/null 2>&1 && pkg=docker-buildx-plugin
    info "Docker BuildKit (buildx) missing: installing $pkg"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null 2>&1 \
      || { apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null 2>&1; } \
      || die "could not install $pkg (Docker's buildx plugin is required)"
  fi
  local code; code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://registry-1.docker.io/v2/ || true)"
  case "$code" in 200|401) ok "internet for the installation (Docker Hub reachable)" ;;
    *) die "Docker Hub not reachable (HTTP ${code:-none}): the installation needs internet (GitHub, Docker Hub, download.docker.com, Microsoft)" ;; esac
  install -d -m 0700 "$BANK_DIR" "$BANK_DIR/secret" "$BANK_DIR/tls"
}

# Something else on this server (e.g. the colleague test kit's pgkit-* containers) must be removed by the user
# first: never removed silently.
check_foreign() {
  local kit="" p busy=""
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    kit="$( { docker ps -a --format '{{.Names}}' --filter label=com.patchgate.kit=colleague-test; docker ps -a --format '{{.Names}}' | grep -E '^pgkit-'; } 2>/dev/null | sort -u | tr '\n' ' ' || true)"
  fi
  if [ -n "${kit// /}" ]; then
    die "the PatchGate colleague TEST KIT is installed on this server (containers: $kit). Remove it first, then re-run:
        bash <kit folder>/test-on-my-pc.sh --cleanup --yes      (or: bash install-patchgate-test.sh --cleanup)
        or by hand:  docker rm -f $kit; docker network rm pgkit-net"
  fi
  # First install only: 80/443/8443 must be free (a re-run finds them served by our own router / site).
  if [ ! -f "$STATE" ] || ! docker inspect "$EDGE_NAME" >/dev/null 2>&1; then
    for p in 80 443 8443; do ss -Hltn "sport = :$p" 2>/dev/null | grep -q . && busy="$busy $p"; done
    if [ -n "$busy" ] && ! site_running 2>/dev/null; then
      die "port(s)$busy already in use by another program (ss -ltnp): stop it first (80/443/8443 on this server belong to PatchGate)"
    fi
  fi
  return 0
}

# ------------------------------------------------------------------ 2. source
bootstrap_source() {
  phase "2. Source"
  # A re-run of the one-link command (resume after a failure) must pick up fixes: the saved state points at
  # our managed clone, so refresh it (fetch + checkout REF) instead of reusing the old checkout. The
  # re-exec'd child (PG_BANK_MANAGED=1) and --source-dir runs are left alone.
  if [ "$MANAGED_CLONE" = 1 ] && [ -z "${PG_BANK_MANAGED:-}" ] && [ "$SOURCE_DIR" = "$BANK_DIR/src" ]; then
    SOURCE_DIR=""
  fi
  if [ -n "$SOURCE_DIR" ]; then
    [ -f "$SOURCE_DIR/deploy/docker-compose.prod.yml" ] && [ -f "$SOURCE_DIR/installers/site/install-site.sh" ] \
      || die "--source-dir $SOURCE_DIR is not a PatchGate checkout"
    SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
    ok "source: $SOURCE_DIR$([ "$MANAGED_CLONE" = 1 ] && echo " (clone of $REPO_SLUG @ $REF)")"
  else
    local here=""; [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ] && here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    if [ -n "$here" ] && [ -f "$here/deploy/docker-compose.prod.yml" ] && [ "$here" != "$BANK_DIR/src" ]; then
      SOURCE_DIR="$here"; ok "source: this checkout ($SOURCE_DIR)"
    else
      clone_or_update
      save_state
      # Continue with the installer of the checked-out version (the one-link script may be newer/older).
      if [ "$(cd "$(dirname "${BASH_SOURCE[0]:-/dev/null}")" 2>/dev/null && pwd)/install.sh" != "$SOURCE_DIR/installers/bank/install.sh" ]; then
        info "continuing with $SOURCE_DIR/installers/bank/install.sh"
        exec env PG_BANK_SOURCE_DIR="$SOURCE_DIR" PG_BANK_MANAGED=1 bash "$SOURCE_DIR/installers/bank/install.sh" "${ORIG_ARGS[@]}"
      fi
    fi
  fi
  # Files from a Windows checkout may carry CRLF.
  find "$SOURCE_DIR/installers" "$SOURCE_DIR/kits/colleague-test/lib" -type f -name '*.sh' -exec sed -i 's/\r$//' {} +
  local base sha=""; base="$(tr -d '\r\n' < "$SOURCE_DIR/VERSION")"
  if git -C "$SOURCE_DIR" rev-parse --short=7 HEAD >/dev/null 2>&1; then sha="$(git -C "$SOURCE_DIR" rev-parse --short=7 HEAD)"; fi
  VERSION="$base-$([ -n "$sha" ] && echo "g$sha" || echo local)"
  [[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,40}$ ]] || die "invalid version string $VERSION"
  ok "version $VERSION"
}
clone_or_update() {
  local dst="$BANK_DIR/src" url="https://github.com/$REPO_SLUG.git" target
  export GIT_TERMINAL_PROMPT=0
  if [ -d "$dst/.git" ]; then
    git -c credential.helper= -C "$dst" fetch --quiet --tags --prune --force origin || die "git fetch failed ($url)"
    ok "updated $dst"
  else
    git -c credential.helper= clone --quiet "$url" "$dst" || die "git clone $url failed (public repository: no sign-in needed; proxy?)"
    ok "cloned $url"
  fi
  if git -C "$dst" rev-parse --verify --quiet "origin/$REF^{commit}" >/dev/null; then target="origin/$REF"
  elif git -C "$dst" rev-parse --verify --quiet "$REF^{commit}" >/dev/null; then target="$REF"
  else die "ref $REF not found in $REPO_SLUG"; fi
  git -C "$dst" -c advice.detachedHead=false checkout --quiet --force --detach "$target"
  ok "checked out $REF = $(git -C "$dst" rev-parse --short=7 HEAD) ($(git -C "$dst" log -1 --format='%cd %s' --date=short | cut -c1-70))"
  SOURCE_DIR="$dst"; MANAGED_CLONE=1
}

# ------------------------------------------------------------------ 3. answers
slugify() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' | cut -c1-40 | sed -E 's/-+$//'; }
detect_lan_ip() { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") {print $(i+1); exit}}'; }
collect_answers() {
  phase "3. Settings"
  ask DOMAIN "Bank internal domain (PatchGate becomes patchgate.<domain>)" "bank.test"
  DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"; DOMAIN="${DOMAIN#patchgate.}"
  [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "invalid domain: $DOMAIN"
  ask BANK_NAME "Bank name" "Bank"
  [ -n "$BANK_SLUG" ] || BANK_SLUG="$(slugify "$BANK_NAME")"
  [[ "$BANK_SLUG" =~ ^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$ ]] || die "invalid bank short code '$BANK_SLUG' (--bank-slug: 2-40 of a-z 0-9 -)"
  ask SITE_NAME "Site name (Tactical site / connector)" "Head office"
  ask OP_EMAIL "PatchGate platform operator sign-in (connectors, enrolment)" "patchgate-operator@$DOMAIN"
  OP_NAME="${OP_NAME:-PatchGate Operator}"
  ask A1_EMAIL "Bank ADMIN #1 sign-in (maker)" "admin1@$DOMAIN"; A1_NAME="${A1_NAME:-$BANK_NAME Admin 1}"
  ask A2_EMAIL "Bank ADMIN #2 sign-in (checker)" "admin2@$DOMAIN"; A2_NAME="${A2_NAME:-$BANK_NAME Admin 2}"
  AU_NAME="${AU_NAME:-$BANK_NAME Auditor}"
  local u; for u in "$OP_EMAIL" "$A1_EMAIL" "$A2_EMAIL" ${AU_EMAIL:+"$AU_EMAIL"}; do
    [[ "$u" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "invalid sign-in name: $u"
  done
  [ "$A1_EMAIL" != "$A2_EMAIL" ] || die "the two bank admins must be different accounts (maker != checker)"
  [ -n "$LAN_IP" ] || LAN_IP="$(detect_lan_ip)"
  [[ "$LAN_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "cannot detect this server's LAN IP: pass --lan-ip"
  ip -4 addr show | grep -q "inet $LAN_IP/" || die "--lan-ip $LAN_IP is not an address of this server"
  ALLOW_CIDRS="${ALLOW_CIDRS:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8}"
  [ -z "$SIEM_URL" ] || [[ "$SIEM_URL" =~ ^tls://[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] || die "--siem-url must be tls://host:port"
  ok "bank \"$BANK_NAME\" ($BANK_SLUG), site \"$SITE_NAME\", domain $DOMAIN, LAN IP $LAN_IP"
  save_state
}

# ------------------------------------------------------------------ 4. TLS (one certificate for the 5 names)
names() { printf '%s\n' "patchgate.$DOMAIN" "rmm.$DOMAIN" "api.$DOMAIN" "mesh.$DOMAIN" "pg-cache.$DOMAIN"; }
setup_tls() {
  phase "4. TLS certificate + Microsoft code-signing roots"
  local d="$BANK_DIR/tls" h
  if [ -s "$d/fullchain.pem" ] && [ -s "$d/privkey.pem" ] && [ -s "$d/bank-ca.pem" ]; then
    ok "keeping $d/fullchain.pem ($TLS_SOURCE, valid until $(openssl x509 -in "$d/fullchain.pem" -noout -enddate | cut -d= -f2))"
  elif [ -n "$CERT$KEY$CA" ]; then
    [ -r "$CERT" ] && [ -r "$KEY" ] && [ -r "$CA" ] || die "--cert, --key and --ca are needed together (readable PEM files)"
    [ "$(openssl x509 -in "$CERT" -noout -pubkey | openssl sha256)" = "$(openssl pkey -in "$KEY" -pubout | openssl sha256)" ] || die "certificate and key do not match"
    while read -r h; do openssl x509 -in "$CERT" -noout -checkhost "$h" | grep -q 'does match' || die "certificate does not cover $h"; done < <(names)
    openssl verify -CAfile "$CA" -untrusted "$CERT" "$CERT" >/dev/null 2>&1 || die "certificate does not chain to --ca"
    install -m 0644 "$CERT" "$d/fullchain.pem"; install -m 0600 "$KEY" "$d/privkey.pem"; install -m 0644 "$CA" "$d/bank-ca.pem"
    TLS_SOURCE="bank certificate"; ok "installed the bank's certificate"
  else
    info "no --cert given: creating a bank CA on this server (the PC kit installs bank-ca.pem on every PC)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=PatchGate bank CA ($DOMAIN)/O=$BANK_NAME" -keyout "$d/bank-ca.key" -out "$d/bank-ca.pem" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=patchgate.$DOMAIN" \
      -keyout "$d/privkey.pem" -out "$d/server.csr" 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' \
      "$(names | sed 's/^/DNS:/' | paste -sd, -)" > "$d/server.ext"
    openssl x509 -req -in "$d/server.csr" -CA "$d/bank-ca.pem" -CAkey "$d/bank-ca.key" -CAcreateserial -days 825 -sha256 \
      -extfile "$d/server.ext" -out "$d/leaf.pem" 2>/dev/null
    cat "$d/leaf.pem" "$d/bank-ca.pem" > "$d/fullchain.pem"
    rm -f "$d/server.csr" "$d/server.ext" "$d/leaf.pem" "$d/bank-ca.srl"
    chmod 0600 "$d/privkey.pem" "$d/bank-ca.key"; chmod 0644 "$d/fullchain.pem" "$d/bank-ca.pem"
    TLS_SOURCE="bank CA made by the installer"
    ok "bank CA $d/bank-ca.pem + certificate for $(names | paste -sd' ' -)"
  fi
  save_state
  codesign_roots
}
codesign_roots() {
  local out="$BANK_DIR/codesign-ca.pem" tmp entry url want name f got
  tmp="$(mktemp)"
  for entry in "${MS_ROOTS[@]}"; do
    read -r url want name <<<"$entry"
    f="$(mktemp)"; got=""
    if curl -fsSL --max-time 30 -o "$f" "$url" 2>/dev/null; then got="$(sha256sum < "$f" | cut -d' ' -f1)"; fi
    if [ "$got" = "$want" ]; then
      openssl x509 -inform DER -in "$f" -outform PEM >> "$tmp" || { rm -f "$f" "$tmp"; die "cannot convert $url"; }
      info "$name: downloaded from microsoft.com, SHA-256 matches the pin"
    else
      # Same certificate shipped in the repository (exported from the Windows trust store), same pin.
      local alt="$SOURCE_DIR/kits/colleague-test/lib/$name"
      got="$( [ -s "$alt" ] && sed -e 's/\r$//' -e '/^-----/d' "$alt" | base64 -d | sha256sum | cut -d' ' -f1 || true)"
      [ "$got" = "$want" ] || { rm -f "$f" "$tmp"; die "Microsoft root $name: SHA-256 mismatch / not available (want $want): refusing (fail closed)"; }
      sed 's/\r$//' "$alt" >> "$tmp"
      warn "$name: download failed, used the pinned copy from the repository"
    fi
    rm -f "$f"
  done
  install -m 0644 "$tmp" "$out"; rm -f "$tmp"
  ok "Authenticode roots (Microsoft Root CA 2011 + 2010, SHA-256 pinned) -> $out"
}

# ------------------------------------------------------------------ 5. PatchGate server
install_server() {
  phase "5. PatchGate server (installers/server/install-patchgate.sh)"
  local args=(--non-interactive --domain "patchgate.$DOMAIN" --admin-email "$OP_EMAIL" --admin-name "$OP_NAME"
    --tls existing --cert "$BANK_DIR/tls/fullchain.pem" --key "$BANK_DIR/tls/privkey.pem"
    --image-source build --source-dir "$SOURCE_DIR" --version "$VERSION" --skip-smoke
    --codesign-ca "$BANK_DIR/codesign-ca.pem")
  [ -n "$SIEM_URL" ] && args+=(--siem-url "$SIEM_URL")
  [ -n "$SIEM_CA" ] && args+=(--siem-ca "$SIEM_CA")
  # RUNBOOK §4.3 subnet rules (web -> SIEM only, fetcher -> proxy only); they do not affect image builds. The
  # host-wide uplink lockdown (PG-BANK-EGRESS) follows after the site install. No SIEM: 127.0.0.1 = no target.
  local dns; dns="$(dns_ip)"
  if [ "$NO_FIREWALL" = 0 ] && [ -n "$dns" ]; then args+=(--apply-firewall --dns-ip "$dns" --siem-ip "$(siem_ip | grep . || echo 127.0.0.1)")
  else args+=(--no-firewall); fi
  # nginx behind the SNI router: 127.0.0.1:8444 (HTTPS) and 127.0.0.1:8080 (HTTP redirect).
  local try
  for try in 1 2; do
    # A build step fetching packages (apt, npm, GitHub) can fail on a network hiccup: the re-run is safe.
    run_child platform-operator.pw env PG_REGISTRY="" \
      PG_HTTPS_BIND="${PG_HTTPS_LOCAL%:*}" PG_HTTPS_PORT="${PG_HTTPS_LOCAL##*:}" PG_HTTP_BIND="${PG_HTTP_LOCAL%:*}" PG_HTTP_PORT="${PG_HTTP_LOCAL##*:}" \
      bash "$SOURCE_DIR/installers/server/install-patchgate.sh" "${args[@]}" && break
    [ "$try" = 1 ] || die "install-patchgate.sh failed twice (log /var/log/patchgate-install.log)"
    warn "install-patchgate.sh failed once (network hiccup during a build?): retrying (safe re-run)"
  done
  install -m 0644 "$BANK_DIR/tls/bank-ca.pem" "$DEPLOY/tls/bank-ca.pem"
  ok "PatchGate $VERSION running (nginx on $PG_HTTPS_LOCAL behind the router); QUARANTINE_HOURS=$(env_get QUARANTINE_HOURS)"
}

# ------------------------------------------------------------------ 6. bank + accounts
# shellcheck disable=SC2086 # ${FP:+-e FP} = zero or two words on purpose
tools_cli() { # script args... (scripts/admin/*.ts in the tools image, as the DB owner, audited)
  dcp run --rm -T -v "$SOURCE_DIR/installers/bank/lib/bank-wire.ts:/app/scripts/admin/bank-wire.ts:ro" \
    -v "$SOURCE_DIR/installers/bank/lib/bank-wire-main.ts:/app/scripts/admin/bank-wire-main.ts:ro" \
    ${FP:+-e FP} migrate node node_modules/tsx/dist/cli.mjs "$@"
}
create_user() { # key upn name role
  local key="$1" upn="$2" name="$3" role="$4" out rc=0 pw
  out="$(tools_cli scripts/admin/create-user.ts --upn "$upn" --name "$name" --role "$role" --tenant "$BANK_SLUG" --generate 2>&1)" || rc=$?
  if [ "$rc" != 0 ]; then
    printf '%s' "$out" | grep -q 'already exists' && { ok "$upn exists (kept)"; return 0; }
    printf '%s\n' "$out" | grep -vi 'password' | tail -5 | sed 's/^/    /'; die "creating $upn failed"
  fi
  pw="$(printf '%s\n' "$out" | sed -n 's/^Temporary password[^:]*: //p' | tail -1)"
  [ -n "$pw" ] || die "create-user did not return a temporary password for $upn"
  (umask 077; printf '%s\n' "$pw" > "$BANK_DIR/secret/$key.pw")
  ok "$role $upn created (bank $BANK_SLUG, audited)"
}
setup_bank() {
  phase "6. Bank and accounts"
  local out
  # Make the mounted CLI files readable for the tools image user (uid 10001).
  chmod 0644 "$SOURCE_DIR/installers/bank/lib/"bank-wire*.ts
  out="$(tools_cli scripts/admin/bank-wire.ts tenant "$BANK_SLUG" "$BANK_NAME" 2>&1)" || { printf '%s\n' "$out" | tail -5 | sed 's/^/    /'; die "creating the bank failed"; }
  TENANT_ID="$(printf '%s\n' "$out" | sed -n 's/^BANKWIRE_TENANT=//p' | tail -1)"
  [ -n "$TENANT_ID" ] || die "bank-wire returned no tenant id"
  save_state
  ok "bank \"$BANK_NAME\" ($BANK_SLUG) = $TENANT_ID (standard rings Ring0-Test / Ring1-Pilot / Ring2-Prod)"
  create_user admin1 "$A1_EMAIL" "$A1_NAME" ADMIN
  create_user admin2 "$A2_EMAIL" "$A2_NAME" ADMIN
  [ -z "$AU_EMAIL" ] || create_user auditor "$AU_EMAIL" "$AU_NAME" AUDITOR
}

# ------------------------------------------------------------------ 7. site bundle (local: no web download)
build_bundle() {
  phase "7. Connector image + online site bundle (built here)"
  export DOCKER_BUILDKIT=1
  docker build -q -t "patchgate-connector:$VERSION" "$SOURCE_DIR/patchgate-connector" >/dev/null || die "building the connector image failed"
  ok "patchgate-connector:$VERSION built from source"
  local out="$BANK_DIR/bundle"
  rm -rf "$out"; mkdir -p "$out"
  bash "$SOURCE_DIR/kits/colleague-test/lib/build-online-bundle.sh" --repo "$SOURCE_DIR" --version "$VERSION" \
    --connector-image "patchgate-connector:$VERSION" --out "$out" || die "building the site bundle failed"
  BUNDLE_TGZ="$out/patchgate-site-$VERSION-online.tar.gz"
  [ -s "$BUNDLE_TGZ" ] || die "bundle $BUNDLE_TGZ missing"
  ok "site bundle $(basename "$BUNDLE_TGZ") (Tactical images digest-pinned in IMAGES.lock; installed locally, no download)"
}
BUNDLE_TGZ=""

# ------------------------------------------------------------------ 8. bank site
site_running() { docker ps -q --filter label=com.docker.compose.project=patchgate-site 2>/dev/null | grep -q .; }
site_enrolled() { [ -f "$SITE_DIR/etc/connector.json" ] && grep -q '"identity"' "$SITE_DIR/etc/connector.json"; }
site_args() {
  SITE_ARGS=(--bundle "$BUNDLE_TGZ" --online --no-lockdown --non-interactive --site-name "$SITE_NAME" --client-name "$BANK_NAME"
    --domain "$DOMAIN" --tls bank --cert "$BANK_DIR/tls/fullchain.pem" --key "$BANK_DIR/tls/privkey.pem" --ca "$BANK_DIR/tls/bank-ca.pem"
    --server "https://patchgate.$DOMAIN" --patchgate-ca "$BANK_DIR/tls/bank-ca.pem" --patchgate-ip "$LAN_IP" --bind-ip "$SITE_BIND")
  if [ -n "$SIEM_URL" ]; then SITE_ARGS+=(--siem-url "$SIEM_URL"); [ -n "$SIEM_IP" ] && SITE_ARGS+=(--siem-ip "$SIEM_IP"); fi
  return 0
}
SITE_ARGS=()
install_site_pass1() {
  phase "8. Bank site: Tactical + connector (installers/site/install-site.sh --online)"
  site_args
  if site_enrolled; then
    run_child tactical-breakglass.pw bash "$SOURCE_DIR/installers/site/install-site.sh" "${SITE_ARGS[@]}" || die "install-site.sh failed"
    ok "site re-run done (already enrolled)"; return 0
  fi
  if ! site_running; then
    # install-site.sh needs ports 80/443/8443 free on this host for its first start: pause the router.
    docker rm -f "$EDGE_NAME" >/dev/null 2>&1 || true
    run_child tactical-breakglass.pw bash "$SOURCE_DIR/installers/site/install-site.sh" "${SITE_ARGS[@]}" --skip-enrol \
      || die "install-site.sh failed (log /var/log/patchgate-site-install.log)"
  fi
  ok "Tactical up on $SITE_BIND (internal networks), connector configured; enrolment follows after the router"
}

# ------------------------------------------------------------------ 9. SNI router
edge_conf() {
  local c allow=""
  for c in $ALLOW_CIDRS; do allow="$allow    allow $c;"$'\n'; done
  cat <<CONF
# pg-bank-edge (installers/bank/install.sh): TLS passthrough by SNI. No TLS termination here.
worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 4096; }
stream {
  log_format edge '\$remote_addr [\$time_local] \$ssl_preread_server_name -> \$upstream_addr \$status';
  access_log /dev/stdout edge;
  map \$ssl_preread_server_name \$edge_backend {
    patchgate.$DOMAIN  $PG_HTTPS_LOCAL;
    rmm.$DOMAIN        $SITE_BIND:443;
    api.$DOMAIN        $SITE_BIND:443;
    mesh.$DOMAIN       $SITE_BIND:443;
    pg-cache.$DOMAIN   $SITE_BIND:8443;
    default            $PG_HTTPS_LOCAL;
  }
  server {
    listen $LAN_IP:443;
    listen 127.0.0.1:443;
    ssl_preread on;
    proxy_pass \$edge_backend;
    proxy_connect_timeout 5s;
    proxy_timeout 1h;
$allow    deny all;
  }
  server {   # package cache for the PCs (https://pg-cache.$DOMAIN:8443)
    listen $LAN_IP:8443;
    proxy_pass $SITE_BIND:8443;
    proxy_timeout 1h;
$allow    deny all;
  }
  server {   # http -> PatchGate's redirect to https
    listen $LAN_IP:80;
    proxy_pass $PG_HTTP_LOCAL;
$allow    deny all;
  }
}
CONF
}
start_edge() {
  phase "9. SNI router $EDGE_NAME ($LAN_IP:443/8443/80)"
  edge_conf > "$BANK_DIR/edge-nginx.conf.tmp"; chmod 0644 "$BANK_DIR/edge-nginx.conf.tmp"
  local changed=1
  if cmp -s "$BANK_DIR/edge-nginx.conf.tmp" "$BANK_DIR/edge-nginx.conf" 2>/dev/null; then changed=0; fi
  mv -f "$BANK_DIR/edge-nginx.conf.tmp" "$BANK_DIR/edge-nginx.conf"
  if [ "$changed" = 0 ] && [ "$(docker inspect -f '{{.State.Running}}' "$EDGE_NAME" 2>/dev/null)" = true ]; then ok "router running (config unchanged)"; return 0; fi
  docker image inspect "$EDGE_IMAGE" >/dev/null 2>&1 || docker pull -q "$EDGE_IMAGE" >/dev/null || die "docker pull $EDGE_IMAGE failed"
  docker rm -f "$EDGE_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$EDGE_NAME" --label com.patchgate.bank=edge --restart unless-stopped --network host \
    --read-only --tmpfs /tmp:size=8m --tmpfs /var/cache/nginx:size=8m \
    --cap-drop ALL --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
    --security-opt no-new-privileges:true --log-opt max-size=50m --log-opt max-file=5 \
    -v "$BANK_DIR/edge-nginx.conf:/etc/nginx/nginx.conf:ro" --entrypoint nginx "$EDGE_IMAGE" -g 'daemon off;' >/dev/null \
    || die "starting $EDGE_NAME failed"
  local _; for _ in $(seq 1 10); do (exec 3<>"/dev/tcp/$LAN_IP/443") 2>/dev/null && break; sleep 1; done
  (exec 3<>"/dev/tcp/$LAN_IP/443") 2>/dev/null || { docker logs --tail 20 "$EDGE_NAME" 2>&1 | sed 's/^/    /'; die "router does not listen on $LAN_IP:443"; }
  ok "router: patchgate.$DOMAIN -> $PG_HTTPS_LOCAL, rmm/api/mesh -> $SITE_BIND:443, pg-cache -> $SITE_BIND:8443 (clients: $ALLOW_CIDRS)"
  # This server itself must find the 5 names (bank DNS may come later): marked hosts entry.
  if ! getent ahostsv4 "patchgate.$DOMAIN" >/dev/null 2>&1; then
    printf '%s %s %s\n' "$LAN_IP" "$(names | paste -sd' ' -)" "$HOSTS_MARK" >> /etc/hosts
    HOSTS_ENTRY=1; save_state
    info "added '$LAN_IP patchgate/rmm/api/mesh/pg-cache.$DOMAIN' to /etc/hosts of this server (bank DNS should carry them too)"
  fi
}

# ------------------------------------------------------------------ 10. connector allow-list + enrolment
allowlist() {
  # Through the router PatchGate's nginx sees the Docker gateway of its own networks as the source; the router
  # itself admits only the bank's internal ranges (--allow-cidrs). Connector requests stay Ed25519-signed.
  local cid gws gw a="$DEPLOY/nginx/allowlists" f
  cid="$(dcp ps -q nginx | head -1)"; [ -n "$cid" ] || die "PatchGate nginx not running"
  gws="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$cid")"
  f="$a/connectors.d/$BANK_SLUG.conf"
  { echo "# $BANK_NAME ($BANK_SLUG) — all-in-one bank server: the local connector arrives via the SNI router"
    echo "# (installers/bank/install.sh), seen as the Docker gateway of nginx's networks."
    # Internal networks have no gateway (Docker prints "invalid IP" or nothing): IPv4 addresses only.
    for gw in $gws; do [[ "$gw" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && echo "$gw/32 1;"; done; } > "$f.tmp"
  grep -q ' 1;$' "$f.tmp" || die "no IPv4 gateway found for PatchGate's nginx networks ($gws)"
  chmod 0644 "$f.tmp"; mv -f "$f.tmp" "$f"
  grep -q "^include /etc/nginx/allowlists/connectors.d/$BANK_SLUG.conf;" "$a/connectors.conf" \
    || echo "include /etc/nginx/allowlists/connectors.d/$BANK_SLUG.conf;" >> "$a/connectors.conf"
  dcp exec -T nginx nginx -t >/dev/null 2>&1 || die "nginx config test failed after the allow-list change"
  dcp exec -T nginx nginx -s reload >/dev/null 2>&1
  ok "connector allow-list: $(grep -c ' 1;$' "$f") address(es) in connectors.d/$BANK_SLUG.conf, nginx reloaded"
}
job_key_fp() { awk '$2=="default" {print $1}' "$DEPLOY/secrets/job-signing-keys/FINGERPRINTS.txt" 2>/dev/null | head -1; }
enrol_site() {
  phase "10. Connector allow-list + enrolment"
  allowlist
  if site_enrolled; then ok "connector already enrolled"; return 0; fi
  local FP out code
  FP="$(job_key_fp)"; [[ "$FP" =~ ^[a-f0-9]{64}$ ]] || die "job-signing key fingerprint not found (deploy/secrets/job-signing-keys/FINGERPRINTS.txt)"
  export FP
  out="$(tools_cli scripts/admin/bank-wire.ts enrol "$TENANT_ID" "$SITE_NAME" 2>&1)" || { printf '%s\n' "$out" | grep -v BANKWIRE | tail -5 | sed 's/^/    /'; die "creating the enrolment code failed"; }
  unset FP
  code="$(printf '%s\n' "$out" | sed -n 's/^BANKWIRE_ENROL=//p' | sed -nE 's/.*"code":"([^"]+)".*/\1/p')"
  [ -n "$code" ] || die "no enrolment code returned"
  info "one-time enrolment code minted locally (not shown); job-key fingerprint ${FP:-$(job_key_fp)}"
  site_args
  # Code + fingerprint go to install-site.sh through its environment only (never argv, screen or log).
  ( export PATCHGATE_ENROLL_CODE="$code" PATCHGATE_JOB_KEY_FINGERPRINT; PATCHGATE_JOB_KEY_FINGERPRINT="$(job_key_fp)"
    run_child tactical-breakglass.pw bash "$SOURCE_DIR/installers/site/install-site.sh" "${SITE_ARGS[@]}" ) || die "site enrolment failed (install-site.sh exit $?)"
  site_enrolled || die "connector not enrolled after install-site.sh"
  ok "connector enrolled, job-signing key fingerprint pinned automatically"
}

# ------------------------------------------------------------------ 11. PC kit (siteIp for hosts entries on the PCs)
pc_kit() {
  local j="$SITE_DIR/pc/patchgate-pc.json"
  [ -f "$j" ] || { warn "PC kit $j missing"; return 0; }
  if grep -q '"siteIp"' "$j"; then sed -i -E "s/\"siteIp\": *\"[^\"]*\"/\"siteIp\": \"$LAN_IP\"/" "$j"
  else sed -i "0,/^{/s//{\n  \"siteIp\": \"$LAN_IP\",/" "$j"; fi
  ok "PC kit $SITE_DIR/pc: siteIp $LAN_IP, hostNames rmm/api/mesh/pg-cache.$DOMAIN, bank-ca.pem"
}

# ------------------------------------------------------------------ 12. egress lockdown (host)
uplink() { ip -4 route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}'; }
dns_ip() { # upstream resolver Docker forwards to (not a loopback stub)
  local rf dns=""
  for rf in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do
    [ -z "$dns" ] && [ -r "$rf" ] && dns="$(awk '/^nameserver/ && $2 !~ /^127\./ {print $2; exit}' "$rf")" || true
  done
  printf '%s' "$dns"
}
siem_ip() {
  [ -n "$SIEM_URL" ] || return 0
  [ -n "$SIEM_IP" ] && { printf '%s' "$SIEM_IP"; return 0; }
  getent ahostsv4 "$(printf '%s' "$SIEM_URL" | sed -E 's#^tls://([^:]+):.*#\1#')" | awk 'NR==1 {print $1}' || true
}
write_firewall() {
  local ext proxy_ip fetch_net siem_net dns siem_port="" siem_ip
  ext="$(uplink)"; [ -n "$ext" ] || return 1
  proxy_ip="$(env_get EGRESS_PROXY_IP)"; proxy_ip="${proxy_ip:-172.30.20.10}"
  fetch_net="$(env_get FETCH_EGRESS_SUBNET)"; fetch_net="${fetch_net:-172.30.20.0/24}"
  siem_net="$(env_get SIEM_OUT_SUBNET)"; siem_net="${siem_net:-172.30.10.0/24}"
  dns="$(dns_ip)"; siem_ip="$(siem_ip)"
  [ -z "$SIEM_URL" ] || siem_port="${SIEM_URL##*:}"
  local dns_rules="" n
  if [ -n "$dns" ]; then
    for n in "$siem_net" "$fetch_net"; do dns_rules="$dns_rules \"-s $n -d $dns -p udp --dport 53 -j ACCEPT\" \"-s $n -d $dns -p tcp --dport 53 -j ACCEPT\""; done
  fi
  cat > "$BANK_DIR/firewall.sh" <<FW
#!/bin/sh
# PatchGate all-in-one bank server: host egress lockdown (written by installers/bank/install.sh).
# Every container packet leaving via the uplink ($ext) is dropped, except: replies, the fetcher's egress proxy
# (squid, vendor allow-list) to tcp/443, DNS from the fetcher network${siem_ip:+, the bank SIEM}. Tactical, MeshCentral,
# the connector, PatchGate web/db/signer: no internet. (The site's Docker networks are additionally internal.)
#   firewall.sh on | off | check | purge     (off = lockdown lifted for image builds; RUNBOOK rules stay)
set -e
C=$FW_CHAIN
set -- "\${1:-on}" "-s $siem_net ! -d $siem_net -j DROP" "-s $fetch_net ! -d $fetch_net -j DROP" \
  "-s $siem_net -d ${siem_ip:-127.0.0.1} -p tcp --dport ${siem_port:-6514} -j ACCEPT" "-s $proxy_ip -p tcp --dport 443 -j ACCEPT" $dns_rules
ACTION="\$1"; shift
case "\$ACTION" in
  on)
    iptables -n -L DOCKER-USER >/dev/null 2>&1 || iptables -N DOCKER-USER
    iptables -N \$C 2>/dev/null || iptables -F \$C
    iptables -A \$C -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    iptables -A \$C -s $proxy_ip -p tcp --dport 443 -j RETURN
    iptables -A \$C -s $fetch_net ${dns:+-d $dns }-p udp --dport 53 -j RETURN
    iptables -A \$C -s $fetch_net ${dns:+-d $dns }-p tcp --dport 53 -j RETURN
FW
  [ -n "$siem_ip" ] && echo "    iptables -A \$C -d $siem_ip -p tcp --dport $siem_port -j RETURN" >> "$BANK_DIR/firewall.sh"
  cat >> "$BANK_DIR/firewall.sh" <<FW
    iptables -A \$C -j DROP
    # RUNBOOK §4.3 subnet rules (also applied by install-patchgate.sh): web only to the SIEM, fetcher only via the proxy.
    for r in "\$@"; do
      # shellcheck disable=SC2086
      iptables -C DOCKER-USER \$r 2>/dev/null || iptables -I DOCKER-USER \$r
    done
    # The uplink chain first.
    while iptables -D DOCKER-USER -o $ext -j \$C 2>/dev/null; do :; done
    iptables -I DOCKER-USER 1 -o $ext -j \$C
    echo "egress lockdown on ($ext)" ;;
  off)
    while iptables -D DOCKER-USER -o $ext -j \$C 2>/dev/null; do :; done
    iptables -F \$C 2>/dev/null || true; iptables -X \$C 2>/dev/null || true
    echo "egress lockdown off" ;;
  purge)   # uninstall --purge: the lockdown AND the RUNBOOK subnet rules
    while iptables -D DOCKER-USER -o $ext -j \$C 2>/dev/null; do :; done
    iptables -F \$C 2>/dev/null || true; iptables -X \$C 2>/dev/null || true
    # shellcheck disable=SC2086
    for r in "\$@"; do while iptables -D DOCKER-USER \$r 2>/dev/null; do :; done; done
    echo "egress rules removed" ;;
  check)
    iptables -C DOCKER-USER -o $ext -j \$C 2>/dev/null && echo on || { echo off; exit 1; } ;;
esac
FW
  chmod 0700 "$BANK_DIR/firewall.sh"
}
firewall_on() {
  if [ "$NO_FIREWALL" = 1 ]; then
    EGRESS="NOT enforced (--no-firewall)"
    warn "!!! --no-firewall: the host egress lockdown is NOT applied. Tactical's networks are internal, but nothing on this host stops other container traffic to the internet. Re-run without --no-firewall to apply it."
    return 0
  fi
  write_firewall || { warn "no default route: nothing on this host can reach the internet (the fetcher neither)"; return 0; }
  "$BANK_DIR/firewall.sh" on | sed 's/^/    /'
  if [ -d /run/systemd/system ]; then
    cat > /etc/systemd/system/patchgate-bank-firewall.service <<UNIT
[Unit]
Description=PatchGate bank server egress lockdown (only the fetcher's egress proxy reaches the internet)
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BANK_DIR/firewall.sh on
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload; systemctl enable patchgate-bank-firewall.service >/dev/null 2>&1 || true
    ok "lockdown persistent (systemd: patchgate-bank-firewall.service)"
  else
    warn "no systemd: run $BANK_DIR/firewall.sh on after every reboot"
  fi
}
firewall_off() { [ -x "$BANK_DIR/firewall.sh" ] && "$BANK_DIR/firewall.sh" off | sed 's/^/    /'; return 0; }

# ------------------------------------------------------------------ 13. self-check
NJS_NET='const n=require("net");const t=(h,p)=>new Promise(r=>{const s=n.connect({host:h,port:p,timeout:4000});s.on("connect",()=>{s.destroy();r(true)});s.on("timeout",()=>{s.destroy();r(false)});s.on("error",()=>r(false))});Promise.all([t("1.1.1.1",443),t("140.82.112.3",443)]).then(a=>console.log(a.some(Boolean)?"REACHABLE":"blocked"))'
NJS_DNS='require("dns").lookup("github.com",e=>console.log(e?"blocked":"RESOLVED"))'
PY_NET='import socket
r="blocked"
for t in [("1.1.1.1",443),("140.82.112.3",443)]:
    try:
        socket.create_connection(t,timeout=4); r="REACHABLE"; break
    except OSError: pass
print(r)'
PY_DNS='import socket
try:
    socket.getaddrinfo("github.com",443); print("RESOLVED")
except OSError: print("blocked")'
probe() { # container -> "raw-ip-result dns-result"
  local c="$1" net dns
  if docker exec "$c" sh -c 'command -v python >/dev/null 2>&1'; then
    net="$(docker exec "$c" python -c "$PY_NET" 2>&1 | tail -1)"; dns="$(docker exec "$c" python -c "$PY_DNS" 2>&1 | tail -1)"
  elif docker exec "$c" sh -c 'command -v node >/dev/null 2>&1'; then
    net="$(docker exec "$c" node -e "$NJS_NET" 2>&1 | tail -1)"; dns="$(docker exec "$c" node -e "$NJS_DNS" 2>&1 | tail -1)"
  else
    # No interpreter: busybox nc / bash /dev/tcp; "untested" (never "blocked") when neither exists.
    net="$(docker exec "$c" sh -c 'if command -v nc >/dev/null 2>&1; then (nc -z -w 4 1.1.1.1 443 || nc -z -w 4 140.82.112.3 443) >/dev/null 2>&1 && echo REACHABLE || echo blocked
      elif command -v bash >/dev/null 2>&1; then timeout 6 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" >/dev/null 2>&1 && echo REACHABLE || echo blocked
      else echo untested; fi' 2>&1 | tail -1)"
    dns="$(docker exec "$c" sh -c 'if command -v nslookup >/dev/null 2>&1; then nslookup github.com >/dev/null 2>&1 && echo RESOLVED || echo blocked
      elif command -v getent >/dev/null 2>&1; then getent hosts github.com >/dev/null 2>&1 && echo RESOLVED || echo blocked; else echo untested; fi' 2>&1 | tail -1)"
  fi
  printf '%s %s' "${net:-error}" "${dns:-error}"
}
self_check() {
  phase "12. Self-check"
  local fails=0 c r code
  step "PatchGate smoke test (deploy/scripts/smoke-test.sh via the router)"
  SMOKE="FAIL"
  if (cd "$DEPLOY" && CA_FILE=tls/bank-ca.pem INTERNAL=1 SMOKE_WAIT_SIEM=120 ./scripts/smoke-test.sh "https://patchgate.$DOMAIN") 2>&1 | sed 's/^/    /'; [ "${PIPESTATUS[0]}" = 0 ]; then SMOKE=PASS; ok "smoke test PASS"
  else fails=$((fails + 1)); warn "smoke test reported failures (see above)"; fi

  step "Connector ACTIVE (PatchGate view) + self-check (site view)"
  CONNECTOR="not active"
  for _ in $(seq 1 36); do
    r="$(psql_q "select status || ' | ' || case when \"lastSeenAt\" > now() - interval '3 minutes' then 'online' else 'offline' end from \"Connector\" where name = '$(printf '%s' "$SITE_NAME" | sed "s/'/''/g")' order by \"enrolledAt\" desc limit 1" 2>/dev/null || true)"
    case "$r" in "ACTIVE | online") break ;; esac; sleep 5
  done
  if [ "$r" = "ACTIVE | online" ]; then CONNECTOR="ACTIVE, online"; ok "connector \"$SITE_NAME\": $CONNECTOR"; else fails=$((fails + 1)); warn "connector: ${r:-not found}"; fi
  if docker exec pg-site-connector node /opt/patchgate-connector/patchgate-connector.mjs check 2>&1 | grep -q '"healthy":true'; then ok "connector self-check healthy"
  else fails=$((fails + 1)); warn "connector self-check not healthy (docker exec pg-site-connector node /opt/patchgate-connector/patchgate-connector.mjs check)"; fi

  step "Through the SNI router ($LAN_IP:443, certificate checked against bank-ca.pem)"
  TACTICAL="unreachable"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --cacert "$BANK_DIR/tls/bank-ca.pem" --resolve "rmm.$DOMAIN:443:$LAN_IP" "https://rmm.$DOMAIN/" || true)"
  if [ "$code" = 200 ]; then TACTICAL="login page 200"; ok "https://rmm.$DOMAIN/ (Tactical login page) -> 200"; else fails=$((fails + 1)); warn "https://rmm.$DOMAIN/ -> ${code:-no answer}"; fi
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --cacert "$BANK_DIR/tls/bank-ca.pem" --resolve "patchgate.$DOMAIN:443:$LAN_IP" "https://patchgate.$DOMAIN/login" || true)"
  if [ "$code" = 200 ]; then ok "https://patchgate.$DOMAIN/login -> 200"; else fails=$((fails + 1)); warn "https://patchgate.$DOMAIN/login -> ${code:-no answer}"; fi
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --cacert "$BANK_DIR/tls/bank-ca.pem" --resolve "pg-cache.$DOMAIN:8443:$LAN_IP" "https://pg-cache.$DOMAIN:8443/repo/" || true)"
  case "$code" in 2*|3*|4*) ok "https://pg-cache.$DOMAIN:8443/repo/ -> $code (package cache answers, TLS valid)" ;; *) warn "package cache -> ${code:-no answer}" ;; esac
  # Self-healing after a reboot: install-site.sh installs the Tactical NATS watchdog (systemd timer, like
  # patchgate-bank-firewall.service; cron where there is no systemd). RUNBOOK "Tactical messaging down".
  if systemctl is-active --quiet patchgate-tactical-watchdog.timer 2>/dev/null; then ok "Tactical NATS watchdog active (patchgate-tactical-watchdog.timer)"
  elif [ -f /etc/cron.d/patchgate-tactical-watchdog ]; then ok "Tactical NATS watchdog active (cron)"
  else warn "Tactical NATS watchdog not active: trmm-nats is not restarted after a reboot (re-run with --upgrade)"; fi

  step "Egress lockdown proof (raw IP 1.1.1.1/140.82.112.3/8.8.8.8 + DNS github.com must FAIL)"
  EGRESS="proven"
  if [ "$("$BANK_DIR/firewall.sh" check 2>/dev/null || true)" = on ]; then ok "DOCKER-USER -> $FW_CHAIN active"; else EGRESS="NOT proven"; fails=$((fails + 1)); warn "egress lockdown chain not active"; fi
  for c in trmm-backend trmm-celery trmm-celerybeat trmm-websockets trmm-nats trmm-meshcentral trmm-nginx trmm-frontend; do
    docker inspect "$c" >/dev/null 2>&1 || continue
    r="$(probe "$c")"; info "$c -> internet: ${r% *}, DNS: ${r#* }"
    case "$r" in *REACHABLE*|*RESOLVED*) EGRESS="BROKEN"; fails=$((fails + 1)) ;; esac
  done
  for c in pg-site-connector pg-site-egress pg-site-ingress; do
    docker inspect "$c" >/dev/null 2>&1 || continue
    r="$(probe "$c")"; info "$c -> internet: ${r% *}"
    case "${r% *}" in *REACHABLE*) EGRESS="BROKEN"; fails=$((fails + 1)) ;; esac
  done
  for c in web-1 signer fetcher; do
    r="$(dcp exec -T "$c" node -e "$NJS_NET" 2>&1 | tail -1 || true)"; info "patchgate $c -> internet (direct): $r"
    case "$r" in *REACHABLE*) EGRESS="BROKEN"; fails=$((fails + 1)) ;; esac
  done
  r="$(dcp exec -T fetcher node -e "fetch('https://www.catalog.update.microsoft.com/Home.aspx',{method:'HEAD',redirect:'manual'}).then(r=>console.log('HTTP '+r.status)).catch(e=>console.log('FAIL '+((e.cause&&e.cause.code)||e.message)))" 2>&1 | tail -1 || true)"
  case "$r" in "HTTP "[1-4]*) ok "fetcher -> https://www.catalog.update.microsoft.com via the egress proxy: $r (allow-listed)" ;;
    *) EGRESS="${EGRESS/proven/proven, BUT fetcher blocked}"; fails=$((fails + 1)); warn "fetcher -> Microsoft catalog via proxy: $r" ;; esac
  r="$(dcp exec -T fetcher node -e "fetch('https://example.com/',{method:'HEAD'}).then(r=>console.log('HTTP '+r.status)).catch(e=>console.log('refused ('+((e.cause&&e.cause.code)||e.message)+')'))" 2>&1 | tail -1 || true)"
  info "fetcher -> https://example.com (NOT allow-listed): $r"
  case "$r" in "HTTP "*) EGRESS="BROKEN"; fails=$((fails + 1)); warn "the egress proxy let a non-allow-listed host through" ;; esac
  [ "$EGRESS" = proven ] && ok "only the fetcher (via the squid allow-list) reaches the internet"
  CHECK_FAILS=$fails
}
SMOKE="not run"; CONNECTOR="?"; TACTICAL="?"; EGRESS="?"; CHECK_FAILS=0

# ------------------------------------------------------------------ logins + summary
write_logins() {
  local f="$BANK_DIR/logins.txt" tmp key upn role what pwf
  tmp="$(mktemp "$BANK_DIR/.logins.XXXXXX")"; chmod 0600 "$tmp"
  {
    echo "PatchGate all-in-one bank server — sign-in details (KEEP PRIVATE; root only)"
    echo "PatchGate: https://patchgate.$DOMAIN/      Tactical (sealed, emergency only): https://rmm.$DOMAIN/"
    echo "Temporary passwords must be changed at the first sign-in. Delete this file once everyone has signed in."
    echo
    for key in operator admin1 admin2 auditor; do
      case "$key" in
        operator) upn="$OP_EMAIL"; role="ADMIN (platform: all banks on this server; connectors, enrolment)"; pwf=platform-operator.pw ;;
        admin1) upn="$A1_EMAIL"; role="ADMIN of $BANK_NAME (maker or checker)"; pwf=admin1.pw ;;
        admin2) upn="$A2_EMAIL"; role="ADMIN of $BANK_NAME (checker: approves the other admin's changes)"; pwf=admin2.pw ;;
        auditor) upn="$AU_EMAIL"; role="AUDITOR of $BANK_NAME (read-only)"; pwf=auditor.pw ;;
      esac
      [ -n "$upn" ] || continue
      what="$( [ -s "$BANK_DIR/secret/$pwf" ] && cat "$BANK_DIR/secret/$pwf" || echo "(set earlier; reset it in Administration -> Users)")"
      printf '[%s]  %s\n  sign-in name : %s\n  temp password: %s\n\n' "$key" "$role" "$upn" "$what"
    done
    echo "[tactical-break-glass]  user tacticaladmin — Tactical is SEALED (dashboard login blocked)."
    echo "  password: TRMM_PASS in $SITE_DIR/tactical.env (root only). Emergency only:"
    echo "  sudo $SITE_DIR/runtime/install-site.sh --break-glass on   (alerted in PatchGate)  ... --break-glass off"
  } > "$tmp"
  mv -f "$tmp" "$f"
}
summary() {
  end_phase
  local fp; fp="$(job_key_fp)"; SELF="$SOURCE_DIR/installers/bank/install.sh"
  cat <<TXT

${C_B}==================== PatchGate all-in-one bank server ====================${C_0}
  PatchGate        https://patchgate.$DOMAIN/          (version $VERSION)
  Tactical RMM     https://rmm.$DOMAIN/  (api./mesh.$DOMAIN)  sealed: patches go through PatchGate only
  Package cache    https://pg-cache.$DOMAIN:8443/repo
  Server LAN IP    $LAN_IP   -> bank DNS: patchgate/rmm/api/mesh/pg-cache.$DOMAIN = $LAN_IP
  TLS              $TLS_SOURCE  (CA: $BANK_DIR/tls/bank-ca.pem)
  Logins           $BANK_DIR/logins.txt   (root only, mode 600)
  Bank             $BANK_NAME ($BANK_SLUG); "Approval required" is ON by default: every change needs the
                   second ADMIN's approval (maker != checker). An Admin can switch it per bank in
                   Administration -> Banks.
  Job-key pin      ${fp:-?}
  Quarantine       QUARANTINE_HOURS=$(env_get QUARANTINE_HOURS) (go-live recommendation: 48; edit $DEPLOY/.env.production, then --upgrade)

  Health           PatchGate smoke test: $SMOKE | connector: $CONNECTOR | Tactical: $TACTICAL | egress lockdown: $EGRESS

  Bank PCs (one step each):
    1. copy $SITE_DIR/pc/ to a read-only share (e.g. \\\\fileserver\\patchgate\$) or a USB stick
    2. on each PC double-click Install-PatchGateAgent.cmd (asks for admin rights), or in an admin PowerShell:
         powershell -ExecutionPolicy Bypass -File <folder>\\Install-PatchGateAgent.ps1 -ConfigFile <folder>\\patchgate-pc.json
       It trusts bank-ca.pem, adds hosts entries for the 5 names -> $LAN_IP only if DNS does not resolve them,
       and installs the Tactical agent (SHA-256 checked). PC install token renewal: sudo $SITE_DIR/runtime/install-site.sh --pc-token
       (then sudo $SELF to refresh siteIp in the kit).

  Your browser PC / admin workstation without bank DNS: add this line to its hosts file
    (Windows: C:\Windows\System32\drivers\etc\hosts as Administrator; Linux/macOS: /etc/hosts)
         $LAN_IP $(names | paste -sd' ' -)
    and trust $BANK_DIR/tls/bank-ca.pem (Windows: certlm.msc -> Trusted Root Certification Authorities -> Import).

  A PC that already has a Tactical agent from an earlier test: Install-PatchGateAgent.cmd re-points it (-Force);
  if it still shows the old site, uninstall the old agent first (admin cmd), then run the .cmd again:
         "C:\Program Files\TacticalAgent\unins000.exe" /VERYSILENT
         "C:\Program Files\Mesh Agent\MeshAgent.exe" -fulluninstall

  Test now:
    1. Open https://patchgate.$DOMAIN/ and sign in as $A1_EMAIL (password in $BANK_DIR/logins.txt; choose a new one).
    2. Copy $SITE_DIR/pc/ to the Windows PC (share or USB) and double-click Install-PatchGateAgent.cmd.
    3. PatchGate -> Endpoints -> "Sync agents now": the PC appears.
    4. Endpoints -> "Request scan of all PCs": its missing updates appear under Patches.
    5. Patches -> pick an update -> create a change request for $BANK_NAME (Ring0-Test) and submit it.
    6. Sign in as $A2_EMAIL (the checker) and approve it (the maker cannot approve its own request).
    7. Start the deployment of the approved request.
    8. Watch the progress on the change request / Endpoints page (the PC downloads from pg-cache.$DOMAIN:8443).

  Later:  sudo $SELF --status | --upgrade [--ref <tag>] | --uninstall [--purge]
  Log:    $LOG_FILE

  Time per phase:
TXT
  local p; for p in "${PHASES[@]}"; do echo "    $p"; done
  echo "    total: $(( ($(date +%s) - RUN_T0) / 60 ))m$(( ($(date +%s) - RUN_T0) % 60 ))s"
  if [ ${#WARNINGS[@]} -gt 0 ]; then
    printf '\n  %sAttention:%s\n' "$C_Y" "$C_0"; local w; for w in "${WARNINGS[@]}"; do printf '   - %s\n' "$w"; done
  fi
  if [ "$CHECK_FAILS" = 0 ]; then printf '\n  Result: %sPASS%s\n' "$C_G" "$C_0"; else printf '\n  Result: %sFAIL%s (%s check(s); re-run to resume)\n' "$C_R" "$C_0" "$CHECK_FAILS"; fi
}

# ------------------------------------------------------------------ modes
do_install() {
  preflight
  bootstrap_source
  collect_answers
  setup_tls
  firewall_off   # re-run: builds need internet
  install_server
  setup_bank
  build_bundle
  install_site_pass1
  start_edge
  enrol_site
  pc_kit
  phase "11. Egress lockdown (DOCKER-USER)"
  firewall_on
  write_logins
  save_state
  self_check
  summary
  [ "$CHECK_FAILS" = 0 ] || exit 4
}

do_upgrade() {
  [ -f "$STATE" ] && [ -f "$DEPLOY/.env.production" ] || die "nothing installed yet (run without --upgrade first)"
  preflight
  if [ "$MANAGED_CLONE" = 1 ] && [ -z "${PG_BANK_UPDATED:-}" ]; then
    phase "2. Source update"
    clone_or_update; save_state
    # Continue with the NEW version's installer (it knows the new release's steps).
    exec env PG_BANK_UPDATED=1 PG_BANK_OLD_VERSION="$VERSION" bash "$SOURCE_DIR/installers/bank/install.sh" "${ORIG_ARGS[@]}"
  fi
  local old="${PG_BANK_OLD_VERSION:-$VERSION}"; VERSION=""
  bootstrap_source
  info "upgrade $old -> $VERSION"
  firewall_off
  phase "5. PatchGate upgrade (backup -> migrate -> rolling restart)"
  run_child platform-operator.pw env PG_REGISTRY="" bash "$SOURCE_DIR/installers/server/install-patchgate.sh" \
    --upgrade "$VERSION" --source-dir "$SOURCE_DIR" --skip-smoke --non-interactive || die "PatchGate upgrade failed (previous version keeps running; RUNBOOK §10)"
  build_bundle
  phase "8. Site upgrade (install-site.sh --upgrade)"
  run_child tactical-breakglass.pw bash "$SOURCE_DIR/installers/site/install-site.sh" --upgrade "$BUNDLE_TGZ" --online --no-lockdown --non-interactive \
    || die "site upgrade failed (log /var/log/patchgate-site-install.log)"
  start_edge
  phase "10. Connector allow-list"
  allowlist
  pc_kit
  phase "11. Egress lockdown"
  firewall_on
  save_state
  self_check
  summary
  [ "$CHECK_FAILS" = 0 ] || exit 4
}

do_status() {
  [ -f "$STATE" ] || die "nothing installed ($STATE missing)"
  step "PatchGate (patchgate.$DOMAIN)"
  bash "$SOURCE_DIR/installers/server/install-patchgate.sh" --status 2>&1 | grep -v '^=====' | sed 's/^/  /' || true
  step "Bank site"
  bash "$SITE_DIR/runtime/install-site.sh" --status 2>&1 | grep -v '^=====' | sed 's/^/  /' || true
  step "Router + lockdown"
  info "$EDGE_NAME: $(docker inspect -f '{{.State.Status}} (restarts {{.RestartCount}})' "$EDGE_NAME" 2>/dev/null || echo missing)"
  info "egress lockdown: $("$BANK_DIR/firewall.sh" check 2>/dev/null || echo off)"
  info "connector: $(psql_q "select name || ' ' || status || ' lastSeen ' || coalesce(to_char(\"lastSeenAt\",'YYYY-MM-DD HH24:MI:SS'),'never') from \"Connector\" order by \"enrolledAt\"" 2>/dev/null | tr '\n' ';' || echo unknown)"
  info "logins file: $BANK_DIR/logins.txt   log: $LOG_FILE"
}

do_uninstall() {
  [ -f "$STATE" ] || die "nothing installed ($STATE missing)"
  step "Uninstall the PatchGate bank server"
  local p=()
  if [ "$PURGE" = 1 ]; then
    warn "--purge deletes PatchGate's database + secrets, Tactical (all agents/history), the connector key and $BANK_DIR"
    if [ "$ASSUME_YES" != 1 ]; then
      [ "$NONINTERACTIVE" != 1 ] && [ -r /dev/tty ] || die "--purge needs --yes in non-interactive mode"
      local a=""; printf '    Type the domain (%s) to confirm: ' "$DOMAIN" >/dev/tty; IFS= read -r a </dev/tty || true
      [ "$a" = "$DOMAIN" ] || die "not confirmed — nothing deleted"
    fi
    p=(--purge --yes)
  fi
  if [ "$PURGE" = 1 ] && [ -x "$BANK_DIR/firewall.sh" ]; then "$BANK_DIR/firewall.sh" purge | sed 's/^/    /'; else firewall_off; fi
  [ -f /etc/systemd/system/patchgate-bank-firewall.service ] && { systemctl disable patchgate-bank-firewall.service >/dev/null 2>&1 || true; rm -f /etc/systemd/system/patchgate-bank-firewall.service; }
  docker rm -f "$EDGE_NAME" >/dev/null 2>&1 || true; ok "router removed"
  [ -x "$SITE_DIR/runtime/install-site.sh" ] && bash "$SITE_DIR/runtime/install-site.sh" --uninstall "${p[@]}" --non-interactive 2>&1 | sed 's/^/  /'
  bash "$SOURCE_DIR/installers/server/install-patchgate.sh" --uninstall "${p[@]}" --non-interactive 2>&1 | sed 's/^/  /'
  if [ "$HOSTS_ENTRY" = 1 ]; then
    local h; h="$(grep -v "$HOSTS_MARK\$" /etc/hosts || true)"; printf '%s\n' "$h" > /etc/hosts && ok "hosts entry removed"
  fi
  if [ "$PURGE" = 1 ]; then
    case "$SOURCE_DIR" in "$BANK_DIR"/*) ;; *) info "source checkout $SOURCE_DIR kept" ;; esac
    rm -rf "${BANK_DIR:?}"; ok "purged $BANK_DIR"
  else
    ok "data kept (volumes, $PG_INSTALL_DIR, $SITE_DIR, $BANK_DIR). Re-install: run the installer again"
  fi
}

main() {
  parse_args "$@"
  [ "$(id -u)" = 0 ] || die "run as root (sudo ...)"
  setup_logging
  RUN_T0=$(date +%s)
  load_state
  case "$MODE" in
    install) do_install ;;
    upgrade) do_upgrade ;;
    status) do_status ;;
    uninstall) do_uninstall ;;
  esac
}
RUN_T0=0
SELF="$BANK_DIR/src/installers/bank/install.sh"
main "$@"
