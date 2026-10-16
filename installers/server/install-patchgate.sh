#!/usr/bin/env bash
# PatchGate platform installer — OUR server (Ubuntu 22.04 / 24.04, Debian 12). Run as root.
#
#   sudo ./install-patchgate.sh                        # interactive first install (or safe re-run)
#   sudo ./install-patchgate.sh --non-interactive --domain patchgate.example.com \
#        --admin-email admin@example.com --admin-name "First Admin" --tls self-signed \
#        --image-source registry --registry registry.example.com --version 1.0.0
#   sudo ./install-patchgate.sh --upgrade 1.1.0        # pull/build -> backup -> migrate -> rolling restart -> smoke
#   sudo ./install-patchgate.sh --status
#   sudo ./install-patchgate.sh --uninstall [--purge]  # keeps data unless --purge (asks for confirmation)
#
# What it does (docs/RUNBOOK.md §3-§5): preflight -> Docker Engine + compose plugin (official repo) ->
# copies deploy/ to /opt/patchgate/deploy -> generate-secrets.sh -> .env.production from your answers ->
# TLS -> host firewall egress rules (§4.3, asks first) -> images -> migrate -> up -d -> health ->
# first platform admin (temporary password shown ONCE, never logged) -> smoke-test.sh -> summary.
# Re-running it is safe: existing secrets, .env.production, certificates, data and users are kept.
# Log: /var/log/patchgate-install.log (secrets are never written to it).
set -euo pipefail
umask 027

INSTALLER_VERSION="1.0.0"
DOCKER_APT_KEY_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"   # Docker Inc. apt release key (download.docker.com/linux/*/gpg)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${PATCHGATE_INSTALL_LOG:-/var/log/patchgate-install.log}"

# ------------------------------------------------------------------ settings (flags > env > defaults)
MODE="install"
NONINTERACTIVE="${PG_NONINTERACTIVE:-0}"
ASSUME_YES=0
PURGE=0
INSTALL_DIR="${PG_INSTALL_DIR:-/opt/patchgate}"
DOMAIN="${PG_DOMAIN:-}"
ADMIN_EMAIL="${PG_ADMIN_EMAIL:-}"
ADMIN_NAME="${PG_ADMIN_NAME:-}"
TLS_MODE="${PG_TLS:-}"                 # existing | self-signed
TLS_CERT="${PG_TLS_CERT:-}"
TLS_KEY="${PG_TLS_KEY:-}"
IMAGE_SOURCE="${PG_IMAGE_SOURCE:-}"    # registry | build
REGISTRY="${PG_REGISTRY-}"             # e.g. registry.example.com/patchgate (empty = local image names)
VERSION="${PG_VERSION:-}"
SOURCE_DIR="${PG_SOURCE_DIR:-}"        # repo root (contains deploy/ and patchgate-web/)
IMAGE_ARCHIVE="${PG_IMAGE_ARCHIVE:-}"  # optional `docker save` tar to load first (offline servers)
SIEM_URL="${PG_SIEM_URL:-}"
SIEM_CA="${PG_SIEM_CA:-}"
CODESIGN_CA="${PG_CODESIGN_CA:-}"
BACKUP_RECIPIENT="${PG_BACKUP_RECIPIENT:-}"
APPLY_FIREWALL="${PG_APPLY_FIREWALL:-ask}"   # ask | yes | no
DNS_IP="${PG_DNS_IP:-}"
SIEM_IP="${PG_SIEM_IP:-}"
SKIP_SMOKE=0
UPGRADE_VERSION=""
# Optional nginx host binds/ports (HTTP_BIND/HTTP_PORT/HTTPS_BIND/HTTPS_PORT in .env.production). Used by the
# all-in-one bank installer (installers/bank/install.sh): its local SNI router owns :443, PatchGate's nginx
# then listens on e.g. 127.0.0.1:8444. Empty = keep the compose defaults (0.0.0.0:80 / 0.0.0.0:443).
NGINX_BINDS="HTTP_BIND=${PG_HTTP_BIND:-} HTTP_PORT=${PG_HTTP_PORT:-} HTTPS_BIND=${PG_HTTPS_BIND:-} HTTPS_PORT=${PG_HTTPS_PORT:-}"

STATE_FILE=""   # set after INSTALL_DIR is final
DEPLOY=""
DC=()

# ------------------------------------------------------------------ output helpers
if [ -t 1 ]; then C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[1m'; C_0=$'\e[0m'; else C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""; fi
step() { printf '\n%s==> %s%s\n' "$C_B" "$*" "$C_0"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %sOK%s  %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '    %sWARN%s %s\n' "$C_Y" "$C_0" "$*"; WARNINGS+=("$*"); }
die()  { printf '\n%sERROR%s %s\n' "$C_R" "$C_0" "$*" >&2; printf '      Log: %s\n' "$LOG_FILE" >&2; exit 1; }
WARNINGS=()
# Read one field of /etc/os-release WITHOUT sourcing it into this shell (it defines VERSION, NAME, ...).
# shellcheck disable=SC1091
os_field() { ( . /etc/os-release 2>/dev/null && printf "%s" "${!1:-}" ); }

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'TXT'

Options (each also settable via the env var in brackets):
  --domain NAME            public DNS name of PatchGate                          [PG_DOMAIN]
  --admin-email UPN        first platform admin (sign-in name)                   [PG_ADMIN_EMAIL]
  --admin-name "NAME"      display name of the first admin                       [PG_ADMIN_NAME]
  --tls existing|self-signed                                                     [PG_TLS]
  --cert FILE --key FILE   with --tls existing: full chain + private key (PEM)   [PG_TLS_CERT, PG_TLS_KEY]
  --image-source registry|build                                                  [PG_IMAGE_SOURCE]
  --registry PREFIX        registry/namespace, e.g. registry.example.com/pg      [PG_REGISTRY]
  --version VER            image tag (web and tools always use the same)         [PG_VERSION]
  --source-dir DIR         repo root (deploy/ + patchgate-web/); default: ../..  [PG_SOURCE_DIR]
  --image-archive FILE|DIR `docker save` tar, or a release images/ dir (offline) [PG_IMAGE_ARCHIVE]
  --siem-url tls://H:P     platform SIEM (mandatory before go-live)              [PG_SIEM_URL]
  --siem-ca FILE           CA of the SIEM certificate                            [PG_SIEM_CA]
  --codesign-ca FILE       Authenticode root bundle (RUNBOOK §4.4)               [PG_CODESIGN_CA]
  --backup-recipient age1… backup public key (private key stays offline)         [PG_BACKUP_RECIPIENT]
  --apply-firewall / --no-firewall   apply the RUNBOOK §4.3 egress rules or not  [PG_APPLY_FIREWALL]
  --dns-ip IP --siem-ip IP values used in the firewall rules                     [PG_DNS_IP, PG_SIEM_IP]
  --install-dir DIR        default /opt/patchgate                                [PG_INSTALL_DIR]
  --non-interactive        never ask; fail if a required value is missing        [PG_NONINTERACTIVE=1]
  --yes                    confirm destructive prompts (with --purge)
  --skip-smoke             do not run smoke-test.sh
TXT
}

need_val() { [ $# -ge 2 ] && [ -n "$2" ] || die "option $1 needs a value"; }
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --domain) need_val "$@"; DOMAIN="$2"; shift 2 ;;
      --admin-email) need_val "$@"; ADMIN_EMAIL="$2"; shift 2 ;;
      --admin-name) need_val "$@"; ADMIN_NAME="$2"; shift 2 ;;
      --tls) need_val "$@"; TLS_MODE="$2"; shift 2 ;;
      --cert) need_val "$@"; TLS_CERT="$2"; shift 2 ;;
      --key) need_val "$@"; TLS_KEY="$2"; shift 2 ;;
      --image-source) need_val "$@"; IMAGE_SOURCE="$2"; shift 2 ;;
      --registry) [ $# -ge 2 ] || die "--registry needs a value"; REGISTRY="$2"; shift 2 ;;
      --version) need_val "$@"; VERSION="$2"; shift 2 ;;
      --source-dir) need_val "$@"; SOURCE_DIR="$2"; shift 2 ;;
      --image-archive) need_val "$@"; IMAGE_ARCHIVE="$2"; shift 2 ;;
      --siem-url) need_val "$@"; SIEM_URL="$2"; shift 2 ;;
      --siem-ca) need_val "$@"; SIEM_CA="$2"; shift 2 ;;
      --codesign-ca) need_val "$@"; CODESIGN_CA="$2"; shift 2 ;;
      --backup-recipient) need_val "$@"; BACKUP_RECIPIENT="$2"; shift 2 ;;
      --apply-firewall) APPLY_FIREWALL=yes; shift ;;
      --no-firewall) APPLY_FIREWALL=no; shift ;;
      --dns-ip) need_val "$@"; DNS_IP="$2"; shift 2 ;;
      --siem-ip) need_val "$@"; SIEM_IP="$2"; shift 2 ;;
      --install-dir) need_val "$@"; INSTALL_DIR="$2"; shift 2 ;;
      --non-interactive) NONINTERACTIVE=1; shift ;;
      --yes|-y) ASSUME_YES=1; shift ;;
      --skip-smoke) SKIP_SMOKE=1; shift ;;
      --upgrade) need_val "$@"; MODE=upgrade; UPGRADE_VERSION="$2"; shift 2 ;;
      --status) MODE=status; shift ;;
      --uninstall) MODE=uninstall; shift ;;
      --purge) PURGE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done
}

# Prompts read from the terminal (also works when the script itself arrives on stdin).
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
confirm() { # "question" default(y|n) -> 0 = yes
  local q="$1" def="${2:-n}" a=""
  if [ "$NONINTERACTIVE" = 1 ] || [ ! -r /dev/tty ]; then [ "$def" = y ]; return; fi
  printf '    %s [%s]: ' "$q" "$([ "$def" = y ] && echo Y/n || echo y/N)" >/dev/tty
  IFS= read -r a </dev/tty || true
  a="${a:-$def}"; [[ "$a" =~ ^[Yy] ]]
}

# ------------------------------------------------------------------ logging (fd 3 = terminal only, never logged)
setup_logging() {
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"; chmod 0600 "$LOG_FILE"
  exec 3>&1
  exec > >(tee -a "$LOG_FILE") 2>&1
  printf '\n===== %s install-patchgate.sh %s (mode=%s) =====\n' "$(date -u +%FT%TZ)" "$INSTALLER_VERSION" "$MODE"
}

# ------------------------------------------------------------------ state (non-secret answers, for re-runs)
load_state() {
  STATE_FILE="$INSTALL_DIR/installer.conf"
  DEPLOY="$INSTALL_DIR/deploy"
  [ -f "$STATE_FILE" ] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      DOMAIN) DOMAIN="${DOMAIN:-$v}" ;;
      ADMIN_EMAIL) ADMIN_EMAIL="${ADMIN_EMAIL:-$v}" ;;
      TLS_MODE) TLS_MODE="${TLS_MODE:-$v}" ;;
      IMAGE_SOURCE) IMAGE_SOURCE="${IMAGE_SOURCE:-$v}" ;;
      REGISTRY) [ -n "${PG_REGISTRY+x}" ] || [ -n "$REGISTRY" ] || REGISTRY="$v" ;;
      VERSION) VERSION="${VERSION:-$v}" ;;
      SOURCE_DIR) SOURCE_DIR="${SOURCE_DIR:-$v}" ;;
      ADMIN_CREATED) ADMIN_CREATED="$v" ;;
      HOSTS_ENTRY) HOSTS_ENTRY="$v" ;;
    esac
  done < "$STATE_FILE"
}
ADMIN_CREATED=""
HOSTS_ENTRY=""
save_state() {
  local tmp; tmp="$(mktemp "$INSTALL_DIR/.installer.XXXXXX")"
  {
    echo "# written by install-patchgate.sh — non-secret answers for re-runs/upgrades"
    echo "DOMAIN=$DOMAIN"; echo "ADMIN_EMAIL=$ADMIN_EMAIL"; echo "TLS_MODE=$TLS_MODE"
    echo "IMAGE_SOURCE=$IMAGE_SOURCE"; echo "REGISTRY=$REGISTRY"; echo "VERSION=$VERSION"
    echo "SOURCE_DIR=$SOURCE_DIR"; echo "ADMIN_CREATED=$ADMIN_CREATED"; echo "HOSTS_ENTRY=$HOSTS_ENTRY"
    echo "INSTALLER_VERSION=$INSTALLER_VERSION"
  } > "$tmp"
  chmod 0640 "$tmp"; mv -f "$tmp" "$STATE_FILE"
}

image_ref() { # web|tools|signer|egress-proxy|backup -> full image reference
  local name="patchgate-$1"
  if [ -n "$REGISTRY" ]; then echo "${REGISTRY%/}/$name:$VERSION"; else echo "$name:$VERSION"; fi
}
# Helper images (signer, egress proxy, backup): the scanned + signed release images in registry mode,
# built from deploy/ (":local") in build mode.
helper_ref() { if [ "$IMAGE_SOURCE" = build ]; then echo "patchgate-$1:local"; else image_ref "$1"; fi; }
# Docker refuses a container CPU limit above the host's CPU count ("range of CPUs is from 0.01 to N").
# Cap the compose defaults (DB 4, web 2, fetcher 2) to this host unless the admin set a value.
fit_cpu_limits() {
  local n var def cur
  n="$(nproc)"
  for var in DB_CPUS:4 WEB_CPUS:2 FETCHER_CPUS:2; do
    def="${var#*:}"; var="${var%%:*}"
    cur="$(env_get "$var")"
    if [ -z "$cur" ] && [ "$def" -gt "$n" ]; then
      env_set "$var" "$n"
      info "$var=$n (this host has $n CPUs; compose default $def)"
    fi
  done
}
set_image_env() {
  env_set PATCHGATE_IMAGE "$(image_ref web)"
  env_set PATCHGATE_TOOLS_IMAGE "$(image_ref tools)"
  env_set SIGNER_IMAGE "$(helper_ref signer)"
  env_set EGRESS_PROXY_IMAGE "$(helper_ref egress-proxy)"
  env_set BACKUP_IMAGE "$(helper_ref backup)"
}

# ------------------------------------------------------------------ preflight
preflight() {
  step "Preflight checks"
  [ "$(id -u)" = 0 ] || die "run as root (sudo $0 ...)"
  [ "$(uname -m)" = x86_64 ] || die "x86-64 required (found $(uname -m))"
  ensure_tools
  [ -r /etc/os-release ] || die "cannot read /etc/os-release"
  local ID VERSION_ID PRETTY_NAME; ID="$(os_field ID)"; VERSION_ID="$(os_field VERSION_ID)"; PRETTY_NAME="$(os_field PRETTY_NAME)"
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|debian:12) ok "OS ${PRETTY_NAME:-$ID $VERSION_ID}" ;;
    *) if [ "${PG_ALLOW_ANY_OS:-0}" = 1 ]; then warn "untested OS ${PRETTY_NAME:-unknown} (PG_ALLOW_ANY_OS=1)"
       else die "supported: Ubuntu 22.04/24.04, Debian 12 (found ${PRETTY_NAME:-unknown}; PG_ALLOW_ANY_OS=1 to try anyway)"; fi ;;
  esac
  local cpus mem_gb disk_gb probe_dir
  cpus="$(nproc)"; mem_gb="$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)"
  probe_dir="$INSTALL_DIR"; while [ ! -d "$probe_dir" ]; do probe_dir="$(dirname "$probe_dir")"; done
  disk_gb="$(df -Pk "$probe_dir" | awk 'NR==2 {printf "%d", $4/1024/1024}')"
  [ "$cpus" -ge 2 ] || die "at least 2 CPUs required (found $cpus; 8 recommended, RUNBOOK §1.2)"
  if [ "$cpus" -ge 4 ]; then ok "$cpus CPUs"; else warn "$cpus CPUs (8 recommended for tier S)"; fi
  [ "$mem_gb" -ge 7 ] || die "at least 8 GB RAM required (found ${mem_gb} GB; 16 GB recommended)"
  if [ "$mem_gb" -ge 15 ]; then ok "${mem_gb} GB RAM"; else warn "${mem_gb} GB RAM (16 GB recommended; lower WEB/DB/FETCHER_MEMORY in .env.production)"; fi
  [ "$disk_gb" -ge 20 ] || die "at least 20 GB free disk under $probe_dir required (found ${disk_gb} GB)"
  if [ "$disk_gb" -ge 100 ]; then ok "${disk_gb} GB free disk"; else warn "${disk_gb} GB free disk (100 GB + package store recommended)"; fi
  if [ "$MODE" = install ]; then check_ports; fi
}

our_nginx_running() {
  [ -f "$DEPLOY/.env.production" ] && command -v docker >/dev/null 2>&1 || return 1
  [ -n "$(cd "$DEPLOY" && "${DC[@]}" ps -q nginx 2>/dev/null)" ]
}
check_ports() {
  if our_nginx_running; then ok "ports 80/443 are served by PatchGate's own nginx (re-run)"; return; fi
  local p busy="" hp hsp
  hp="${PG_HTTP_PORT:-}"; hsp="${PG_HTTPS_PORT:-}"
  if [ -f "$DEPLOY/.env.production" ]; then hp="${hp:-$(env_get HTTP_PORT)}"; hsp="${hsp:-$(env_get HTTPS_PORT)}"; fi
  for p in "${hp:-80}" "${hsp:-443}"; do
    if ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then busy="$busy $p"; fi
  done
  [ -z "$busy" ] || die "port(s)$busy already in use: stop the other service first (ss -ltnp)"
  ok "ports ${hp:-80} and ${hsp:-443} are free"
}

check_dns() {
  local resolved mine
  resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
  mine="$(hostname -I 2>/dev/null || true)"
  if [ -z "$resolved" ]; then
    warn "DNS: $DOMAIN does not resolve yet — create an A record to this server's public IP before banks connect"
    return 1
  fi
  local ip match=0
  for ip in $resolved; do case " $mine " in *" $ip "*) match=1 ;; esac; [ "$ip" = 127.0.0.1 ] && match=1; done
  if [ "$match" = 1 ]; then ok "DNS: $DOMAIN -> $resolved"; else
    warn "DNS: $DOMAIN -> $resolved, not an address of this host ($mine) — fine behind a load balancer/NAT, otherwise fix the A record"
  fi
  return 0
}

ensure_tools() {
  local missing=()
  local t
  for t in curl openssl gpg ss getent tar awk sed; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
  [ ${#missing[@]} -eq 0 ] && return 0
  info "installing base tools: ${missing[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl openssl gnupg iproute2 >/dev/null
}

# ------------------------------------------------------------------ Docker Engine + compose plugin (official repo)
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
install_docker() {
  step "Docker Engine"
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "Docker already installed"
  else
    info "installing Docker Engine + compose plugin from download.docker.com"
    local ID VERSION_CODENAME; ID="$(os_field ID)"; VERSION_CODENAME="$(os_field VERSION_CODENAME)"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg >/dev/null
    install -m 0755 -d /etc/apt/keyrings
    # Pinned: Docker's release-signing key (docs.docker.com/engine/install). Any other key = refuse.
    dk_key="$(mktemp)"
    curl -fsSL --proto "=https" --tlsv1.2 "https://download.docker.com/linux/${ID}/gpg" -o "$dk_key"
    dk_fpr="$(gpg --show-keys --with-colons "$dk_key" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
    [ "$dk_fpr" = "$DOCKER_APT_KEY_FPR" ] || { rm -f "$dk_key"; die "Docker apt key fingerprint mismatch (got ${dk_fpr:-none}, expected $DOCKER_APT_KEY_FPR): not installing Docker"; }
    gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg < "$dk_key"; rm -f "$dk_key"
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
    ok "Docker installed"
  fi
  start_docker
  local dv cv
  dv="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 0)"
  cv="$(docker compose version --short 2>/dev/null | sed 's/^v//' || echo 0)"
  version_ge "$dv" 26.0.0 || die "Docker Engine >= 26 required (found $dv)"
  version_ge "$cv" 2.24.0 || die "Docker Compose >= 2.24 required (found $cv)"
  ok "Docker $dv, Compose $cv"
}
start_docker() {
  docker info >/dev/null 2>&1 && return 0
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  docker info >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
  local _
  for _ in $(seq 1 10); do docker info >/dev/null 2>&1 && return 0; sleep 2; done
  if [ ! -d /run/systemd/system ] && ! pgrep -x dockerd >/dev/null 2>&1; then
    # No init system (e.g. a container used for testing): run the daemon in the background.
    info "no systemd: starting dockerd in the background (log /var/log/dockerd.log)"
    # </dev/null 3>&-: the daemon must not inherit our stdin (curl | bash) or fd 3 (terminal), otherwise
    # whoever reads our output (| tee, docker exec) never sees EOF and waits forever.
    nohup dockerd >/var/log/dockerd.log 2>&1 </dev/null 3>&- &
  fi
  for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && return 0; sleep 2; done
  die "Docker daemon did not start (systemctl status docker / journalctl -u docker)"
}

# ------------------------------------------------------------------ answers
collect_answers() {
  step "Configuration"
  ask DOMAIN "Public DNS name of PatchGate (e.g. patchgate.example.com)"
  DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
  [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "invalid domain: $DOMAIN"
  if [ -z "$ADMIN_CREATED" ]; then
    ask ADMIN_EMAIL "First platform admin e-mail (sign-in name)"
    [[ "$ADMIN_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "invalid e-mail: $ADMIN_EMAIL"
    ask ADMIN_NAME "First platform admin full name"
  fi
  if [ ! -s "$DEPLOY/tls/fullchain.pem" ]; then
    ask TLS_MODE "TLS certificate: 'existing' (your cert files) or 'self-signed' (testing only)" "existing"
    case "$TLS_MODE" in
      existing) ask TLS_CERT "Path to the certificate full chain (PEM)"; ask TLS_KEY "Path to the private key (PEM)" ;;
      self-signed) ;;
      *) die "--tls must be 'existing' or 'self-signed'" ;;
    esac
  fi
  ask IMAGE_SOURCE "Images: 'registry' (pull a released version) or 'build' (from source)" "registry"
  case "$IMAGE_SOURCE" in
    registry)
      if [ -z "$REGISTRY" ] && [ -z "${PG_REGISTRY+x}" ] && [ "$NONINTERACTIVE" != 1 ] && [ ! -f "$STATE_FILE" ]; then
        ask REGISTRY "Registry/namespace (empty = images already loaded locally)" "-"
        [ "$REGISTRY" = "-" ] && REGISTRY=""
      fi ;;
    build)
      [ -n "$SOURCE_DIR" ] || SOURCE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
      [ -f "$SOURCE_DIR/patchgate-web/Dockerfile" ] || die "build: $SOURCE_DIR/patchgate-web/Dockerfile not found (--source-dir)" ;;
    *) die "--image-source must be 'registry' or 'build'" ;;
  esac
  ask VERSION "Version (image tag, e.g. 1.0.0)"
  [[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid version tag: $VERSION"
  ok "domain=$DOMAIN version=$VERSION images=$IMAGE_SOURCE${REGISTRY:+ ($REGISTRY)} tls=${TLS_MODE:-keep existing}"
}

# ------------------------------------------------------------------ deploy/ files
copy_deploy() {
  step "Deployment files -> $DEPLOY"
  local src="${SOURCE_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}/deploy"
  [ -f "$src/docker-compose.prod.yml" ] || die "deploy/ not found at $src (use --source-dir <repo root>)"
  install -d -m 0750 "$INSTALL_DIR" "$DEPLOY"
  # Never overwrite local state: configuration, secrets, certificates, CA files, backups.
  tar -C "$src" \
      --exclude='./.env.production' --exclude='./secrets' --exclude='./backups' \
      --exclude='./tls/*.pem' --exclude='./tls/*.key' --exclude='./ca/*.pem' \
      --exclude='./nginx/allowlists/connectors.conf' --exclude='./nginx/allowlists/connectors.d/*.conf' \
      --exclude='./nginx/allowlists/health.conf' \
      -cf - . | tar -C "$DEPLOY" --no-same-owner -xf -
  # Allow-lists are operator-owned after the first install (banks are added there).
  local f
  for f in nginx/allowlists/connectors.conf nginx/allowlists/health.conf; do
    [ -f "$DEPLOY/$f" ] || install -m 0644 "$src/$f" "$DEPLOY/$f"
  done
  # Files copied from a Windows checkout may carry CRLF; the containers need LF and the exec bit.
  find "$DEPLOY" -type f \( -name '*.sh' -o -name '*.conf' -o -name '*.template' -o -name '*.yml' -o -name '*.txt' \
       -o -name '*.mjs' -o -name 'Dockerfile' -o -name '*.example' \) -exec sed -i 's/\r$//' {} +
  find "$DEPLOY" -type f -name '*.sh' -exec chmod 0755 {} +
  chmod 0755 "$DEPLOY/scripts/"*.sh "$DEPLOY/postgres/"*.sh "$DEPLOY/postgres/initdb/"*.sh "$DEPLOY/scheduler/"*.sh 2>/dev/null || true
  chmod 0644 "$DEPLOY/nginx/nginx.conf" "$DEPLOY/nginx/templates/"* "$DEPLOY/nginx/allowlists/"*.conf 2>/dev/null || true
  chmod 0755 "$DEPLOY" "$DEPLOY/nginx" "$DEPLOY/nginx/templates" "$DEPLOY/nginx/allowlists" "$DEPLOY/ca" "$DEPLOY/tls"
  mkdir -p "$DEPLOY/backups"
  ok "copied (existing .env.production, secrets/, tls/, ca/ and allow-lists kept)"
}

run_generate_secrets() {
  step "Secrets (deploy/scripts/generate-secrets.sh — creates missing ones only)"
  # Its output lists file names, permissions and NON-secret fingerprints only.
  (cd "$DEPLOY" && ./scripts/generate-secrets.sh) | sed 's/^/    /'
  ok "secrets in $DEPLOY/secrets (0600). Escrow an encrypted copy offline (RUNBOOK §4.2)."
}

# ------------------------------------------------------------------ TLS
setup_tls() {
  step "TLS certificate"
  local tls="$DEPLOY/tls"
  if [ -s "$tls/fullchain.pem" ] && [ -s "$tls/privkey.pem" ]; then
    ok "keeping existing $tls/fullchain.pem"
  elif [ "$TLS_MODE" = existing ]; then
    [ -r "$TLS_CERT" ] && [ -r "$TLS_KEY" ] || die "cannot read --cert/--key"
    local a b
    a="$(openssl x509 -in "$TLS_CERT" -noout -pubkey 2>/dev/null | openssl sha256)" || die "not a PEM certificate: $TLS_CERT"
    b="$(openssl pkey -in "$TLS_KEY" -pubout 2>/dev/null | openssl sha256)" || die "not a PEM private key: $TLS_KEY"
    [ "$a" = "$b" ] || die "certificate and private key do not match"
    openssl x509 -in "$TLS_CERT" -noout -checkhost "$DOMAIN" 2>/dev/null | grep -q 'does match' \
      || die "certificate is not valid for $DOMAIN"
    install -m 0644 "$TLS_CERT" "$tls/fullchain.pem"
    install -m 0600 "$TLS_KEY" "$tls/privkey.pem"
    ok "installed your certificate for $DOMAIN"
  else
    make_self_signed "$tls"
  fi
  local end; end="$(openssl x509 -in "$tls/fullchain.pem" -noout -enddate | cut -d= -f2)"
  info "certificate valid until $end"
}
make_self_signed() { # dir — local test CA + server certificate (connectors pin the CA with --ca)
  local d="$1"
  warn "self-signed TLS: for testing only. Connectors must pin $d/selfsigned-ca.pem (--ca)."
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
    -subj "/CN=PatchGate test CA ($DOMAIN)/O=PatchGate" -keyout "$d/selfsigned-ca.key" -out "$d/selfsigned-ca.pem" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$DOMAIN" \
    -keyout "$d/privkey.pem" -out "$d/server.csr" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$DOMAIN" > "$d/server.ext"
  openssl x509 -req -in "$d/server.csr" -CA "$d/selfsigned-ca.pem" -CAkey "$d/selfsigned-ca.key" -CAcreateserial \
    -days 397 -sha256 -extfile "$d/server.ext" -out "$d/server.pem" 2>/dev/null
  cat "$d/server.pem" "$d/selfsigned-ca.pem" > "$d/fullchain.pem"
  rm -f "$d/server.csr" "$d/server.ext" "$d/server.pem" "$d/selfsigned-ca.srl"
  chmod 0600 "$d/privkey.pem" "$d/selfsigned-ca.key"; chmod 0644 "$d/fullchain.pem" "$d/selfsigned-ca.pem"
  ok "issued a test certificate for $DOMAIN (CA: $d/selfsigned-ca.pem)"
}

# ------------------------------------------------------------------ .env.production
env_get() { sed -n "s/^$1=//p" "$DEPLOY/.env.production" | tail -1; }
env_set() { # KEY VALUE — replace "KEY=…" or "# KEY=…", else append
  local f="$DEPLOY/.env.production" k="$1" v="$2" tmp
  tmp="$(mktemp "$DEPLOY/.env.XXXXXX")"
  awk -v k="$k" -v v="$v" '
    BEGIN { done = 0 }
    !done && ($0 ~ "^" k "=" || $0 ~ "^# *" k "=") { print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }' "$f" > "$tmp"
  chmod 0600 "$tmp"; mv -f "$tmp" "$f"
}
env_unset() { # comment out KEY=…
  sed -i "s/^$1=/# $1=/" "$DEPLOY/.env.production"
}
write_env() {
  step "Configuration file deploy/.env.production"
  local f="$DEPLOY/.env.production" fresh=0
  if [ ! -f "$f" ]; then
    install -m 0600 "$DEPLOY/.env.production.example" "$f"
    fresh=1
  fi
  set_image_env
  fit_cpu_limits
  local nb; for nb in $NGINX_BINDS; do [ -z "${nb#*=}" ] || { env_set "${nb%%=*}" "${nb#*=}"; info "${nb%%=*}=${nb#*=}"; }; done
  if [ "$fresh" = 1 ]; then
    env_set PATCHGATE_HOSTNAME "$DOMAIN"
    env_set PUBLIC_BASE_URL "https://$DOMAIN"
    env_set PATCH_REPO_URL "https://$DOMAIN/repo"
    env_set SIEM_SYSLOG_URL "${SIEM_URL:-tls://siem.not-configured.invalid:6514}"
    [ -n "$SIEM_URL" ] || warn "no platform SIEM given: audit export will report siemExport=false. Set SIEM_SYSLOG_URL + ca/siem-ca.pem before go-live."
    ok "created from .env.production.example (sane defaults; review it any time)"
  else
    [ "$(env_get PATCHGATE_HOSTNAME)" = "$DOMAIN" ] || warn "existing .env.production has PATCHGATE_HOSTNAME=$(env_get PATCHGATE_HOSTNAME) (kept; edit it to change)"
    ok "kept existing values; image tags set to $VERSION"
  fi
  [ -n "$SIEM_URL" ] && env_set SIEM_SYSLOG_URL "$SIEM_URL"
  # CA files (mounted read-only at /etc/patchgate/ca).
  [ -n "$SIEM_CA" ] && install -m 0644 "$SIEM_CA" "$DEPLOY/ca/siem-ca.pem"
  [ -n "$CODESIGN_CA" ] && install -m 0644 "$CODESIGN_CA" "$DEPLOY/ca/codesign-ca.pem"
  if [ ! -s "$DEPLOY/ca/internal-ca.pem" ]; then env_unset NODE_EXTRA_CA_CERTS; else env_set NODE_EXTRA_CA_CERTS /etc/patchgate/ca/internal-ca.pem; fi
  [ -s "$DEPLOY/ca/siem-ca.pem" ] || warn "ca/siem-ca.pem missing: the SIEM connection cannot be verified until you add it"
  [ -s "$DEPLOY/ca/codesign-ca.pem" ] || warn "ca/codesign-ca.pem missing: package signature checks fail closed until you add the Authenticode roots (RUNBOOK §4.4, --codesign-ca)"
}

backup_recipient() {
  local cur; cur="$(env_get BACKUP_AGE_RECIPIENTS)"
  if [ -n "$BACKUP_RECIPIENT" ]; then
    [[ "$BACKUP_RECIPIENT" =~ ^age1[0-9a-z]{58}$ ]] || die "invalid age recipient: $BACKUP_RECIPIENT"
    env_set BACKUP_AGE_RECIPIENTS "$BACKUP_RECIPIENT"; return
  fi
  case "$cur" in age1replace*|"") ;; *) return ;; esac
  # No key given: create one so backups work from day one. The private key stays in a root-only file and is
  # NOT printed; move it OFFLINE and delete it from the server (RUNBOOK §7).
  local idf="$INSTALL_DIR/backup-identity.agekey" pub
  if [ ! -s "$idf" ]; then
    (umask 077; docker run --rm --entrypoint age-keygen "$(helper_ref backup)" > "$idf" 2>/dev/null) || die "age-keygen failed"
  fi
  pub="$(sed -n 's/^# public key: //p' "$idf")"
  [[ "$pub" =~ ^age1 ]] || die "could not read the generated backup public key"
  env_set BACKUP_AGE_RECIPIENTS "$pub"
  warn "generated a backup key pair: move $idf OFFLINE (two custodians) and delete it from this server"
}

# ------------------------------------------------------------------ host firewall (RUNBOOK §4.3)
firewall_rules() { # prints one iptables argument list per line
  local siem_net fetch_net proxy_ip net
  siem_net="$(env_get SIEM_OUT_SUBNET)"; siem_net="${siem_net:-172.30.10.0/24}"
  fetch_net="$(env_get FETCH_EGRESS_SUBNET)"; fetch_net="${fetch_net:-172.30.20.0/24}"
  proxy_ip="$(env_get EGRESS_PROXY_IP)"; proxy_ip="${proxy_ip:-172.30.20.10}"
  # Inserted at the top, in this order: the DROPs end up below the ACCEPTs.
  echo "-s $siem_net ! -d $siem_net -j DROP"
  echo "-s $fetch_net ! -d $fetch_net -j DROP"
  echo "-s $siem_net -d $SIEM_IP -p tcp --dport 6514 -j ACCEPT"
  echo "-s $proxy_ip -p tcp --dport 443 -j ACCEPT"
  for net in "$siem_net" "$fetch_net"; do
    echo "-s $net -d $DNS_IP -p udp --dport 53 -j ACCEPT"
    echo "-s $net -d $DNS_IP -p tcp --dport 53 -j ACCEPT"
  done
}
detect_fw_values() {
  if [ -z "$DNS_IP" ]; then
    DNS_IP="$(resolvectl dns 2>/dev/null | awk 'NF>=4 && $1=="Link" {print $4; exit}' || true)"
    [ -n "$DNS_IP" ] || DNS_IP="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
    case "$DNS_IP" in 127.*|"") DNS_IP="<DNS-SERVER-IP>" ;; esac
  fi
  if [ -z "$SIEM_IP" ]; then
    local h; h="$(env_get SIEM_SYSLOG_URL | sed -E 's#^tls://([^:/]+).*#\1#')"
    SIEM_IP="$(getent ahostsv4 "$h" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
    SIEM_IP="${SIEM_IP:-<SIEM-IP>}"
  fi
}
setup_firewall() {
  step "Host firewall: egress rules (RUNBOOK §4.3)"
  detect_fw_values
  info "Only the egress proxy may reach the internet (tcp/443); web may reach only the SIEM; both may use DNS."
  local r; while IFS= read -r r; do info "iptables -I DOCKER-USER $r"; done < <(firewall_rules)
  local apply=0
  case "$APPLY_FIREWALL" in
    yes) apply=1 ;;
    no) ;;
    *) confirm "Apply these rules now?" n && apply=1 ;;
  esac
  if [ "$apply" = 0 ]; then
    warn "firewall egress rules NOT applied: apply them (RUNBOOK §4.3) before go-live; smoke-test INTERNAL checks need them"
    FIREWALL_APPLIED=0; return
  fi
  case "$DNS_IP$SIEM_IP" in *"<"*) die "set --dns-ip and --siem-ip to apply the firewall rules" ;; esac
  command -v iptables >/dev/null || die "iptables not found"
  iptables -n -L DOCKER-USER >/dev/null 2>&1 || iptables -N DOCKER-USER
  while IFS= read -r r; do
    # shellcheck disable=SC2086
    iptables -C DOCKER-USER $r 2>/dev/null || iptables -I DOCKER-USER $r
  done < <(firewall_rules)
  if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 && ok "rules saved (netfilter-persistent)"
  else warn "rules applied but NOT persistent: apt-get install iptables-persistent && netfilter-persistent save"; fi
  FIREWALL_APPLIED=1
  ok "egress rules active in DOCKER-USER"
}
FIREWALL_APPLIED=0

# ------------------------------------------------------------------ images
load_archive() { # a `docker save` file, or a release images/ directory (every *.tar / *.tar.gz in it)
  [ -n "$IMAGE_ARCHIVE" ] || return 0
  local f files=()
  if [ -d "$IMAGE_ARCHIVE" ]; then
    for f in "$IMAGE_ARCHIVE"/*.tar.gz "$IMAGE_ARCHIVE"/*.tar; do [ -f "$f" ] && files+=("$f"); done
    [ ${#files[@]} -gt 0 ] || die "no *.tar / *.tar.gz image archives in $IMAGE_ARCHIVE"
  else
    [ -r "$IMAGE_ARCHIVE" ] || die "cannot read --image-archive $IMAGE_ARCHIVE"
    files=("$IMAGE_ARCHIVE")
  fi
  for f in "${files[@]}"; do
    info "loading images from $(basename "$f")"
    docker load -i "$f" | sed 's/^/    /'
  done
}
have_image() { docker image inspect "$1" >/dev/null 2>&1; }
get_images() {
  step "Images ($IMAGE_SOURCE, version $VERSION)"
  load_archive
  local web tools
  web="$(image_ref web)"; tools="$(image_ref tools)"
  if [ "$IMAGE_SOURCE" = build ]; then
    info "building $web and $tools from $SOURCE_DIR/patchgate-web (several minutes)"
    docker build -q -t "$web" --build-arg "PATCHGATE_BUILD_ID=${VERSION//./_}" "$SOURCE_DIR/patchgate-web" >/dev/null       || die "building $web failed (see log)"
    docker build -q -t "$tools" --target tools --build-arg "PATCHGATE_BUILD_ID=${VERSION//./_}" "$SOURCE_DIR/patchgate-web" >/dev/null       || die "building $tools failed (see log)"
  else
    local img
    for img in "$web" "$tools" "$(helper_ref signer)" "$(helper_ref egress-proxy)" "$(helper_ref backup)"; do
      if have_image "$img"; then ok "$img present"; else
        [ -n "$REGISTRY" ] || die "$img is not loaded locally and no --registry given"
        docker pull -q "$img" >/dev/null || die "docker pull $img failed (docker login ${REGISTRY%%/*}?)"
        ok "pulled $img"
      fi
    done
  fi
  # Build mode only: helper images from deploy/ (signer, egress proxy, backup) when missing or on upgrade.
  # Registry mode uses the release's helper images (pulled / checked above), never a local rebuild.
  if [ "$IMAGE_SOURCE" = build ]; then
    local svc todo=()
    for svc in signer egress-proxy backup; do
      if [ "$MODE" = upgrade ] || ! have_image "$(helper_ref "$svc")"; then todo+=("$svc"); fi
    done
    if [ ${#todo[@]} -gt 0 ]; then
      info "building ${todo[*]} from deploy/"
      (cd "$DEPLOY" && "${DC[@]}" build -q "${todo[@]}") || die "building ${todo[*]} failed"
    fi
  fi
  ok "all images ready"
}

# ------------------------------------------------------------------ stack
wait_healthy() { # timeout-seconds service...
  local timeout="$1"; shift
  local deadline=$(( $(date +%s) + timeout )) svc cid st pending
  while :; do
    pending=""
    for svc in "$@"; do
      cid="$(cd "$DEPLOY" && "${DC[@]}" ps -q "$svc" 2>/dev/null | head -1 || true)"
      st="$( [ -n "$cid" ] && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo missing)"
      case "$st" in healthy|running) ;; *) pending="$pending $svc($st)" ;; esac
    done
    [ -z "$pending" ] && return 0
    [ "$(date +%s)" -lt "$deadline" ] || { warn "not healthy after ${timeout}s:$pending"; return 1; }
    sleep 5
  done
}
run_migrate() {
  local out rc=0
  out="$(cd "$DEPLOY" && "${DC[@]}" run --rm -T migrate 2>&1)" || rc=$?
  printf '%s
' "$out" | tail -6 | sed 's/^/    /'
  return "$rc"
}
ALL_SERVICES=(db signer egress-proxy web-1 web-2 fetcher scheduler nginx backup)
start_stack() {
  step "Database and schema"
  (cd "$DEPLOY" && "${DC[@]}" up -d db) >/dev/null
  wait_healthy 180 db || die "database did not become healthy: docker compose logs db"
  run_migrate || die "migration failed (see log)"
  ok "migrations applied (prisma migrate deploy as patchgate_owner)"
  step "Starting PatchGate"
  (cd "$DEPLOY" && "${DC[@]}" up -d --remove-orphans) 2>&1 | grep -v -E '^\s*$' | tail -3 | sed 's/^/    /' || true
  wait_healthy 420 "${ALL_SERVICES[@]}" || { (cd "$DEPLOY" && "${DC[@]}" ps) ; die "stack not healthy (docker compose logs <service>)"; }
  ok "all services healthy"
}

create_admin() {
  step "First platform admin"
  if [ -n "$ADMIN_CREATED" ]; then ok "already created earlier ($ADMIN_CREATED) — skipped"; return; fi
  local out rc=0
  # Output is captured (never logged): it contains the one-time password.
  out="$(cd "$DEPLOY" && "${DC[@]}" run --rm -T migrate node node_modules/tsx/dist/cli.mjs scripts/admin/create-user.ts \
          --upn "$ADMIN_EMAIL" --name "$ADMIN_NAME" --role ADMIN --generate 2>&1)" || rc=$?
  if [ "$rc" != 0 ]; then
    if printf '%s' "$out" | grep -q 'already exists'; then
      ADMIN_CREATED="$ADMIN_EMAIL"; save_state
      ok "$ADMIN_EMAIL already exists — skipped (reset its password from Administration -> Users if needed)"
      return
    fi
    printf '%s\n' "$out" | grep -v -i 'password' | tail -5 | sed 's/^/    /'
    die "creating the first admin failed"
  fi
  local pw; pw="$(printf '%s\n' "$out" | sed -n 's/^Temporary password[^:]*: //p' | tail -1)"
  [ -n "$pw" ] || die "create-user did not return a temporary password"
  ADMIN_CREATED="$ADMIN_EMAIL"; save_state
  ok "created platform ADMIN $ADMIN_EMAIL (audited)"
  ADMIN_PASSWORD="$pw"
}
ADMIN_PASSWORD=""

ensure_local_resolution() {
  # The smoke test connects to https://$DOMAIN from this host. For a self-signed TEST install whose name
  # is not in DNS yet, add a marked hosts entry (removed again by --uninstall).
  getent ahostsv4 "$DOMAIN" >/dev/null 2>&1 && return 0
  [ "$TLS_MODE" = self-signed ] || return 1
  printf '127.0.0.1 %s # patchgate-install\n' "$DOMAIN" >> /etc/hosts
  HOSTS_ENTRY=1; save_state
  warn "added '127.0.0.1 $DOMAIN' to /etc/hosts for the local smoke test (test install only)"
}

run_smoke() {
  step "Smoke test (deploy/scripts/smoke-test.sh)"
  if [ "$SKIP_SMOKE" = 1 ]; then warn "smoke test skipped (--skip-smoke)"; SMOKE_RESULT="skipped"; return 0; fi
  ensure_local_resolution || { warn "$DOMAIN does not resolve from this host: smoke test skipped"; SMOKE_RESULT="skipped (DNS)"; return 0; }
  local ca="" internal=0 rc=0
  [ -s "$DEPLOY/tls/selfsigned-ca.pem" ] && ca="tls/selfsigned-ca.pem"
  [ "$FIREWALL_APPLIED" = 1 ] && internal=1
  # SMOKE_WAIT_SIEM: right after start the first audit export has not run yet (siemExport=false until the
  # scheduler's first tick); wait up to 3 min for it instead of reporting a false failure. With the
  # placeholder SIEM (no --siem-url) smoke-test.sh reports a WARN instead (warned about above).
  (cd "$DEPLOY" && CA_FILE="$ca" INTERNAL="$internal" SMOKE_WAIT_SIEM=180 ./scripts/smoke-test.sh "https://$DOMAIN") | sed 's/^/    /' || rc=${PIPESTATUS[0]}
  if [ "$rc" = 0 ]; then SMOKE_RESULT="PASS"; ok "smoke test PASS"; else SMOKE_RESULT="FAIL ($rc checks)"; warn "smoke test: $rc check(s) failed (see above)"; fi
  [ "$internal" = 1 ] || info "(internal isolation checks run once the firewall rules are applied: INTERNAL=1 ./scripts/smoke-test.sh)"
}
SMOKE_RESULT="not run"

summary() {
  step "Summary"
  local fp; fp="$(awk '$2=="default" {print $1}' "$DEPLOY/secrets/job-signing-keys/FINGERPRINTS.txt" 2>/dev/null || true)"
  cat <<TXT
    PatchGate URL        https://$DOMAIN
    Version              $VERSION ($IMAGE_SOURCE)
    Install dir          $DEPLOY   (compose: cd $DEPLOY && docker compose -f docker-compose.prod.yml --env-file .env.production ps)
    First admin          ${ADMIN_CREATED:-not created}
    Smoke test           $SMOKE_RESULT
    Default job-key fingerprint (banks pin it; per-bank keys: RUNBOOK §6.4)
                         ${fp:-n/a}
    Log                  $LOG_FILE
TXT
  if [ ${#WARNINGS[@]} -gt 0 ]; then
    printf '\n    %sTo do before go-live:%s\n' "$C_Y" "$C_0"
    local w; for w in "${WARNINGS[@]}"; do printf '     - %s\n' "$w"; done
  fi
  cat <<'TXT'

    Next steps (docs/TEAM-GUIDE.md):
     1. Sign in with the admin e-mail and the temporary password, choose a new password (sign-in is password-only).
     2. Administration -> Banks: create the bank. Connectors -> Add site: copy the one-line site install command.
     3. Escrow deploy/secrets/ offline (two custodians). Set up monitoring (RUNBOOK §8) and a restore drill (§7.3).
TXT
  if [ -n "$ADMIN_PASSWORD" ]; then
    # Terminal only (fd 3), never the log file.
    printf '\n    %sTemporary password for %s (shown ONCE, not logged, must be changed at first sign-in):%s\n        %s\n\n' \
      "$C_B" "$ADMIN_CREATED" "$C_0" "$ADMIN_PASSWORD" >&3
    ADMIN_PASSWORD=""
  fi
}

# ------------------------------------------------------------------ modes
init_compose() {
  DC=(docker compose -f docker-compose.prod.yml --env-file .env.production)
}
do_install() {
  preflight
  install_docker
  collect_answers
  check_dns || true
  copy_deploy
  run_generate_secrets
  setup_tls
  write_env
  save_state
  get_images
  backup_recipient
  setup_firewall
  start_stack
  create_admin
  run_smoke
  save_state
  summary
}

do_upgrade() {
  [ -f "$DEPLOY/.env.production" ] || die "no installation in $INSTALL_DIR (run without --upgrade first)"
  preflight
  start_docker
  local old="$VERSION"
  VERSION="$UPGRADE_VERSION"
  [[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid version tag: $VERSION"
  [ "$IMAGE_SOURCE" = build ] && { [ -n "$SOURCE_DIR" ] || SOURCE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"; }
  step "Upgrade $old -> $VERSION"
  copy_deploy
  run_generate_secrets
  get_images
  step "Backup before upgrade"
  if (cd "$DEPLOY" && "${DC[@]}" exec -T backup patchgate-backup now) 2>&1 | tail -3 | sed 's/^/    /'; then
    local bdir; bdir="$(env_get BACKUP_DIR || true)"
    ok "backup written to ${bdir:-$DEPLOY/backups} (copy it off-host)"
  else
    confirm "Backup FAILED. Continue the upgrade anyway?" n || die "upgrade aborted before any change (fix the backup first)"
  fi
  set_image_env
  fit_cpu_limits
  save_state
  step "Migrate"
  run_migrate || die "migration failed — previous images still running; restore if needed (RUNBOOK §10)"
  step "Rolling restart"
  local svc
  for svc in web-1 web-2 fetcher scheduler; do
    (cd "$DEPLOY" && "${DC[@]}" up -d --no-deps "$svc") >/dev/null 2>&1
    wait_healthy 300 "$svc" || die "$svc not healthy after upgrade — roll back: --upgrade $old (RUNBOOK §10)"
    ok "$svc on $VERSION"
  done
  (cd "$DEPLOY" && "${DC[@]}" up -d --remove-orphans) >/dev/null 2>&1
  wait_healthy 300 "${ALL_SERVICES[@]}" || die "stack not healthy after upgrade"
  ok "all services healthy"
  run_smoke
  save_state
  summary
}

do_status() {
  [ -f "$DEPLOY/.env.production" ] || die "no installation in $INSTALL_DIR"
  step "PatchGate status ($DOMAIN, version $VERSION)"
  (cd "$DEPLOY" && "${DC[@]}" ps --format 'table {{.Service}}\t{{.Status}}\t{{.Image}}') | sed 's/^/    /'
  local code ca=()
  [ -s "$DEPLOY/tls/selfsigned-ca.pem" ] && ca=(--cacert "$DEPLOY/tls/selfsigned-ca.pem")
  code="$(curl -s -o /dev/null -w '%{http_code}' "${ca[@]}" --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/health" || true)"
  if [ "$code" = 200 ]; then ok "https://$DOMAIN/api/health -> 200"; else warn "https://$DOMAIN/api/health -> $code"; fi
  local ready
  ready="$(cd "$DEPLOY" && "${DC[@]}" exec -T web-1 node -e "fetch('http://127.0.0.1:3000/api/ready').then(r=>r.text()).then(t=>console.log(t),()=>console.log('unreachable'))" 2>/dev/null || echo unreachable)"
  info "readiness: $ready"
  local end; end="$(openssl x509 -in "$DEPLOY/tls/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2)"
  info "certificate valid until: ${end:-unknown}"
}

do_uninstall() {
  [ -d "$DEPLOY" ] || die "no installation in $INSTALL_DIR"
  step "Uninstall PatchGate"
  if [ "$PURGE" = 1 ]; then
    warn "--purge deletes the database, package store, secrets (audit/encryption keys!) and certificates in $INSTALL_DIR"
    if [ "$ASSUME_YES" != 1 ]; then
      [ "$NONINTERACTIVE" != 1 ] && [ -r /dev/tty ] || die "--purge needs --yes in non-interactive mode"
      local a=""; printf '    Type the domain (%s) to confirm: ' "$DOMAIN" >/dev/tty; IFS= read -r a </dev/tty || true
      [ "$a" = "$DOMAIN" ] || die "not confirmed — nothing deleted"
    fi
  fi
  if command -v docker >/dev/null 2>&1 && [ -f "$DEPLOY/.env.production" ]; then
    if [ "$PURGE" = 1 ]; then
      (cd "$DEPLOY" && "${DC[@]}" --profile ops --profile replica down -v --remove-orphans --rmi local) 2>&1 | tail -2 | sed 's/^/    /' || true
    else
      (cd "$DEPLOY" && "${DC[@]}" --profile ops --profile replica down --remove-orphans) 2>&1 | tail -2 | sed 's/^/    /' || true
    fi
  fi
  ok "containers and networks removed"
  if [ "$HOSTS_ENTRY" = 1 ]; then
    # Rewrite in place (no rename): /etc/hosts may be a bind mount (containers) or have special attributes.
    local h; h="$(grep -v '# patchgate-install$' /etc/hosts || true)"
    if printf '%s\n' "$h" > /etc/hosts; then ok "removed the test hosts entry"
    else warn "could not edit /etc/hosts: remove the '# patchgate-install' line yourself"; fi
  fi
  if [ "$PURGE" = 1 ]; then
    if command -v iptables >/dev/null 2>&1 && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
      detect_fw_values
      local r; while IFS= read -r r; do
        # shellcheck disable=SC2086
        iptables -D DOCKER-USER $r 2>/dev/null || true
      done < <(firewall_rules 2>/dev/null || true)
    fi
    rm -rf "$INSTALL_DIR"
    ok "purged $INSTALL_DIR (volumes, secrets, certificates)"
  else
    ok "data kept: docker volumes (patchgate_pgdata, patchgate_repo, …) and $INSTALL_DIR (secrets, config, certs)"
    info "re-install: run this script again; delete everything: --uninstall --purge"
  fi
}

main() {
  parse_args "$@"
  [ "$(id -u)" = 0 ] || die "run as root (sudo $0 ...)"
  setup_logging
  init_compose
  load_state
  case "$MODE" in
    install) do_install ;;
    upgrade) do_upgrade ;;
    status) do_status ;;
    uninstall) do_uninstall ;;
  esac
}

main "$@"
