#!/usr/bin/env bash
# PatchGate bank-site installer: Tactical RMM (offline) + PatchGate Connector on ONE Linux VM. Run as root.
#
# Three ways to start it:
#   A. from the USB bundle (no internet at all):
#        tar xzf patchgate-site-<ver>.tar.gz && cd patchgate-site-<ver> && sudo ./install-site.sh
#      or  sudo ./install-site.sh --bundle /media/usb/patchgate-site-<ver>.tar.gz   (checks SHA256SUMS first)
#   B. from our PatchGate server (the VM may reach ONLY our domain, outbound 443):
#        curl -fsSL https://<patchgate>/install/site.sh | sudo bash -s -- --code <CODE> --fingerprint <SHA256>
#      (downloads the bundle over https with the one-time enrolment code and verifies SHA256SUMS first)
#   C. maintenance:  --status | --upgrade <bundle.tar.gz|dir> | --pc-token [hours] | --uninstall [--purge]
#                    --break-glass on|off  (emergency dashboard login for tacticaladmin; alerted in PatchGate)
#   ONLINE variant (site VM with internet): add --online. Public images (Tactical, mongo, redis, postgres,
#   socat) are pulled from Docker Hub pinned to the exact digests in images/IMAGES.lock (the same bits as the
#   offline bundle); Docker comes from the official apt repo if missing. Tactical still runs on internal-only
#   networks and patches still flow ONLY via PatchGate. At the end it offers to lock the VM's outbound traffic
#   down to the PatchGate domain (--lockdown applies it without asking). Offline is the default.
#
# Asks only: site name, internal domain, TLS (bank certificate | self-signed), PatchGate URL, enrolment code,
# job-key fingerprint (both shown in PatchGate when you add the site). Everything else is automatic:
# Docker (offline, from the bundle, if missing) -> images -> Tactical on internal networks -> provisioning
# (admin user, least-privilege API key, client/site, the 3 PatchGate scripts, manual patch policy) ->
# connector config -> enrolment (pins the job-signing key fingerprint) -> start -> `check` -> isolation
# proof -> the command for the bank PCs. Re-running is safe. Log: /var/log/patchgate-site-install.log
set -euo pipefail
umask 027

INSTALLER_VERSION="1.0.0"
DOCKER_APT_KEY_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"   # Docker Inc. apt release key (download.docker.com/linux/*/gpg)
# Replaced by the PatchGate server when it serves /install/site.sh (its PUBLIC_BASE_URL).
DEFAULT_SERVER="__PATCHGATE_URL__"
case "$DEFAULT_SERVER" in __*) DEFAULT_SERVER="" ;; esac
# Bundle-signing public key ("ed25519:<base64>"), baked in from the server's PATCHGATE_SITE_BUNDLE_PUBKEY
# (server config, not the bundle volume). A bundle downloaded from PatchGate must be signed with it.
DEFAULT_BUNDLE_KEY="__PATCHGATE_BUNDLE_KEY__"
case "$DEFAULT_BUNDLE_KEY" in __*) DEFAULT_BUNDLE_KEY="" ;; esac

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"; fi
LOG_FILE="${PATCHGATE_SITE_LOG:-/var/log/patchgate-site-install.log}"
SITE_DIR="${PG_SITE_DIR:-/opt/patchgate-site}"
PROJECT="patchgate-site"

MODE="install"
NONINTERACTIVE="${PG_NONINTERACTIVE:-0}"
ASSUME_YES=0
PURGE=0
BUNDLE_ARG=""
BUNDLE_DIR="${PG_BUNDLE_DIR:-}"
FROM_URL=""
BUNDLE_VERSION_WANTED="${PG_BUNDLE_VERSION:-latest}"
BUNDLE_PUBKEY="${PG_BUNDLE_PUBKEY:-$DEFAULT_BUNDLE_KEY}"
ALLOW_UNSIGNED="${PG_ALLOW_UNSIGNED:-0}"
SITE_NAME="${PG_SITE_NAME:-}"
CLIENT_NAME="${PG_CLIENT_NAME:-}"
SITE_DOMAIN="${PG_SITE_DOMAIN:-}"
TLS_MODE="${PG_SITE_TLS:-}"          # bank | self-signed
TLS_CERT="${PG_SITE_CERT:-}"
TLS_KEY="${PG_SITE_KEY:-}"
TLS_CA="${PG_SITE_CA:-}"
SERVER_URL="${PG_SERVER:-}"
PATCHGATE_CA="${PG_PATCHGATE_CA:-}"
PATCHGATE_IP="${PG_PATCHGATE_IP:-}"
ENROLL_CODE="${PATCHGATE_ENROLL_CODE:-}"
FINGERPRINT="${PATCHGATE_JOB_KEY_FINGERPRINT:-}"
SIEM_URL="${PG_SIEM_URL:-}"
SIEM_IP="${PG_SIEM_IP:-}"
BIND_IP="${PG_BIND_IP:-0.0.0.0}"
CACHE_PORT="${PG_CACHE_PORT:-8443}"
LAN_SUBNET="${PG_SITE_LAN_SUBNET:-172.29.250.0/24}"
EGRESS_SUBNET="${PG_SITE_EGRESS_SUBNET:-172.29.251.0/24}"
TOKEN_HOURS="${PG_PC_TOKEN_HOURS:-72}"
REENROL=0
SKIP_ENROL="${PG_SKIP_ENROL:-0}"
ONLINE="${PG_ONLINE:-0}"
LOCKDOWN="${PG_LOCKDOWN:-ask}"         # ask | yes | no   (online mode: restrict VM egress to PatchGate)
LAN_CIDRS="${PG_LAN_CIDRS:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16}"
BREAK_GLASS_STATE=""                     # on | off (--break-glass)

# ------------------------------------------------------------------ output
if [ -t 1 ]; then C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[1m'; C_0=$'\e[0m'; else C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""; fi
WARNINGS=()
# Read one field of /etc/os-release WITHOUT sourcing it into this shell (it defines VERSION, NAME, ...).
# shellcheck disable=SC1091
os_field() { ( . /etc/os-release 2>/dev/null && printf "%s" "${!1:-}" ); }
step() { printf '\n%s==> %s%s\n' "$C_B" "$*" "$C_0"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %sOK%s  %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '    %sWARN%s %s\n' "$C_Y" "$C_0" "$*"; WARNINGS+=("$*"); }
die()  { printf '\n%sERROR%s %s\n' "$C_R" "$C_0" "$*" >&2; printf '      Log: %s\n' "$LOG_FILE" >&2; exit 1; }

usage() {
  awk 'NR > 1 && /^set -euo/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$SCRIPT_PATH" 2>/dev/null || true
  cat <<'TXT'

Options (env var in brackets):
  --site-name "NAME"        site name as created in PatchGate, e.g. "Head office"   [PG_SITE_NAME]
  --client-name "NAME"      Tactical client (default: the site's bank, "Bank")      [PG_CLIENT_NAME]
  --domain NAME             internal DNS domain: rmm./api./mesh./pg-cache.<domain>  [PG_SITE_DOMAIN]
  --tls bank|self-signed    bank certificate (covering those 4 names) or test CA    [PG_SITE_TLS]
  --cert F --key F --ca F   with --tls bank: certificate chain, key, bank root CA   [PG_SITE_CERT/KEY/CA]
  --server URL              PatchGate URL, e.g. https://patchgate.example.com      [PG_SERVER]
  --patchgate-ca FILE       pin our CA (only for a private/test PatchGate CA)       [PG_PATCHGATE_CA]
  --patchgate-ip IP         connect to this IP for the PatchGate name (optional)    [PG_PATCHGATE_IP]
  --code CODE               one-time enrolment code (24 h)                          [PATCHGATE_ENROLL_CODE]
  --fingerprint SHA256      job-signing key fingerprint (confirm by phone!)         [PATCHGATE_JOB_KEY_FINGERPRINT]
  --siem-url tls://H:P      bank SIEM for the audit relay (optional)                [PG_SIEM_URL]
  --siem-ip IP              IP of the bank SIEM (if its name is not in DNS)         [PG_SIEM_IP]
  --bind-ip IP              address the site ports listen on (default 0.0.0.0)      [PG_BIND_IP]
  --cache-port N            package cache port for the PCs (default 8443)           [PG_CACHE_PORT]
  --lan-subnet CIDR --egress-subnet CIDR   container subnets (must not overlap the bank LAN)
  --pc-token-hours N        lifetime of the PC install token (default 72, max 720)  [PG_PC_TOKEN_HOURS]
  --bundle FILE|DIR         install from this bundle (tar.gz or extracted dir)
  --from-url URL            download the bundle from PatchGate (needs --code)
  --bundle-version V        with --from-url (default latest)                        [PG_BUNDLE_VERSION]
  --bundle-key KEY|FILE     bundle-signing key: "ed25519:<base64>" or a PEM file     [PG_BUNDLE_PUBKEY]
                            (--bundle-pubkey: same; the web install has it built in)
  --allow-unsigned          accept a downloaded bundle WITHOUT a signature check (lab only)  [PG_ALLOW_UNSIGNED=1]
  --online                  VM has internet: pull digest-pinned public images, Docker from apt  [PG_ONLINE=1]
  --lockdown / --no-lockdown   online mode: restrict VM egress to PatchGate (+ LAN) without asking / skip
  --lan-cidrs "CIDR ..."    internal ranges kept reachable by --lockdown (default RFC 1918)    [PG_LAN_CIDRS]
  --reenrol                 enrol again (new connector key; needs a NEW code)
  --skip-enrol              set up Tactical + connector config only (enrol later)   [PG_SKIP_ENROL=1]
  --non-interactive         never ask                                                [PG_NONINTERACTIVE=1]
  --yes                     confirm --purge
  --break-glass on|off      Tactical is SEALED (no human dashboard login). "on" unblocks the break-glass
                            account tacticaladmin for an emergency, "off" blocks it again. Both are
                            written to Tactical's audit log and alerted in PatchGate (RUNBOOK "Tactical is sealed")
TXT
}

need_val() { [ $# -ge 2 ] && [ -n "$2" ] || die "option $1 needs a value"; }
ORIG_ARGS=()
parse_args() {
  ORIG_ARGS=("$@")
  while [ $# -gt 0 ]; do
    case "$1" in
      --site-name) need_val "$@"; SITE_NAME="$2"; shift 2 ;;
      --client-name) need_val "$@"; CLIENT_NAME="$2"; shift 2 ;;
      --domain) need_val "$@"; SITE_DOMAIN="$2"; shift 2 ;;
      --tls) need_val "$@"; TLS_MODE="$2"; shift 2 ;;
      --cert) need_val "$@"; TLS_CERT="$2"; shift 2 ;;
      --key) need_val "$@"; TLS_KEY="$2"; shift 2 ;;
      --ca) need_val "$@"; TLS_CA="$2"; shift 2 ;;
      --server) need_val "$@"; SERVER_URL="$2"; shift 2 ;;
      --patchgate-ca) need_val "$@"; PATCHGATE_CA="$2"; shift 2 ;;
      --patchgate-ip) need_val "$@"; PATCHGATE_IP="$2"; shift 2 ;;
      --code) need_val "$@"; ENROLL_CODE="$2"; shift 2 ;;
      --fingerprint|--job-key-fingerprint) need_val "$@"; FINGERPRINT="$2"; shift 2 ;;
      --siem-url) need_val "$@"; SIEM_URL="$2"; shift 2 ;;
      --siem-ip) need_val "$@"; SIEM_IP="$2"; shift 2 ;;
      --bind-ip) need_val "$@"; BIND_IP="$2"; shift 2 ;;
      --cache-port) need_val "$@"; CACHE_PORT="$2"; shift 2 ;;
      --lan-subnet) need_val "$@"; LAN_SUBNET="$2"; shift 2 ;;
      --egress-subnet) need_val "$@"; EGRESS_SUBNET="$2"; shift 2 ;;
      --pc-token-hours) need_val "$@"; TOKEN_HOURS="$2"; shift 2 ;;
      --bundle) need_val "$@"; BUNDLE_ARG="$2"; shift 2 ;;
      --bundle-dir) need_val "$@"; BUNDLE_DIR="$2"; shift 2 ;;
      --from-url) need_val "$@"; FROM_URL="$2"; shift 2 ;;
      --bundle-version) need_val "$@"; BUNDLE_VERSION_WANTED="$2"; shift 2 ;;
      --bundle-pubkey|--bundle-key) need_val "$@"; BUNDLE_PUBKEY="$2"; shift 2 ;;
      --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
      --online) ONLINE=1; shift ;;
      --lockdown) LOCKDOWN=yes; shift ;;
      --no-lockdown) LOCKDOWN=no; shift ;;
      --lan-cidrs) need_val "$@"; LAN_CIDRS="$2"; shift 2 ;;
      --reenrol|--reenroll) REENROL=1; shift ;;
      --skip-enrol) SKIP_ENROL=1; shift ;;
      --non-interactive) NONINTERACTIVE=1; shift ;;
      --yes|-y) ASSUME_YES=1; shift ;;
      --status) MODE=status; shift ;;
      --upgrade) need_val "$@"; MODE=upgrade; BUNDLE_ARG="$2"; shift 2 ;;
      --pc-token) MODE=pctoken; if [ $# -ge 2 ] && [[ "$2" =~ ^[0-9]+$ ]]; then TOKEN_HOURS="$2"; shift; fi; shift ;;
      --uninstall) MODE=uninstall; shift ;;
      --break-glass) need_val "$@"; MODE=breakglass; BREAK_GLASS_STATE="$2"; shift 2 ;;
      --purge) PURGE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done
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
confirm() {
  local q="$1" def="${2:-n}" a=""
  if [ "$NONINTERACTIVE" = 1 ] || [ ! -r /dev/tty ]; then [ "$def" = y ]; return; fi
  printf '    %s [%s]: ' "$q" "$([ "$def" = y ] && echo Y/n || echo y/N)" >/dev/tty
  IFS= read -r a </dev/tty || true
  a="${a:-$def}"; [[ "$a" =~ ^[Yy] ]]
}

setup_logging() {
  [ -n "${PG_SITE_LOGGING:-}" ] && return 0   # re-exec'd from the bootstrapper: already logging
  mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; chmod 0600 "$LOG_FILE"
  exec 3>&1
  exec > >(tee -a "$LOG_FILE") 2>&1
  export PG_SITE_LOGGING=1
  printf '\n===== %s install-site.sh %s (mode=%s) =====\n' "$(date -u +%FT%TZ)" "$INSTALLER_VERSION" "$MODE"
}
# fd 3 = the terminal only (never logged): used for the one-time Tactical admin password.
term() { if { true >&3; } 2>/dev/null; then printf '%s\n' "$*" >&3; else printf '%s\n' "$*" >/dev/tty 2>/dev/null || true; fi; }

# ------------------------------------------------------------------ site state (non-secret answers)
STATE="$SITE_DIR/site.conf"
load_state() {
  [ -f "$STATE" ] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      SITE_NAME) SITE_NAME="${SITE_NAME:-$v}" ;;
      CLIENT_NAME) CLIENT_NAME="${CLIENT_NAME:-$v}" ;;
      SITE_DOMAIN) SITE_DOMAIN="${SITE_DOMAIN:-$v}" ;;
      TLS_MODE) TLS_MODE="${TLS_MODE:-$v}" ;;
      SERVER_URL) SERVER_URL="${SERVER_URL:-$v}" ;;
      PATCHGATE_IP) PATCHGATE_IP="${PATCHGATE_IP:-$v}" ;;
      SIEM_URL) SIEM_URL="${SIEM_URL:-$v}" ;;
      SIEM_IP) SIEM_IP="${SIEM_IP:-$v}" ;;
      BIND_IP) [ -n "${PG_BIND_IP:-}" ] || BIND_IP="$v" ;;
      CACHE_PORT) [ -n "${PG_CACHE_PORT:-}" ] || CACHE_PORT="$v" ;;
      LAN_SUBNET) [ -n "${PG_SITE_LAN_SUBNET:-}" ] || LAN_SUBNET="$v" ;;
      EGRESS_SUBNET) [ -n "${PG_SITE_EGRESS_SUBNET:-}" ] || EGRESS_SUBNET="$v" ;;
      BUNDLE_VERSION) INSTALLED_BUNDLE="$v" ;;
      ONLINE) [ "$v" = 1 ] && ONLINE=1 ;;
    esac
  done < "$STATE"
}
INSTALLED_BUNDLE=""
save_state() {
  local tmp; tmp="$(mktemp "$SITE_DIR/.site.XXXXXX")"
  {
    echo "# written by install-site.sh — non-secret answers for re-runs/upgrades"
    for k in SITE_NAME CLIENT_NAME SITE_DOMAIN TLS_MODE SERVER_URL PATCHGATE_IP SIEM_URL SIEM_IP BIND_IP CACHE_PORT LAN_SUBNET EGRESS_SUBNET ONLINE; do
      printf '%s=%s\n' "$k" "${!k}"
    done
    printf 'BUNDLE_VERSION=%s\n' "${BUNDLE_VERSION:-$INSTALLED_BUNDLE}"
  } > "$tmp"
  chmod 0640 "$tmp"; mv -f "$tmp" "$STATE"
}

# ------------------------------------------------------------------ bundle: verify, extract, download
sha_check_dir() { # dir — verify every file listed in <dir>/SHA256SUMS
  local d="$1"
  [ -f "$d/SHA256SUMS" ] || die "$d/SHA256SUMS missing: refusing an unverifiable bundle"
  (cd "$d" && sha256sum --quiet --strict -c SHA256SUMS) || die "bundle checksum mismatch in $d: do NOT use it (re-copy or re-download)"
}
ed25519_pem() { # "ed25519:<base64 raw 32-byte key>" -> PEM public key on stdout (SPKI DER prefix 302a300506032b6570032100)
  local raw="${1#ed25519:}"
  [[ "$raw" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
  printf -- '-----BEGIN PUBLIC KEY-----\n'
  { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; printf '%s' "$raw" | base64 -d; } | base64 -w0
  printf -- '\n-----END PUBLIC KEY-----\n'
}
verify_sig() { # sums-file sig-file — Ed25519 detached signature (openssl >= 3)
  local sums="$1" sig="$2" pub="$BUNDLE_PUBKEY" tmp=""
  if [ -z "$pub" ]; then
    # Downloaded bundles MUST be signed: the checksums come from the same server as the archive.
    if [ -n "$FROM_URL" ] && [ "$ALLOW_UNSIGNED" != 1 ]; then
      die "no bundle-signing key: refusing a downloaded bundle whose signature cannot be checked (pass --bundle-key ed25519:… from the TEAM-GUIDE, or --allow-unsigned in a lab)"
    fi
    if [ -n "$FROM_URL" ]; then warn "--allow-unsigned: bundle signature NOT checked (SHA-256 only) — lab use only"
    elif [ -f "$sig" ]; then warn "bundle is signed but no --bundle-key given: signature NOT checked (SHA-256 only)"; fi
    return 0
  fi
  [ -f "$sig" ] || die "a bundle-signing key is set but $(basename "$sig") is missing: refusing an unsigned bundle"
  [ "$(wc -c < "$sig")" = 64 ] || die "$(basename "$sig") is not an Ed25519 signature (64 bytes)"
  if [[ "$pub" == ed25519:* ]]; then
    tmp="$(mktemp)"; ed25519_pem "$pub" > "$tmp" || { rm -f "$tmp"; die "bundle key must be ed25519:<base64 of 32 bytes>"; }; pub="$tmp"
  elif [ ! -f "$pub" ]; then tmp="$(mktemp)"; printf '%s\n' "$pub" > "$tmp"; pub="$tmp"; fi
  if openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$sums" -sigfile "$sig" >/dev/null 2>&1; then
    ok "bundle signature valid"
  else
    [ -n "$tmp" ] && rm -f "$tmp"; die "bundle signature INVALID: do not use this bundle"
  fi
  [ -n "$tmp" ] && rm -f "$tmp"
  return 0
}
extract_bundle() { # tarball -> sets BUNDLE_DIR (verified)
  local tgz="$1" dir sums
  [ -f "$tgz" ] || die "bundle not found: $tgz"
  dir="$(cd "$(dirname "$tgz")" && pwd)"; sums="$dir/SHA256SUMS"
  if [ -f "$sums" ] && grep -q " [* ]\?$(basename "$tgz")\$" "$sums"; then
    (cd "$dir" && grep " [* ]\?$(basename "$tgz")\$" SHA256SUMS | sha256sum --strict -c --quiet -) \
      || die "$(basename "$tgz") does not match SHA256SUMS: do NOT use it"
    verify_sig "$sums" "$sums.sig"
    ok "bundle archive matches SHA256SUMS"
  else
    warn "no SHA256SUMS next to $(basename "$tgz"): only the inner checksums are verified"
  fi
  local name; name="$(tar -tzf "$tgz" 2>/dev/null | head -1 | cut -d/ -f1 || true)"
  [[ "$name" =~ ^patchgate-site-[A-Za-z0-9._-]+$ ]] || die "unexpected bundle layout ($name)"
  install -d -m 0750 "$SITE_DIR/bundles"
  rm -rf "${SITE_DIR:?}/bundles/$name"
  info "extracting $(basename "$tgz") to $SITE_DIR/bundles/ (a few minutes)"
  tar -C "$SITE_DIR/bundles" --no-same-owner -xzf "$tgz"
  BUNDLE_DIR="$SITE_DIR/bundles/$name"
}
download_bundle() { # downloads from PatchGate: /install/bundle/<version>/{SHA256SUMS,SHA256SUMS.sig,<file>}
  local base="${FROM_URL%/}" ver="$BUNDLE_VERSION_WANTED" dl hdr file
  [[ "$base" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || die "--from-url must be https://host[:port]"
  [ -n "$ENROLL_CODE" ] || die "--from-url needs --code (the one-time enrolment code authorises the download)"
  [[ "$ver" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid --bundle-version"
  command -v curl >/dev/null || die "curl is required for --from-url"
  dl="$SITE_DIR/downloads/$ver"; install -d -m 0700 "$SITE_DIR/downloads" "$dl"
  hdr="$(mktemp)"; chmod 0600 "$hdr"
  # The code goes in a header file: never on a command line, in a URL or in the log.
  printf 'Authorization: PatchGate-Enrolment %s\n' "$ENROLL_CODE" > "$hdr"
  local ca=()
  [ -n "$PATCHGATE_CA" ] && ca=(--cacert "$PATCHGATE_CA")
  local res=()
  [ -n "$PATCHGATE_IP" ] && res=(--resolve "$(printf '%s' "$base" | sed -E 's#https://([^:/]+)(:([0-9]+))?#\1#'):$(printf '%s' "$base" | sed -nE 's#https://[^:/]+:([0-9]+)#\1#p' | grep . || echo 443):$PATCHGATE_IP")
  local C=(curl -fsS --proto "=https" --tlsv1.2 --retry 5 --retry-delay 5 -H "@$hdr" "${ca[@]}" "${res[@]}")
  step "Download the site bundle from $base"
  "${C[@]}" -o "$dl/SHA256SUMS" "$base/install/bundle/$ver/SHA256SUMS" || { rm -f "$hdr"; die "download of SHA256SUMS failed (code valid? VM allowed to reach $base?)"; }
  "${C[@]}" -o "$dl/SHA256SUMS.sig" "$base/install/bundle/$ver/SHA256SUMS.sig" 2>/dev/null || rm -f "$dl/SHA256SUMS.sig"
  # An Ed25519 signature is exactly 64 bytes; anything else (e.g. an error page) is not a signature.
  if [ -f "$dl/SHA256SUMS.sig" ] && [ "$(wc -c < "$dl/SHA256SUMS.sig")" != 64 ]; then rm -f "$dl/SHA256SUMS.sig"; fi
  # Offline (full) bundle by default; the small "-online" variant with --online.
  local want='^patchgate-site-[A-Za-z0-9._]+(-[A-Za-z0-9._]+)*\.tar\.gz$'
  file="$(awk '{print $2}' "$dl/SHA256SUMS" | sed 's/^\*//' | grep -E "$want" | \
    if [ "$ONLINE" = 1 ]; then grep -E -- '-online\.tar\.gz$'; else grep -vE -- '-online\.tar\.gz$'; fi | head -1 || true)"
  [ -n "$file" ] || { rm -f "$hdr"; die "SHA256SUMS lists no $([ "$ONLINE" = 1 ] && echo 'patchgate-site-*-online.tar.gz' || echo 'patchgate-site-*.tar.gz')"; }
  if [ -f "$dl/$file" ] && (cd "$dl" && grep " [* ]\?$file\$" SHA256SUMS | sha256sum --strict -c --quiet - >/dev/null 2>&1); then
    ok "$file already downloaded and verified"
  else
    rm -f "$dl/$file"
    info "downloading $file (resumable: re-run continues an interrupted download)"
    if ! "${C[@]}" -C - -o "$dl/$file.part" "$base/install/bundle/$ver/$file"; then
      info "resume not possible: downloading from the start"
      rm -f "$dl/$file.part"
      "${C[@]}" -o "$dl/$file.part" "$base/install/bundle/$ver/$file" || { rm -f "$hdr"; die "bundle download failed (re-run to resume)"; }
    fi
    mv -f "$dl/$file.part" "$dl/$file"
  fi
  rm -f "$hdr"
  BUNDLE_ARG="$dl/$file"
  ok "downloaded $(du -h "$dl/$file" | cut -f1) $file"
}

# Resolve where the bundle is and hand over to ITS install-site.sh (so the version always matches).
resolve_bundle() {
  if [ -n "$BUNDLE_DIR" ]; then return 0; fi
  if [ -z "$BUNDLE_ARG" ] && [ -z "$FROM_URL" ] && [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/bundle.env" ]; then
    BUNDLE_DIR="$SCRIPT_DIR"; return 0
  fi
  if [ -z "$BUNDLE_ARG" ] && [ -z "$FROM_URL" ]; then
    if [ "$MODE" = install ] && [ -n "$DEFAULT_SERVER" ]; then FROM_URL="$DEFAULT_SERVER"
    elif [ -d "$SITE_DIR/runtime" ] && [ "$MODE" != install ]; then return 0
    else die "no bundle: run from an extracted bundle, or pass --bundle <file> or --from-url <PatchGate URL>"; fi
  fi
  [ "$(id -u)" = 0 ] || die "run as root"
  install -d -m 0750 "$SITE_DIR"
  [ -n "$FROM_URL" ] && { SERVER_URL="${SERVER_URL:-$FROM_URL}"; download_bundle; }
  if [ -d "$BUNDLE_ARG" ]; then BUNDLE_DIR="$(cd "$BUNDLE_ARG" && pwd)"; else extract_bundle "$BUNDLE_ARG"; fi
  [ -f "$BUNDLE_DIR/install-site.sh" ] || die "not a site bundle: $BUNDLE_DIR"
  sha_check_dir "$BUNDLE_DIR"
  ok "bundle content verified (SHA256SUMS)"
  # Continue with the bundle's own installer; pass the answers on via the environment (no secrets in argv).
  export PATCHGATE_ENROLL_CODE="$ENROLL_CODE" PATCHGATE_JOB_KEY_FINGERPRINT="$FINGERPRINT" PG_SERVER="$SERVER_URL"
  export PG_BUNDLE_DIR="$BUNDLE_DIR" PG_BUNDLE_VERIFIED=1
  local args=() skip=0 a
  for a in "${ORIG_ARGS[@]}"; do
    if [ "$skip" = 1 ]; then skip=0; continue; fi
    case "$a" in --bundle|--from-url|--bundle-version|--code|--fingerprint|--job-key-fingerprint|--server|--bundle-dir) skip=1 ;;
      --upgrade) args+=(--upgrade "$BUNDLE_DIR"); skip=1 ;;
      *) args+=("$a") ;; esac
  done
  exec bash "$BUNDLE_DIR/install-site.sh" "${args[@]}"
}

load_bundle_env() {
  [ -n "$BUNDLE_DIR" ] || return 0
  # shellcheck disable=SC1091
  . "$BUNDLE_DIR/bundle.env"
  : "${BUNDLE_VERSION:?}" "${TACTICAL_VERSION:?}" "${CONNECTOR_IMAGE:?}" "${SOCAT_IMAGE:?}" "${AGENT_VERSION:?}"
}

# ------------------------------------------------------------------ preflight
preflight() {
  step "Preflight checks"
  [ "$(id -u)" = 0 ] || die "run as root (sudo ...)"
  [ "$(uname -m)" = x86_64 ] || die "x86-64 required"
  local t; for t in tar gzip sha256sum openssl awk sed; do command -v "$t" >/dev/null || die "$t is required"; done
  local mem_gb disk_gb probe
  mem_gb="$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)"
  probe="$SITE_DIR"; while [ ! -d "$probe" ]; do probe="$(dirname "$probe")"; done
  disk_gb="$(df -Pk "$probe" | awk 'NR==2 {printf "%d", $4/1024/1024}')"
  [ "$mem_gb" -ge 3 ] || die "at least 4 GB RAM required (found ${mem_gb} GB; 8 GB recommended)"
  if [ "$mem_gb" -ge 7 ]; then ok "${mem_gb} GB RAM"; else warn "${mem_gb} GB RAM (8 GB recommended for Tactical + connector)"; fi
  [ "$disk_gb" -ge 20 ] || die "at least 20 GB free under $probe required (found ${disk_gb} GB; 60 GB recommended for the package cache)"
  if [ "$disk_gb" -ge 60 ]; then ok "${disk_gb} GB free disk"; else warn "${disk_gb} GB free disk (60 GB recommended)"; fi
  if ! site_running; then
    local p busy=""
    for p in 80 443 "$CACHE_PORT"; do ss -Hltn "sport = :$p" 2>/dev/null | grep -q . && busy="$busy $p"; done
    [ -z "$busy" ] || die "port(s)$busy already in use on this VM (ss -ltnp)"
    ok "ports 80, 443, $CACHE_PORT free"
  else
    ok "site already running (re-run)"
  fi
}
site_running() { command -v docker >/dev/null 2>&1 && docker ps -q --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null | grep -q .; }

# ------------------------------------------------------------------ Docker (offline: static from the bundle; online: apt)
install_docker_apt() {
  local ID VERSION_CODENAME; ID="$(os_field ID)"; VERSION_CODENAME="$(os_field VERSION_CODENAME)"
  case "${ID:-}" in ubuntu|debian) ;; *) die "--online installs Docker only on Ubuntu/Debian; install Docker Engine + compose plugin yourself, then re-run" ;; esac
  info "installing Docker Engine + compose plugin from download.docker.com (official apt repo)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg iptables >/dev/null
  install -m 0755 -d /etc/apt/keyrings
  # Pinned: Docker's release-signing key (docs.docker.com/engine/install). Any other key = refuse.
  local dk_key dk_fpr; dk_key="$(mktemp)"
  curl -fsSL --proto "=https" --tlsv1.2 "https://download.docker.com/linux/${ID}/gpg" -o "$dk_key"
  dk_fpr="$(gpg --show-keys --with-colons "$dk_key" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
  [ "$dk_fpr" = "$DOCKER_APT_KEY_FPR" ] || { rm -f "$dk_key"; die "Docker apt key fingerprint mismatch (got ${dk_fpr:-none}, expected $DOCKER_APT_KEY_FPR): not installing Docker"; }
  gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg < "$dk_key"; rm -f "$dk_key"
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
  if [ -d /run/systemd/system ]; then systemctl enable --now docker >/dev/null 2>&1 || true; fi
  ok "Docker installed from the official repository"
}
install_docker() {
  step "Docker"
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "Docker already installed ($(docker --version | cut -d, -f1))"
  elif [ "$ONLINE" = 1 ]; then
    install_docker_apt
  else
    local tgz=""; for tgz in "$BUNDLE_DIR"/docker/docker-*.tgz; do [ -f "$tgz" ] && break; done; [ -f "$tgz" ] || tgz=""
    [ -n "$tgz" ] || die "Docker is missing and the bundle has no docker/docker-*.tgz"
    command -v iptables >/dev/null || die "iptables is required by Docker (apt/dnf install iptables from the OS media)"
    info "installing Docker from the bundle (static binaries: $(basename "$tgz"))"
    tar -C /usr/local/bin --strip-components=1 --no-same-owner -xzf "$tgz"
    install -d -m 0755 /usr/local/lib/docker/cli-plugins
    install -m 0755 "$BUNDLE_DIR/docker/docker-compose" /usr/local/lib/docker/cli-plugins/docker-compose
    getent group docker >/dev/null || groupadd --system docker
    if [ -d /run/systemd/system ]; then
      cat > /etc/systemd/system/docker.service <<'UNIT'
[Unit]
Description=Docker Engine (static, installed by PatchGate install-site.sh)
After=network-online.target firewalld.service
Wants=network-online.target
[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=1048576
TasksMax=infinity
Delegate=yes
KillMode=process
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
      systemctl daemon-reload
      systemctl enable --now docker >/dev/null 2>&1 || true
    fi
    ok "Docker binaries installed in /usr/local/bin"
  fi
  if ! docker info >/dev/null 2>&1; then
    local _
    if [ -d /run/systemd/system ]; then systemctl start docker >/dev/null 2>&1 || true
    elif [ -x /etc/init.d/docker ]; then service docker start >/dev/null 2>&1 || true; fi
    for _ in $(seq 1 10); do docker info >/dev/null 2>&1 && break; sleep 2; done
    if ! docker info >/dev/null 2>&1 && [ ! -d /run/systemd/system ] && ! pgrep -x dockerd >/dev/null 2>&1; then
      info "no systemd: starting dockerd in the background (log /var/log/dockerd.log)"
      # </dev/null 3>&-: the daemon must not inherit our stdin (curl | bash) or fd 3 (terminal), otherwise
      # whoever reads our output (| tee, docker exec) never sees EOF and waits forever.
      nohup dockerd >/var/log/dockerd.log 2>&1 </dev/null 3>&- &
    fi
    for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done
  fi
  docker info >/dev/null 2>&1 || die "Docker daemon not running"
  ok "Docker $(docker version --format '{{.Server.Version}}'), Compose $(docker compose version --short)"
}

all_images_present() {
  local img
  while read -r img; do
    [ -n "$img" ] || continue
    docker image inspect "$img" >/dev/null 2>&1 || return 1
  done < "$BUNDLE_DIR/images/IMAGES.txt"
}
load_images() {
  if [ "$ONLINE" = 1 ]; then pull_images; return; fi
  step "Images (offline, from the bundle)"
  [ -f "$BUNDLE_DIR/images/images.tar" ] || die "this is the ONLINE bundle (no images.tar): add --online, or use the full patchgate-site-<ver>.tar.gz"
  if [ "$MODE" != upgrade ] && all_images_present; then ok "all $(wc -l < "$BUNDLE_DIR/images/IMAGES.txt") images already loaded"; return; fi
  info "docker load (several minutes)"
  docker load -i "$BUNDLE_DIR/images/images.tar" | sed 's/^/    /'
  docker load -i "$BUNDLE_DIR/images/local.tar" | sed 's/^/    /'
  all_images_present || die "an image listed in images/IMAGES.txt is missing after docker load"
  ok "images loaded"
}
# Online: public images from their registries, pinned to the exact digests of this bundle (IMAGES.lock);
# the connector image from the bundle (local.tar); offline MeshCentral built here from the pinned base.
pull_images() {
  step "Images (online: digest-pinned pulls from Docker Hub)"
  local tag ref
  if [ "$MODE" = upgrade ] || ! docker image inspect "$CONNECTOR_IMAGE" >/dev/null 2>&1; then
    docker load -i "$BUNDLE_DIR/images/local.tar" | sed 's/^/    /'
  fi
  while read -r tag ref; do
    [ -n "$tag" ] || continue
    [[ "$ref" =~ ^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$ ]] || die "bad IMAGES.lock entry: $ref"
    if [ "$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$tag" 2>/dev/null | grep -cx "$ref")" -gt 0 ]; then
      ok "$tag (already pulled, digest matches)"; continue
    fi
    if docker image inspect "$ref" >/dev/null 2>&1; then
      docker tag "$ref" "$tag"; ok "$tag (pinned digest already present locally)"; continue
    fi
    docker pull -q "$ref" >/dev/null || die "docker pull $ref failed: Docker Hub not reachable? (if the outbound lockdown is active, lift it for the upgrade or use the offline bundle)"
    docker tag "$ref" "$tag"
    ok "$tag <- ${ref%%@*} (pinned digest)"
  done < "$BUNDLE_DIR/images/IMAGES.lock"
  local found
  found="$(docker run --rm --network none --entrypoint sh "tacticalrmm/tactical:$TACTICAL_VERSION" -c \
    'sed -n "s/^TRMM_VERSION = \"\(.*\)\"/\1/p" /tmp/tactical/api/tacticalrmm/settings.py' 2>/dev/null || true)"
  [ "$found" = "$TACTICAL_VERSION" ] || die "pulled Tactical image reports version '$found', expected $TACTICAL_VERSION"
  local mesh="patchgate-site/tactical-meshcentral-offline:$TACTICAL_VERSION"
  if [ "$MODE" = upgrade ] || ! docker image inspect "$mesh" >/dev/null 2>&1; then
    info "building the offline MeshCentral image (npm modules baked in; runs without internet)"
    docker build -q -t "$mesh" --build-arg "MESH_BASE=tacticalrmm/tactical-meshcentral:$TACTICAL_VERSION" \
      "$BUNDLE_DIR/tactical/meshcentral-offline" >/dev/null || die "building $mesh failed"
  fi
  all_images_present || die "an image listed in images/IMAGES.txt is missing"
  ok "Tactical $found verified; all images ready (same digests as the offline bundle)"
}

# ------------------------------------------------------------------ answers
norm_fingerprint() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -e 's/^sha256://' -e 's/://g' -e 's/[[:space:]]//g'; }
enrolled() { [ -f "$SITE_DIR/etc/connector.json" ] && grep -q '"identity"' "$SITE_DIR/etc/connector.json"; }
collect_answers() {
  step "Site settings"
  ask SITE_NAME "Site name (as in PatchGate, e.g. Head office)"
  [[ "$SITE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._()-]{0,63}$ ]] || die "site name: letters, digits, space . _ ( ) - (max 64)"
  CLIENT_NAME="${CLIENT_NAME:-Bank}"
  ask SITE_DOMAIN "Internal DNS domain for this site (rmm./api./mesh./pg-cache.<domain>)"
  SITE_DOMAIN="$(printf '%s' "$SITE_DOMAIN" | tr '[:upper:]' '[:lower:]')"
  [[ "$SITE_DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "invalid domain: $SITE_DOMAIN"
  if [ ! -s "$SITE_DIR/tls/site-cert.pem" ]; then
    ask TLS_MODE "TLS: 'bank' (certificate from the bank's internal CA) or 'self-signed' (test CA made here)" "bank"
    case "$TLS_MODE" in
      bank) ask TLS_CERT "Certificate chain file (PEM) valid for rmm/api/mesh/pg-cache.$SITE_DOMAIN"
            ask TLS_KEY "Private key file (PEM)"; ask TLS_CA "Bank root CA file (PEM)" ;;
      self-signed) ;;
      *) die "--tls must be 'bank' or 'self-signed'" ;;
    esac
  fi
  if ! enrolled || [ "$REENROL" = 1 ]; then
    ask SERVER_URL "PatchGate URL (https://...)" "$DEFAULT_SERVER"
    if [ "$SKIP_ENROL" != 1 ]; then
      ask ENROLL_CODE "One-time enrolment code (from PatchGate, Connectors -> Add site)"
      ask FINGERPRINT "Job-signing key fingerprint (64 hex; confirm it by phone with PatchGate)"
    fi
  fi
  SERVER_URL="${SERVER_URL%/}"
  [ -z "$SERVER_URL" ] || [[ "$SERVER_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || die "PatchGate URL must be https://host[:port]"
  if [ -n "$FINGERPRINT" ]; then
    FINGERPRINT="$(norm_fingerprint "$FINGERPRINT")"
    [[ "$FINGERPRINT" =~ ^[a-f0-9]{64}$ ]] || die "fingerprint must be 64 hex digits (SHA-256)"
  fi
  [[ "$CACHE_PORT" =~ ^[0-9]{2,5}$ ]] || die "invalid --cache-port"
  [[ "$TOKEN_HOURS" =~ ^[0-9]+$ ]] && [ "$TOKEN_HOURS" -ge 1 ] && [ "$TOKEN_HOURS" -le 720 ] || die "--pc-token-hours must be 1..720"
  [ -z "$SIEM_URL" ] || [[ "$SIEM_URL" =~ ^tls://[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] || die "--siem-url must be tls://host:port"
  ok "site \"$SITE_NAME\", domain $SITE_DOMAIN, PatchGate ${SERVER_URL:-<not set>}"
}

# ------------------------------------------------------------------ TLS (one certificate for rmm/api/mesh/pg-cache)
setup_tls() {
  step "TLS certificate for rmm/api/mesh/pg-cache.$SITE_DOMAIN"
  local d="$SITE_DIR/tls"; install -d -m 0750 "$d"
  if [ -s "$d/site-cert.pem" ] && [ -s "$d/site-key.pem" ] && [ -s "$d/bank-ca.pem" ]; then
    ok "keeping existing certificate"
  elif [ "$TLS_MODE" = bank ]; then
    [ -r "$TLS_CERT" ] && [ -r "$TLS_KEY" ] && [ -r "$TLS_CA" ] || die "cannot read --cert/--key/--ca"
    local a b h
    a="$(openssl x509 -in "$TLS_CERT" -noout -pubkey | openssl sha256)"; b="$(openssl pkey -in "$TLS_KEY" -pubout | openssl sha256)"
    [ "$a" = "$b" ] || die "certificate and key do not match"
    for h in rmm api mesh pg-cache; do
      openssl x509 -in "$TLS_CERT" -noout -checkhost "$h.$SITE_DOMAIN" | grep -q 'does match' || die "certificate does not cover $h.$SITE_DOMAIN"
    done
    openssl verify -CAfile "$TLS_CA" -untrusted "$TLS_CERT" "$TLS_CERT" >/dev/null 2>&1 || die "certificate does not chain to the given bank CA"
    install -m 0644 "$TLS_CERT" "$d/site-cert.pem"; install -m 0600 "$TLS_KEY" "$d/site-key.pem"; install -m 0644 "$TLS_CA" "$d/bank-ca.pem"
    ok "installed the bank certificate"
  else
    warn "self-signed site CA: every bank PC must trust $SITE_DIR/pc/bank-ca.pem (the PC script does it). Use the bank's PKI in production."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1825 \
      -subj "/CN=PatchGate site CA ($SITE_DOMAIN)/O=PatchGate site" -keyout "$d/site-ca.key" -out "$d/bank-ca.pem" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=rmm.$SITE_DOMAIN" \
      -keyout "$d/site-key.pem" -out "$d/site.csr" 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:rmm.%s,DNS:api.%s,DNS:mesh.%s,DNS:pg-cache.%s\n' \
      "$SITE_DOMAIN" "$SITE_DOMAIN" "$SITE_DOMAIN" "$SITE_DOMAIN" > "$d/site.ext"
    openssl x509 -req -in "$d/site.csr" -CA "$d/bank-ca.pem" -CAkey "$d/site-ca.key" -CAcreateserial -days 397 -sha256 \
      -extfile "$d/site.ext" -out "$d/leaf.pem" 2>/dev/null
    cat "$d/leaf.pem" "$d/bank-ca.pem" > "$d/site-cert.pem"
    rm -f "$d/site.csr" "$d/site.ext" "$d/leaf.pem" "$d/bank-ca.srl"
    chmod 0600 "$d/site-key.pem" "$d/site-ca.key"; chmod 0644 "$d/site-cert.pem" "$d/bank-ca.pem"
    ok "issued a site certificate from a new site CA ($d/bank-ca.pem)"
  fi
}

# ------------------------------------------------------------------ runtime files + env
ip_in() { # cidr host-number -> address (only /24 subnets are supported for the fixed addresses)
  local net="${1%/*}"; printf '%s.%s' "${net%.*}" "$2"
}
install_runtime() {
  step "Site files -> $SITE_DIR"
  [[ "$LAN_SUBNET" =~ ^([0-9]{1,3}\.){3}0/24$ ]] && [[ "$EGRESS_SUBNET" =~ ^([0-9]{1,3}\.){3}0/24$ ]] || die "subnets must be x.y.z.0/24"
  install -d -m 0750 "$SITE_DIR" "$SITE_DIR/runtime" "$SITE_DIR/state"
  install -d -m 0755 "$SITE_DIR/pc"
  # Everything from the bundle except the big image/Docker archives.
  tar -C "$BUNDLE_DIR" --exclude=./images --exclude=./docker -cf - . | tar -C "$SITE_DIR/runtime" --no-same-owner -xf -
  find "$SITE_DIR/runtime" -type f \( -name '*.sh' -o -name '*.yml' -o -name '*.py' -o -name '*.mjs' -o -name '*.env' \) -exec sed -i 's/\r$//' {} +
  chmod 0755 "$SITE_DIR/runtime/install-site.sh"
  local envf="$SITE_DIR/site.env" pg_host pg_port siem_host siem_port
  pg_host="$(printf '%s' "${SERVER_URL:-https://patchgate.invalid}" | sed -E 's#^https://([^:/]+).*#\1#')"
  pg_port="$(printf '%s' "${SERVER_URL:-}" | sed -nE 's#^https://[^:/]+:([0-9]+).*#\1#p')"; pg_port="${pg_port:-443}"
  siem_host="siem.not-configured.invalid"; siem_port=6514
  if [ -n "$SIEM_URL" ]; then siem_host="$(printf '%s' "$SIEM_URL" | sed -E 's#^tls://([^:]+):.*#\1#')"; siem_port="${SIEM_URL##*:}"; fi
  [ "$siem_port" != "$pg_port" ] || die "the SIEM port must differ from the PatchGate port"
  # Tactical secrets: created once, kept on re-runs (root-only file; compose reads it).
  local tenv="$SITE_DIR/tactical.env"
  if [ ! -s "$tenv" ]; then
    r() { openssl rand -hex 16; }
    ( umask 077
      { echo "TRMM_USER=tacticaladmin"; echo "TRMM_PASS=$(r)"; echo "MESH_USER=meshadmin"; echo "MESH_PASS=$(r)"
        echo "MONGODB_USER=mongo"; echo "MONGODB_PASSWORD=$(r)"; echo "POSTGRES_USER=tactical"; echo "POSTGRES_PASS=$(r)"; } > "$tenv" )
    FIRST_TACTICAL=1
  fi
  ( umask 077
    cat "$tenv"
    cat <<ENV
IMAGE_REPO=tacticalrmm/
VERSION=$TACTICAL_VERSION
APP_HOST=rmm.$SITE_DOMAIN
API_HOST=api.$SITE_DOMAIN
MESH_HOST=mesh.$SITE_DOMAIN
CSRF_COOKIE_DOMAIN=$SITE_DOMAIN
SESSION_COOKIE_DOMAIN=$SITE_DOMAIN
MESH_PERSISTENT_CONFIG=0
TRMM_DISABLE_WEB_TERMINAL=True
TRMM_DISABLE_SERVER_SCRIPTS=True
TRMM_DISABLE_SSO=True
CERT_PUB_KEY=$(base64 -w0 "$SITE_DIR/tls/site-cert.pem")
CERT_PRIV_KEY=$(base64 -w0 "$SITE_DIR/tls/site-key.pem")
SITE_DIR=$SITE_DIR
SITE_DOMAIN=$SITE_DOMAIN
SITE_LAN_SUBNET=$LAN_SUBNET
SITE_EGRESS_SUBNET=$EGRESS_SUBNET
NGINX_IP=$(ip_in "$LAN_SUBNET" 20)
INGRESS_IP=$(ip_in "$LAN_SUBNET" 30)
CONNECTOR_IP=$(ip_in "$LAN_SUBNET" 40)
EGRESS_IP=$(ip_in "$EGRESS_SUBNET" 10)
CONNECTOR_EGRESS_IP=$(ip_in "$EGRESS_SUBNET" 20)
BIND_IP=$BIND_IP
CACHE_PORT=$CACHE_PORT
SOCAT_IMAGE=$SOCAT_IMAGE
CONNECTOR_IMAGE=$CONNECTOR_IMAGE
PG_HOST=$pg_host
PG_PORT=$pg_port
PG_TARGET=${PATCHGATE_IP:-$pg_host}
SIEM_HOST=$siem_host
SIEM_PORT=$siem_port
SIEM_TARGET=${SIEM_IP:-$siem_host}
ENV
  ) > "$envf.tmp"
  mv -f "$envf.tmp" "$envf"; chmod 0600 "$envf"
  DC=(docker compose -p "$PROJECT" --env-file "$envf" -f "$SITE_DIR/runtime/tactical/docker-compose.yml" -f "$SITE_DIR/runtime/tactical/docker-compose.site.yml")
  ok "runtime files and $envf (0600) written"
}
FIRST_TACTICAL=0
DC=()
set_dc() {
  DC=(docker compose -p "$PROJECT" --env-file "$SITE_DIR/site.env" -f "$SITE_DIR/runtime/tactical/docker-compose.yml" -f "$SITE_DIR/runtime/tactical/docker-compose.site.yml")
}
TV() { sed -n "s/^$1=//p" "$SITE_DIR/site.env" | tail -1; }

# ------------------------------------------------------------------ Tactical
start_tactical() {
  step "Tactical RMM $TACTICAL_VERSION (internal networks only)"
  "${DC[@]}" up -d --no-build --remove-orphans tactical-postgres tactical-redis tactical-mongodb tactical-meshcentral \
    tactical-init tactical-nats tactical-frontend tactical-backend tactical-websockets tactical-nginx tactical-celery \
    tactical-celerybeat site-ingress 2>&1 | grep -vE '^\s*$' | tail -3 | sed 's/^/    /' || true
  info "waiting for tactical-init (first start: migrations, 3-10 minutes)"
  local i state
  for i in $(seq 1 120); do
    state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' trmm-init 2>/dev/null || echo missing)"
    [ "$state" = "exited 0" ] && break
    if docker logs --tail 3 trmm-init 2>&1 | grep -q "mesh_token: No such file"; then
      if ! docker exec trmm-meshcentral test -s /opt/tactical/tmp/mesh_token 2>/dev/null; then
        info "MeshCentral token missing (first boot race) -> restarting meshcentral"; docker restart trmm-meshcentral >/dev/null; sleep 45
      fi
    fi
    [ $((i % 8)) = 0 ] && info "... still initialising ($((i * 15 / 60)) min)"
    sleep 15
  done
  [ "$(docker inspect -f '{{.State.ExitCode}}' trmm-init 2>/dev/null)" = 0 ] || { docker logs --tail 30 trmm-init 2>&1 | sed 's/^/    /'; die "Tactical init failed"; }
  # PatchGate decides and delivers; Tactical must never approve, install or update by itself (ARCHITECTURE §6).
  local changed
  changed="$(docker exec -u 0 trmm-backend sh -c 'f=/opt/tactical/api/tacticalrmm/local_settings.py; grep -q "PatchGate site" "$f" && echo no || { cat >> "$f" <<EOF

# --- PatchGate site: Tactical is a delivery pipe only, never reaches the internet ---
TRMM_DISABLE_APPROVE_UPDATES_TASK = True
TRMM_DISABLE_WINUPDATES_INSTALL_TASK = True
TRMM_DISABLE_AGENT_AUTO_UPDATE_TASK = True
INSTALL_NUSHELL = False
INSTALL_DENO = False
EOF
echo yes; }')"
  if [ "$changed" = yes ]; then docker restart trmm-backend trmm-celery trmm-celerybeat trmm-websockets >/dev/null; info "Tactical auto-approve/auto-update tasks disabled"; fi
  local _; for _ in $(seq 1 40); do docker exec trmm-backend sh -c 'cd /opt/tactical/api && python manage.py check >/dev/null 2>&1' && break; sleep 3; done
  ensure_nats || die "Tactical's NATS message bus did not start (docker logs trmm-nats)"
  ok "Tactical up: https://rmm.$SITE_DOMAIN"
}

# Upstream start race (official images, not modified): trmm-nats can start nats-server before tactical-init has
# (re)written nats-rmm.conf; supervisor then gives up and Tactical answers every script run with "natsdown" (no PC
# reachable). Restart trmm-nats until nats-server runs. After a VM reboot run --status (it reports this state).
# (no pgrep in a future image = cannot tell = assume running; never block the install on the probe itself)
nats_running() { docker exec trmm-nats sh -c 'command -v pgrep >/dev/null 2>&1 || exit 0; pgrep -x nats-server >/dev/null' 2>/dev/null; }
ensure_nats() {
  local i
  for i in 1 2 3 4 5 6; do
    nats_running && return 0
    info "Tactical NATS not running (start race) -> restarting trmm-nats"
    docker restart trmm-nats >/dev/null 2>&1 || true
    sleep 30
  done
  nats_running
}

provision_tactical() {
  step "Provision Tactical for PatchGate (least privilege)"
  docker exec -u 0 trmm-backend sh -c 'rm -rf /tmp/pg-scripts && mkdir -p /tmp/pg-scripts'
  local s
  for s in Install-PatchGatePackage.ps1 Invoke-PatchGateWuScan.ps1 Install-PatchGateWinUpdate.ps1; do
    docker cp "$SITE_DIR/runtime/endpoint/$s" "trmm-backend:/tmp/pg-scripts/$s" >/dev/null
  done
  docker cp "$SITE_DIR/runtime/tactical/provision-site.py" trmm-backend:/tmp/pg-provision-site.py >/dev/null
  # Re-provisioning re-seals Tactical; an open break-glass session (state file) is kept open.
  local keep_bg=false; [ "$(break_glass_state)" = on ] && keep_bg=true
  local args; args="$(printf '{"client":"%s","site":"%s","tokenHours":%s,"rotateKey":%s,"scriptsDir":"/tmp/pg-scripts","keepBreakGlass":%s}' \
    "$(json_esc "$CLIENT_NAME")" "$(json_esc "$SITE_NAME")" "$TOKEN_HOURS" "${ROTATE_KEY:-false}" "$keep_bg")"
  printf '%s' "$args" | docker exec -i -u 0 trmm-backend sh -c 'cat > /tmp/pg-provision-args.json && chmod 0644 /tmp/pg-provision-args.json /tmp/pg-provision-site.py && chmod -R a+r /tmp/pg-scripts'
  local out line
  out="$(docker exec -w /opt/tactical/api trmm-backend sh -c 'python manage.py shell < /tmp/pg-provision-site.py' 2>&1 || true)"
  docker exec -u 0 trmm-backend rm -rf /tmp/pg-provision-args.json /tmp/pg-provision-site.py /tmp/pg-scripts >/dev/null 2>&1 || true
  line="$(printf '%s\n' "$out" | grep '^PATCHGATE_PROVISION=' | tail -1 || true)"
  [ -n "$line" ] || { printf '%s\n' "$out" | grep -viE 'key|token|pass' | tail -15 | sed 's/^/    /'; die "Tactical provisioning failed"; }
  ( umask 077; printf '%s\n' "${line#PATCHGATE_PROVISION=}" > "$SITE_DIR/state/provision.json" )
  PROV="$SITE_DIR/state/provision.json"
  ok "service account + API key ($(jfield apiKeyState)), client \"$CLIENT_NAME\" (id $(jfield clientId)), site \"$SITE_NAME\" (id $(jfield siteId))"
  ok "scripts: install=$(jfield installScriptId) wuScan=$(jfield wuScanScriptId) wuInstall=$(jfield wuInstallScriptId); patch policy = manual"
  ok "Tactical sealed: dashboard login blocked (newly: $(jfield sealBlocked | tr ';' ' ' | sed 's/^$/none/')), other API keys expired: $(jfield sealExpiredApiKeys), agent auto-update $(jfield agentAutoUpdate), break-glass $(jfield breakGlass)"
  local others; others="$(jfield sealOtherUsers | tr ';' ' ')"
  if [ -n "${others// /}" ]; then warn "Tactical has other dashboard users (blocked, reported to PatchGate): $others"; fi
}

# Break-glass state of the sealed Tactical (root-only state file; Tactical itself is the source of truth).
break_glass_state() { cat "$SITE_DIR/state/break-glass" 2>/dev/null || echo off; }
PROV=""
json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
jfield() { # key -> value from provision.json (flat JSON of numbers/strings)
  sed -E "s/.*\"$1\": *\"?([^\",}]*)\"?.*/\1/" "$PROV"
}

# ------------------------------------------------------------------ connector
write_connector_files() {
  step "PatchGate Connector configuration"
  local etc="$SITE_DIR/etc"
  install -d -m 0750 -o root -g 1000 "$etc"
  install -m 0640 -o root -g 1000 "$SITE_DIR/tls/bank-ca.pem" "$etc/bank-ca.pem"
  install -m 0640 -o root -g 1000 "$SITE_DIR/tls/site-cert.pem" "$etc/cache-cert.pem"
  install -m 0640 -o root -g 1000 "$SITE_DIR/tls/site-key.pem" "$etc/cache-key.pem"
  ( umask 027; jfield apiKey | tr -d '\n' > "$etc/tactical-api-key" ); chown root:1000 "$etc/tactical-api-key"; chmod 0640 "$etc/tactical-api-key"
  [ -n "$PATCHGATE_CA" ] && install -m 0640 -o root -g 1000 "$PATCHGATE_CA" "$etc/patchgate-ca.pem"
  docker run --rm --user 0 --network none --read-only \
    -e SITE_DOMAIN="$SITE_DOMAIN" -e CACHE_PORT="$CACHE_PORT" -e SIEM_URL="$SIEM_URL" \
    -e INSTALL_SCRIPT_ID="$(jfield installScriptId)" -e WU_SCAN_SCRIPT_ID="$(jfield wuScanScriptId)" -e WU_INSTALL_SCRIPT_ID="$(jfield wuInstallScriptId)" \
    -v "$etc:/etc/patchgate-connector" -v "$SITE_DIR/runtime/connector:/opt/pg-site:ro" \
    --entrypoint node "$CONNECTOR_IMAGE" /opt/pg-site/write-config.mjs | sed 's/^/    /'
  chown root:1000 "$etc/connector.json"; chmod 0640 "$etc/connector.json"
  ok "connector.json: Tactical https://api.$SITE_DOMAIN:4443, cache https://pg-cache.$SITE_DOMAIN:$CACHE_PORT/repo${SIEM_URL:+, SIEM $SIEM_URL}"
}

enrol_connector() {
  step "Enrol the connector with PatchGate"
  if enrolled && [ "$REENROL" != 1 ]; then ok "already enrolled ($(sed -nE 's/.*"connectorId": *"([^"]+)".*/\1/p' "$SITE_DIR/etc/connector.json" | head -1 || true))"; return 0; fi
  if [ "$SKIP_ENROL" = 1 ]; then warn "enrolment skipped (--skip-enrol): re-run with --code and --fingerprint"; return 0; fi
  [ -n "$SERVER_URL" ] && [ -n "$ENROLL_CODE" ] && [ -n "$FINGERPRINT" ] || die "enrolment needs --server, --code and --fingerprint"
  "${DC[@]}" up -d --no-deps site-egress >/dev/null 2>&1
  "${DC[@]}" stop connector >/dev/null 2>&1 || true
  local etc="$SITE_DIR/etc" rc=0 out
  chown 1000 "$etc" "$etc/connector.json"   # init rewrites connector.json atomically (this step only)
  local ca=(); [ -s "$etc/patchgate-ca.pem" ] && ca=(--ca /etc/patchgate-connector/patchgate-ca.pem)
  local force=(); [ "$REENROL" = 1 ] && force=(--force)
  out="$(ETC_MODE=rw PATCHGATE_ENROLL_CODE="$ENROLL_CODE" PATCHGATE_JOB_KEY_FINGERPRINT="$FINGERPRINT" \
    "${DC[@]}" run --rm --no-deps -T -e PATCHGATE_ENROLL_CODE -e PATCHGATE_JOB_KEY_FINGERPRINT \
    connector init --config /etc/patchgate-connector/connector.json --server "$SERVER_URL" "${ca[@]}" "${force[@]}" 2>&1)" || rc=$?
  chown root:1000 "$etc" "$etc/connector.json"; chmod 0750 "$etc"; chmod 0640 "$etc/connector.json"
  printf '%s\n' "$out" | grep -v -i 'code' | tail -4 | sed 's/^/    /'
  if [ "$rc" != 0 ]; then
    ENROL_FAILED=1
    warn "enrolment FAILED (exit $rc). Tactical and the connector config are ready. Check: PatchGate reachable from this VM, code unused and < 24 h old, fingerprint exactly as shown in PatchGate, this site's egress IP on PatchGate's connector allow-list. Then re-run with a NEW --code."
    return 0
  fi
  ok "enrolled; job-signing key pinned (fingerprint ${FINGERPRINT:0:16}…)"
}
ENROL_FAILED=0

start_connector() {
  step "Start the connector"
  if ! enrolled; then warn "connector not started (not enrolled yet)"; return 0; fi
  "${DC[@]}" up -d --no-build --remove-orphans >/dev/null 2>&1 || "${DC[@]}" up -d --no-build connector site-egress 2>&1 | tail -3 | sed 's/^/    /'
  local _ st; for _ in $(seq 1 24); do
    st="$(docker inspect -f '{{.State.Health.Status}}' pg-site-connector 2>/dev/null || echo missing)"
    [ "$st" = healthy ] && break; sleep 5
  done
  if [ "$st" = healthy ]; then ok "connector healthy (package cache listening)"; else warn "connector health: $st (docker logs pg-site-connector)"; fi
  step "Connector self-check (patchgate-connector check)"
  local rc=0
  docker exec pg-site-connector node /opt/patchgate-connector/patchgate-connector.mjs check 2>&1 | sed 's/^/    /' || rc=$?
  if [ "$rc" = 0 ]; then CHECK_RESULT="healthy"; ok "check: healthy"; else CHECK_RESULT="unhealthy"; warn "check reported a problem (see above)"; fi
}
CHECK_RESULT="not run"

# ------------------------------------------------------------------ isolation proof
prove_isolation() {
  step "Isolation proof (Tactical + connector must NOT reach the internet)"
  local fail=0 c out
  # Offline mode: any leak is fatal. Online mode: reported as a WARNING (the bank chose a VM with internet).
  leak() { if [ "$ONLINE" = 1 ]; then warn "internet reachable: $1"; else fail=1; fi; }
  local PY='import socket
r="blocked"
for t in [("1.1.1.1",443),("140.82.112.3",443),("8.8.8.8",53)]:
    try:
        socket.create_connection(t,timeout=4); r="REACHABLE "+t[0]; break
    except OSError: pass
print(r)'
  for c in trmm-backend trmm-celery trmm-nginx trmm-meshcentral trmm-nats; do
    if docker exec "$c" sh -c 'command -v python >/dev/null 2>&1'; then
      out="$(docker exec "$c" python -c "$PY" 2>&1 | tail -1)"
    elif docker exec "$c" sh -c 'command -v node >/dev/null 2>&1'; then
      out="$(docker exec "$c" node -e 'const n=require("net");const t=(h,p)=>new Promise(r=>{const s=n.connect({host:h,port:p,timeout:4000});s.on("connect",()=>{s.destroy();r(1)});s.on("timeout",()=>{s.destroy();r(0)});s.on("error",()=>r(0))});Promise.all([t("1.1.1.1",443),t("140.82.112.3",443)]).then(a=>console.log(a.some(Boolean)?"REACHABLE":"blocked"))' 2>&1 | tail -1)"
    else
      out="$(docker exec "$c" sh -c '(nc -z -w 4 1.1.1.1 443 || nc -z -w 4 140.82.112.3 443) >/dev/null 2>&1 && echo REACHABLE || echo blocked' 2>&1 | tail -1)"
    fi
    info "$c -> internet: $out"; case "$out" in *REACHABLE*) leak "$c: $out" ;; esac
  done
  out="$(docker exec trmm-backend python -c "import socket
try:
    socket.create_connection(('$(TV EGRESS_IP)',$(TV PG_PORT)),timeout=4); print('REACHABLE')
except OSError: print('blocked')" 2>&1 | tail -1)"
  info "trmm-backend -> PatchGate forwarder: $out"; case "$out" in *REACHABLE*) leak "Tactical reaches the PatchGate forwarder" ;; esac
  if docker inspect pg-site-connector >/dev/null 2>&1 && [ "$(docker inspect -f '{{.State.Running}}' pg-site-connector)" = true ]; then
    local NJS='const n=require("net");const t=(h,p)=>new Promise(r=>{const s=n.connect({host:h,port:p,timeout:4000});s.on("connect",()=>{s.destroy();r(true)});s.on("timeout",()=>{s.destroy();r(false)});s.on("error",()=>r(false))});'
    out="$(docker exec pg-site-connector node -e "${NJS}Promise.all([t('1.1.1.1',443),t('140.82.112.3',443),t('8.8.8.8',53)]).then(a=>console.log(a.some(Boolean)?'REACHABLE':'blocked'))" 2>&1 | tail -1)"
    info "connector -> internet (raw IP): $out"; case "$out" in *REACHABLE*) leak "connector reaches the internet" ;; esac
    out="$(docker exec pg-site-connector node -e "require('dns').lookup('github.com',e=>console.log(e?'blocked ('+e.code+')':'RESOLVED'))" 2>&1 | tail -1)"
    info "connector -> DNS github.com: $out"; case "$out" in *RESOLVED*) leak "connector DNS: $out" ;; esac
    out="$(docker exec pg-site-connector node -e "${NJS}t('$(TV EGRESS_IP)',22).then(ok=>console.log(ok?'REACHABLE':'blocked'))" 2>&1 | tail -1)"
    info "connector -> forwarder, any other port (22): $out"; case "$out" in *REACHABLE*) leak "forwarder exposes port 22" ;; esac
    out="$(docker exec pg-site-connector node -e "${NJS}t('$(TV PG_HOST)',$(TV PG_PORT)).then(ok=>console.log(ok?'reachable':'UNREACHABLE'))" 2>&1 | tail -1)"
    info "connector -> PatchGate $(TV PG_HOST):$(TV PG_PORT) (its only way out): $out"
    [ "$out" = reachable ] || warn "PatchGate is not reachable from the connector: check the VM's outbound 443 to $(TV PG_HOST)"
  fi
  [ "$fail" = 0 ] || { ISOLATION="BROKEN"; die "ISOLATION BROKEN: a Tactical/connector container reached the internet (see above)"; }
  ISOLATION="proven (containers)"
  ok "no internet from Tactical or the connector; the connector reaches only PatchGate"
  # The VM itself (host network): its egress is the bank's firewall (or --lockdown in online mode).
  if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null || timeout 5 bash -c 'exec 3<>/dev/tcp/140.82.112.3/443' 2>/dev/null; then

    ISOLATION="$ISOLATION; VM host: internet reachable"
    warn "internet reachable from the VM host itself: restrict its outbound traffic to $(TV PG_HOST):$(TV PG_PORT) ($([ "$ONLINE" = 1 ] && echo 'bank firewall, or the lockdown offered below' || echo 'bank firewall'))"
  else
    info "VM host -> internet: blocked"
  fi
}
ISOLATION="not checked"

# ------------------------------------------------------------------ online mode: lock the VM's egress to PatchGate
lockdown_rules() { # prints "<chain> <iptables args>" lines
  local pg_host pg_port ips ip cidr ext
  pg_host="$(TV PG_HOST)"; pg_port="$(TV PG_PORT)"
  ips="$PATCHGATE_IP"
  [ -n "$ips" ] || ips="$(getent ahostsv4 "$pg_host" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
  [ -n "$ips" ] || { echo "ERROR cannot resolve $pg_host"; return 0; }
  ext="$(ip route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  # VM itself (OUTPUT): loopback, replies, the bank LAN (DNS/NTP/SIEM/AD live there), PatchGate:443. Nothing else.
  echo "OUTPUT -o lo -j ACCEPT"
  echo "OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
  for cidr in $LAN_CIDRS; do echo "OUTPUT -d $cidr -j ACCEPT"; done
  for ip in $ips; do echo "OUTPUT -d $ip -p tcp --dport $pg_port -j ACCEPT"; done
  echo "OUTPUT -j REJECT"
  # Containers (DOCKER-USER, forwarded traffic leaving via ${ext:-the uplink}): only PatchGate, the LAN and replies.
  [ -n "$ext" ] || return 0
  echo "DOCKER-USER -o $ext -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  for cidr in $LAN_CIDRS; do echo "DOCKER-USER -o $ext -d $cidr -j RETURN"; done
  for ip in $ips; do echo "DOCKER-USER -o $ext -d $ip -p tcp --dport $pg_port -j RETURN"; done
  echo "DOCKER-USER -o $ext -j REJECT"
}
offer_lockdown() {
  [ "$ONLINE" = 1 ] || return 0
  step "Recommended: lock this VM's outbound traffic down to PatchGate only"
  info "Online mode needed internet for the installation. From now on the site needs ONLY:"
  info "  outbound tcp/$(TV PG_PORT) to $(TV PG_HOST)  +  the bank LAN ($LAN_CIDRS)."
  info "Patches and updates still flow ONLY via PatchGate: Tactical runs on internal networks, its patch policy is"
  info "manual, auto-update tasks are off, and PCs are never pointed at Microsoft Update or any internet source."
  local rules; rules="$(lockdown_rules)"
  case "$rules" in ERROR*) warn "lockdown: ${rules#ERROR }"; return 0 ;; esac
  info "Commands (applied in this order, -A = append to the end of the chain):"
  local l; while IFS= read -r l; do info "  iptables -A $l"; done <<< "$rules"
  info "  (persist: apt-get install iptables-persistent && netfilter-persistent save)"
  local apply=0
  case "$LOCKDOWN" in yes) apply=1 ;; no) ;; *) confirm "Apply these rules now? (Docker updates/pulls will need them lifted again)" n && apply=1 ;; esac
  if [ "$apply" = 0 ]; then warn "outbound lockdown NOT applied (recommended before go-live)"; return 0; fi
  command -v iptables >/dev/null || die "iptables not found"
  while IFS= read -r l; do
    # shellcheck disable=SC2086
    iptables -C $l 2>/dev/null || iptables -A $l
  done <<< "$rules"
  # DOCKER-USER ends with RETURN by default: our REJECT must come before it.
  iptables -D DOCKER-USER -j RETURN 2>/dev/null && iptables -A DOCKER-USER -j RETURN || true
  if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 && ok "rules saved"; else warn "lockdown applied but NOT persistent (iptables-persistent)"; fi
  if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then warn "lockdown applied but 1.1.1.1:443 is still reachable"; else
    ok "lockdown active: VM -> internet blocked"; ISOLATION="${ISOLATION/VM host: internet reachable/VM host: locked down}"
    local kept=() w; for w in "${WARNINGS[@]}"; do case "$w" in "internet reachable from the VM host"*) ;; *) kept+=("$w") ;; esac; done
    WARNINGS=("${kept[@]}")
  fi
}

# ------------------------------------------------------------------ PCs (step 3)
write_pc_kit() {
  step "Bank PC kit (step 3)"
  local pc="$SITE_DIR/pc" agent sha arch
  install -m 0644 "$SITE_DIR/runtime/pc/Install-PatchGateAgent.ps1" "$pc/Install-PatchGateAgent.ps1"
  # double-click wrapper (older bundles do not have it)
  if [ -f "$SITE_DIR/runtime/pc/Install-PatchGateAgent.cmd" ]; then install -m 0644 "$SITE_DIR/runtime/pc/Install-PatchGateAgent.cmd" "$pc/Install-PatchGateAgent.cmd"; fi
  install -m 0644 "$SITE_DIR/tls/bank-ca.pem" "$pc/bank-ca.pem"
  # Optional siteIp (hosts entries on PCs whose DNS lacks the site names): known when the ports bind to one IP.
  local site_ip_line=""
  if [ "$BIND_IP" != 0.0.0.0 ]; then site_ip_line="  \"siteIp\": \"$BIND_IP\","; fi
  for arch in amd64 386; do
    agent="tacticalagent-v${AGENT_VERSION}-windows-${arch}.exe"
    [ -f "$SITE_DIR/runtime/agent/$agent" ] && install -m 0644 "$SITE_DIR/runtime/agent/$agent" "$pc/$agent"
  done
  agent="tacticalagent-v${AGENT_VERSION}-windows-amd64.exe"
  sha="$(awk -v f="$agent" '$2==f || $2=="*"f {print $1}' "$SITE_DIR/runtime/agent/AGENT-SHA256SUMS")"
  local sha386; sha386="$(awk -v f="tacticalagent-v${AGENT_VERSION}-windows-386.exe" '$2==f || $2=="*"f {print $1}' "$SITE_DIR/runtime/agent/AGENT-SHA256SUMS")"
  local cache; cache="https://pg-cache.$SITE_DOMAIN$( [ "$CACHE_PORT" = 443 ] || printf ":%s" "$CACHE_PORT")/repo"
  ( umask 027
    cat > "$pc/patchgate-pc.json" <<JSON
{${site_ip_line:+
$site_ip_line}
  "siteName": "$(json_esc "$SITE_NAME")",
  "tacticalApiUrl": "https://api.$SITE_DOMAIN",
  "cacheUrl": "$cache",
  "agentVersion": "$AGENT_VERSION",
  "agentRepoPath": "tactical/agent/$AGENT_VERSION/$agent",
  "agentSha256": "$sha",
  "agentRepoPath386": "tactical/agent/$AGENT_VERSION/tacticalagent-v${AGENT_VERSION}-windows-386.exe",
  "agentSha256_386": "$sha386",
  "clientId": $(jfield clientId),
  "siteId": $(jfield siteId),
  "installToken": "$(jfield installToken)",
  "installTokenExpiresAt": "$(jfield installTokenExpiresAt)",
  "caFile": "bank-ca.pem",
  "hostNames": ["rmm.$SITE_DOMAIN", "api.$SITE_DOMAIN", "mesh.$SITE_DOMAIN", "pg-cache.$SITE_DOMAIN"]
}
JSON
  )
  chmod 0640 "$pc/patchgate-pc.json"
  ok "PC kit in $pc (install token valid until $(jfield installTokenExpiresAt); renew: install-site.sh --pc-token)"
}

summary() {
  step "Summary"
  local vm_ip; vm_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  cat <<TXT
    Site                 $SITE_NAME   (bundle $BUNDLE_VERSION, Tactical $TACTICAL_VERSION, agent $AGENT_VERSION, $([ "$ONLINE" = 1 ] && echo online || echo offline) install)
    Tactical             https://rmm.$SITE_DOMAIN   (admin user: tacticaladmin)
    Package cache        https://pg-cache.$SITE_DOMAIN:$CACHE_PORT/repo
    PatchGate            ${SERVER_URL:-not set}   enrolment: $(if enrolled; then echo enrolled; elif [ "$ENROL_FAILED" = 1 ]; then echo FAILED; else echo pending; fi)
    Connector check      $CHECK_RESULT
    Isolation            $ISOLATION
    Log                  $LOG_FILE

    DNS (bank): point rmm/api/mesh/pg-cache.$SITE_DOMAIN to this VM (${vm_ip:-<VM IP>}).
    Firewall (bank): this VM -> ONLY $(TV PG_HOST):$(TV PG_PORT) outbound; PCs -> this VM tcp/443 + tcp/$CACHE_PORT.

    Step 3 — on each bank PC (admin PowerShell), or as a GPO startup script:
      1. copy $SITE_DIR/pc/ to a share the PCs can read, e.g. \\\\fileserver\\patchgate$ (read-only for computers)
      2. powershell -ExecutionPolicy Bypass -File \\\\fileserver\\patchgate$\\Install-PatchGateAgent.ps1 -ConfigFile \\\\fileserver\\patchgate$\\patchgate-pc.json
    The agent is taken from the site cache once PatchGate has cached it (Connectors -> site -> "Cache agent"),
    otherwise from the copy next to the script (SHA-256 checked either way).
TXT
  if [ ${#WARNINGS[@]} -gt 0 ]; then
    printf '\n    %sAttention:%s\n' "$C_Y" "$C_0"
    local w; for w in "${WARNINGS[@]}"; do printf '     - %s\n' "$w"; done
  fi
  if [ "$FIRST_TACTICAL" = 1 ]; then
    term ""
    term "    Break-glass account 'tacticaladmin' password (shown ONCE, not logged; stored root-only in $SITE_DIR/tactical.env):"
    term "        $(sed -n 's/^TRMM_PASS=//p' "$SITE_DIR/tactical.env")"
    term "    Tactical is SEALED: its dashboard login is blocked. Patches and installs go through PatchGate only."
    term "    Emergency only: sudo $SITE_DIR/runtime/install-site.sh --break-glass on   (alerted in PatchGate), then set up"
    term "    two-factor authentication at https://rmm.$SITE_DOMAIN, and --break-glass off when done."
  fi
}

# ------------------------------------------------------------------ modes
do_install() {
  preflight
  install_docker
  load_images
  collect_answers
  setup_tls
  install_runtime
  BUNDLE_VERSION="${BUNDLE_VERSION:-}"; save_state
  start_tactical
  provision_tactical
  write_connector_files
  enrol_connector
  start_connector
  prove_isolation
  write_pc_kit
  save_state
  offer_lockdown
  summary
  [ "$ENROL_FAILED" = 0 ] || exit 3
}

do_status() {
  [ -f "$SITE_DIR/site.env" ] || die "no site installed in $SITE_DIR"
  set_dc
  step "PatchGate site status ($SITE_NAME, bundle $INSTALLED_BUNDLE)"
  "${DC[@]}" ps --format 'table {{.Service}}\t{{.Status}}' 2>/dev/null | sed 's/^/    /'
  if docker inspect pg-site-connector >/dev/null 2>&1; then
    step "Connector check"
    docker exec pg-site-connector node /opt/patchgate-connector/patchgate-connector.mjs check 2>&1 | sed 's/^/    /' || true
  fi
  local end; end="$(openssl x509 -in "$SITE_DIR/tls/site-cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2)"
  info "site certificate valid until: ${end:-unknown}"
  [ -f "$SITE_DIR/pc/patchgate-pc.json" ] && info "PC install token valid until: $(sed -nE 's/.*"installTokenExpiresAt": *"([^"]+)".*/\1/p' "$SITE_DIR/pc/patchgate-pc.json")"
  seal_status
}

do_pc_token() {
  [ -f "$SITE_DIR/site.env" ] || die "no site installed in $SITE_DIR"
  BUNDLE_DIR="$SITE_DIR/runtime"; load_bundle_env; set_dc
  docker inspect trmm-backend >/dev/null 2>&1 || die "Tactical is not running"
  provision_tactical
  write_pc_kit
  ok "new PC install token written to $SITE_DIR/pc/patchgate-pc.json — copy it to the PC share again"
}

# Run tactical/break-glass.py (on | off | check) in the Tactical backend; prints its PATCHGATE_* result line.
seal_script() { # state by marker
  docker cp "$SITE_DIR/runtime/tactical/break-glass.py" trmm-backend:/tmp/pg-break-glass.py >/dev/null
  printf '{"state":"%s","by":"%s"}' "$1" "$2" | docker exec -i -u 0 trmm-backend sh -c 'cat > /tmp/pg-break-glass-args.json && chmod 0644 /tmp/pg-break-glass-args.json /tmp/pg-break-glass.py'
  local out
  out="$(docker exec -w /opt/tactical/api trmm-backend sh -c 'python manage.py shell < /tmp/pg-break-glass.py' 2>&1 || true)"
  docker exec -u 0 trmm-backend rm -f /tmp/pg-break-glass-args.json /tmp/pg-break-glass.py >/dev/null 2>&1 || true
  printf '%s\n' "$out" | grep "^$3=" | tail -1 || { printf '%s\n' "$out" | grep -viE 'key|token|pass' | tail -10 | sed 's/^/    /' >&2; return 1; }
}

do_break_glass() {
  [ -f "$SITE_DIR/site.env" ] || die "no site installed in $SITE_DIR"
  case "$BREAK_GLASS_STATE" in on|off) ;; *) die "--break-glass needs on or off" ;; esac
  docker inspect trmm-backend >/dev/null 2>&1 || die "Tactical is not running"
  step "Break-glass $BREAK_GLASS_STATE (sealed Tactical)"
  local by; by="$(printf '%s@%s' "${SUDO_USER:-root}" "$(hostname 2>/dev/null || echo site-vm)" | tr -cd 'A-Za-z0-9@._-')"
  seal_script "$BREAK_GLASS_STATE" "$by" PATCHGATE_BREAK_GLASS >/dev/null || die "break-glass $BREAK_GLASS_STATE failed"
  ( umask 077; printf '%s\n' "$BREAK_GLASS_STATE" > "$SITE_DIR/state/break-glass" )
  logger -t patchgate-site "break-glass $BREAK_GLASS_STATE for tacticaladmin by $by" 2>/dev/null || true
  if [ "$BREAK_GLASS_STATE" = on ]; then
    ok "tacticaladmin may sign in at https://rmm.$(TV SITE_DOMAIN) (password: TRMM_PASS in $SITE_DIR/tactical.env, root-only)"
    warn "PatchGate alerts the bank's and the platform's admins (Tactical activity). Do NOT approve or install patches here; run --break-glass off when done"
  else
    ok "tacticaladmin blocked again, its dashboard sessions ended"
  fi
  info "recorded in Tactical's audit log -> reported to PatchGate within ~1 minute"
}

# Read-only sealed-state self-check (--status).
seal_status() {
  docker inspect trmm-backend >/dev/null 2>&1 || { warn "Tactical is not running: seal not checked"; return 0; }
  if nats_running; then ok "Tactical NATS message bus running"; else warn "Tactical NATS message bus NOT running: PCs cannot be reached (fix: docker restart trmm-nats)"; fi
  step "Tactical seal"
  local line; line="$(seal_script check status PATCHGATE_SEAL_CHECK)" || { warn "seal check failed"; return 0; }
  PROV="$(mktemp)"; printf '%s\n' "${line#PATCHGATE_SEAL_CHECK=}" > "$PROV"
  local users="" u bg; bg="$(break_glass_state)"
  # the break-glass account may be open while break-glass is on; anyone else open = seal broken
  for u in $(jfield openDashboardUsers | tr ';' ' '); do
    if [ "$u" = tacticaladmin ] && [ "$bg" = on ]; then continue; fi
    users="$users $u"
  done
  if [ "$bg" = on ]; then warn "break-glass is ON (tacticaladmin can sign in): run --break-glass off when done"; fi
  if [ -n "$users" ]; then warn "dashboard login OPEN for:$users (re-seal: --pc-token or --upgrade)"; else ok "dashboard login blocked"; fi
  if [ "$(jfield otherValidApiKeys)" = 0 ]; then ok "no other valid API keys"; else warn "$(jfield otherValidApiKeys) other valid API key(s) in Tactical"; fi
  if [ "$(jfield nonManualPatchPolicies)" = 0 ]; then ok "no patch policy auto-approves"; else warn "$(jfield nonManualPatchPolicies) patch policy(ies) auto-approve updates (re-seal: --upgrade)"; fi
  if [ "$(jfield agentAutoUpdate)" = off ]; then ok "agent auto-update off (agents upgrade only through PatchGate)"; else warn "agent auto-update is ON in Tactical"; fi
  if [ "$(jfield svcAuditRead)" = yes ]; then ok "service account can read the audit log"; else warn "service account cannot read the audit log (re-run --pc-token to re-provision)"; fi
  rm -f "$PROV"; PROV=""
}

do_uninstall() {
  [ -d "$SITE_DIR" ] || die "no site installed in $SITE_DIR"
  step "Uninstall the PatchGate site"
  if [ "$PURGE" = 1 ] && [ "$ASSUME_YES" != 1 ]; then
    [ "$NONINTERACTIVE" != 1 ] && [ -r /dev/tty ] || die "--purge needs --yes in non-interactive mode"
    local a=""; printf '    This deletes Tactical (all agents/history), the connector key and cache. Type PURGE: ' >/dev/tty
    IFS= read -r a </dev/tty || true; [ "$a" = PURGE ] || die "not confirmed — nothing deleted"
  fi
  if [ -f "$SITE_DIR/site.env" ] && command -v docker >/dev/null 2>&1; then
    set_dc
    if [ "$PURGE" = 1 ]; then "${DC[@]}" down -v --remove-orphans 2>&1 | tail -2 | sed 's/^/    /' || true
    else "${DC[@]}" down --remove-orphans 2>&1 | tail -2 | sed 's/^/    /' || true; fi
  fi
  ok "containers and networks removed"
  if [ "$PURGE" = 1 ]; then
    if [ -f "$SITE_DIR/runtime/images/IMAGES.txt" ] || [ -f "$SITE_DIR/runtime/bundle.env" ]; then
      # shellcheck disable=SC1091
      . "$SITE_DIR/runtime/bundle.env" 2>/dev/null || true
    fi
    rm -rf "${SITE_DIR:?}"
    ok "purged $SITE_DIR (Tactical data, connector key, cache, certificates). Revoke the connector in PatchGate."
  else
    ok "data kept (docker volumes + $SITE_DIR). Re-install: run install-site.sh again. Delete all: --uninstall --purge"
  fi
}

main() {
  parse_args "$@"
  [ "$(id -u)" = 0 ] || die "run as root (sudo ...)"
  setup_logging
  load_state
  case "$MODE" in
    install|upgrade)
      [ -n "${PG_BUNDLE_VERIFIED:-}" ] || resolve_bundle
      [ -n "$BUNDLE_DIR" ] || die "no bundle found"
      if [ -z "${PG_BUNDLE_VERIFIED:-}" ]; then sha_check_dir "$BUNDLE_DIR"; ok "bundle content verified (SHA256SUMS)"; fi
      load_bundle_env
      if [ "$MODE" = upgrade ]; then
        [ -f "$SITE_DIR/site.env" ] || die "no site installed yet: install first"
        step "Upgrade ${INSTALLED_BUNDLE:-?} -> $BUNDLE_VERSION"
      fi
      do_install ;;
    status) do_status ;;
    pctoken) do_pc_token ;;
    uninstall) do_uninstall ;;
    breakglass) do_break_glass ;;
  esac
}

main "$@"
