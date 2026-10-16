#!/usr/bin/env bash
# PatchGate colleague test kit — the WHOLE system on one PC with ONE command (TEST SETUP ONLY).
#
#   ./test-on-my-pc.sh              install everything (about 25-40 minutes), or resume an interrupted run
#   ./test-on-my-pc.sh --status     containers, URL, connector health
#   ./test-on-my-pc.sh --code WHO   current 6-digit sign-in code (WHO: platform-admin|operator|bank-admin|approver)
#   ./test-on-my-pc.sh --cleanup    remove ONLY this kit's containers, network and volumes (logs are kept)
#
# Two privileged Ubuntu 24.04 containers stand in for two VMs: "pgkit-server" (the PatchGate server, installed
# with the REAL installers/server/install-patchgate.sh from this kit's release images) and "pgkit-site" (a bank
# site VM with internet: the REAL one-line site install, which downloads the signed site bundle from PatchGate and
# pulls Tactical RMM from Docker Hub, digest-pinned). Runs from Git Bash on Windows (Docker Desktop) and on Linux.
# Self-signed TLS, throwaway signing key, everything on one PC: NOT how a bank is installed (docs/TEAM-GUIDE.md).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'   # Git Bash: never rewrite container paths like /root/kit

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d '\r\n' < "$KIT/VERSION")"
LABEL="com.patchgate.kit=colleague-test"
SERVER=pgkit-server; SITE=pgkit-site; NET=pgkit-net
VOL_SERVER=pgkit-server-docker; VOL_SITE=pgkit-site-docker
BASE_IMAGE="ubuntu:24.04"
DOMAIN="patchgate.pgi.test"
SITE_DOMAIN="test-bank.pgi.test"
SUBNETS=(172.33.0.0/24 172.34.0.0/24 172.35.0.0/24 172.36.0.0/24 172.37.0.0/24 10.233.33.0/24 10.234.34.0/24)
PORTS=(443 9443 10443 11443 12443 13443 8444)
LOGS="$KIT/logs"
STATE="$LOGS/kit-state.env"
LOGINS="$KIT/logins.txt"
CA_OUT="$KIT/patchgate-test-ca.pem"
mkdir -p "$LOGS"

# ------------------------------------------------------------------ output
if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B=""; G=""; Y=""; R=""; N=""; fi
TOTAL_STEPS=12
STEP_NO=0; STEP_T0=0; TIMES=()
step() { # title
  end_step
  STEP_NO=$((STEP_NO + 1)); STEP_T0=$(date +%s); STEP_NAME="$1"
  printf '\n%s[%d/%d] %s%s   (%s)\n' "$B" "$STEP_NO" "$TOTAL_STEPS" "$1" "$N" "$(date +%H:%M:%S)"
}
end_step() {
  [ "$STEP_NO" -gt 0 ] && [ "$STEP_T0" -gt 0 ] || return 0
  local s=$(( $(date +%s) - STEP_T0 ))
  TIMES+=("$(printf '%2d. %-52s %3dm%02ds' "$STEP_NO" "$STEP_NAME" $((s / 60)) $((s % 60)))")
  STEP_T0=0
}
ok()   { printf '    %sOK%s   %s\n' "$G" "$N" "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    %sWARN%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%sFAILED%s %s\n' "$R" "$N" "$*" >&2; printf '       Log: %s\n       Re-run ./test-on-my-pc.sh to resume, or ./test-on-my-pc.sh --cleanup to start over.\n' "${LOG_FILE:-$LOGS}" >&2; exit 1; }

hostpath() { # local path -> a form docker.exe understands (Git Bash: D:/x/y; Linux: unchanged)
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}
dx() { docker exec "$@"; }
in_server() { docker exec -e KIT_DOMAIN="$DOMAIN" "$SERVER" bash /root/kit/lib/server-steps.sh "$@"; }
in_site() { docker exec -e KIT_DOMAIN="$DOMAIN" -e KIT_SITE_DOMAIN="$SITE_DOMAIN" "$SITE" bash /root/kit/lib/site-steps.sh "$@"; }
exists() { docker inspect "$1" >/dev/null 2>&1; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = true ]; }
mark_done() { dx "$1" sh -c "mkdir -p /root/kit/done && touch /root/kit/done/$2"; }
is_done() { exists "$1" && running "$1" && dx "$1" test -f "/root/kit/done/$2" 2>/dev/null; }
# shellcheck disable=SC1090
load_state() { [ -f "$STATE" ] && . "$STATE"; return 0; }
save_state() {
  { echo "# test-on-my-pc.sh choices (no secrets)"; echo "SUBNET=$SUBNET"; echo "SERVER_IP=$SERVER_IP"; echo "SITE_IP=$SITE_IP"; echo "HOST_PORT=$HOST_PORT"; } > "$STATE"
}
url_port() { [ "${HOST_PORT:-443}" = 443 ] && printf '' || printf ':%s' "$HOST_PORT"; }

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

# ------------------------------------------------------------------ --cleanup
do_cleanup() {
  echo "${B}Removing the PatchGate test kit (label $LABEL) — nothing else is touched${N}"
  local ids
  ids="$(docker ps -aq --filter "label=$LABEL")"
  if [ -n "$ids" ]; then
    docker ps -a --filter "label=$LABEL" --format '    container {{.Names}}'
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null
  fi
  docker network ls -q --filter "label=$LABEL" | while read -r n; do
    echo "    network $(docker network inspect -f '{{.Name}}' "$n")"; docker network rm "$n" >/dev/null
  done
  docker volume ls -q --filter "label=$LABEL" | while read -r v; do
    echo "    volume $v"; docker volume rm "$v" >/dev/null
  done
  rm -f "$STATE"
  [ -f "$LOGINS" ] && { rm -f "$LOGINS"; echo "    logins.txt (its accounts no longer exist)"; }
  echo "    kept: logs in $LOGS"
  echo
  echo "If you added the hosts entry, remove it again (PowerShell as Administrator):"
  echo "  (Get-Content \$env:windir\\System32\\drivers\\etc\\hosts) -notmatch 'patchgate\\.pgi\\.test' | Set-Content \$env:windir\\System32\\drivers\\etc\\hosts"
  echo "Linux/macOS:  sudo sed -i.bak '/patchgate\\.pgi\\.test/d' /etc/hosts"
  echo "(The base image $BASE_IMAGE stays cached: docker image rm $BASE_IMAGE if you want it gone.)"
}

# ------------------------------------------------------------------ --status / --code
do_status() {
  load_state
  echo "${B}PatchGate test kit status${N}"
  docker ps -a --filter "label=$LABEL" --format '    {{.Names}}\t{{.Status}}\t{{.Ports}}'
  [ -n "$(docker ps -aq --filter "label=$LABEL")" ] || { echo "    (no kit containers: run ./test-on-my-pc.sh)"; return 0; }
  if running "$SERVER" && dx "$SERVER" test -f /opt/patchgate/deploy/.env.production; then
    echo; echo "  PatchGate server stack:"; in_server ps 2>/dev/null | sed 's/^/    /' || true
    echo; echo "  Connector (server view: name | status | last seen | online):"
    in_server connector-status 2>/dev/null | sed 's/^/    /' || echo "    (database not reachable)"
  fi
  if running "$SITE" && dx "$SITE" sh -c 'docker inspect pg-site-connector >/dev/null 2>&1'; then
    echo; echo "  Connector self-check (site view):"; in_site check || true
  fi
  if [ -n "${HOST_PORT:-}" ]; then
    echo; echo "  URL: https://$DOMAIN$(url_port)/   (needs the hosts line 127.0.0.1 $DOMAIN, see START-HERE.md)"
    local code; code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$CA_OUT" --resolve "$DOMAIN:$HOST_PORT:127.0.0.1" "https://$DOMAIN:$HOST_PORT/login" 2>/dev/null || true)"
    echo "  From this PC: https://$DOMAIN$(url_port)/login -> HTTP ${code:-none}"
    [ -f "$LOGINS" ] && echo "  Accounts: $LOGINS"
  fi
}
do_code() {
  running "$SERVER" || die "the kit is not running (./test-on-my-pc.sh)"
  in_server totp "$1"
}

# ------------------------------------------------------------------ steps
preflight() {
  step "Preflight: Docker, memory, disk, internet, network, port"
  command -v docker >/dev/null 2>&1 || die "docker not found. Windows: install Docker Desktop (WSL2) and open it. Linux: install Docker Engine."
  docker info >/dev/null 2>&1 || die "Docker is not running. Windows: start Docker Desktop and wait until it says 'Engine running'. Linux: sudo systemctl start docker (or add yourself to the docker group)."
  local os mem_b mem_gb ncpu
  os="$(docker info --format '{{.OperatingSystem}}')"; ncpu="$(docker info --format '{{.NCPU}}')"
  mem_b="$(docker info --format '{{.MemTotal}}')"; mem_gb=$(( mem_b / 1024 / 1024 / 1024 ))
  ok "Docker $(docker version --format '{{.Server.Version}}') on $os, $ncpu CPUs"
  [ "$(docker info --format '{{.OSType}}')" = linux ] || die "Docker must run Linux containers (Docker Desktop: switch to Linux containers)"
  [ "$(docker info --format '{{.Architecture}}')" = x86_64 ] || die "x86-64 required (found $(docker info --format '{{.Architecture}}'))"
  [ "$mem_gb" -ge 11 ] || die "Docker can use only ${mem_gb} GB RAM; at least 12 GB needed (16 GB recommended). Docker Desktop: Settings -> Resources (or %UserProfile%\\.wslconfig: [wsl2] memory=16GB, then 'wsl --shutdown')."
  if [ "$mem_gb" -lt 15 ]; then warn "Docker can use ${mem_gb} GB RAM (16 GB recommended): it will work but be slow"; else ok "${mem_gb} GB RAM available to Docker"; fi
  info "pulling $BASE_IMAGE from Docker Hub (also tests that Docker Hub is reachable)"
  docker pull -q "$BASE_IMAGE" >/dev/null 2>&1 || die "cannot pull $BASE_IMAGE from Docker Hub. Corporate proxy? Docker Desktop: Settings -> Resources -> Proxies. Then re-run."
  local free_gb
  free_gb="$(docker run --rm "$BASE_IMAGE" df -Pk / | awk 'NR==2 {printf "%d", $4/1024/1024}')"
  [ "$free_gb" -ge 20 ] || die "only ${free_gb} GB free in Docker's disk; 20 GB needed (Docker Desktop: Settings -> Resources -> Disk image size, or docker system prune)"
  ok "${free_gb} GB free disk for Docker"
  local u code fail=0
  for u in https://registry-1.docker.io/v2/ https://download.docker.com/linux/ubuntu/gpg; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$u" 2>/dev/null || true)"
    case "$code" in 200|401) ok "internet: $u (HTTP $code)" ;; *) warn "internet: $u -> ${code:-no answer} from this PC"; fail=1 ;; esac
  done
  if [ "$fail" = 1 ]; then
    # The containers' view is what matters (Docker Desktop may use its own proxy settings).
    docker run --rm "$BASE_IMAGE" bash -c 'exec 3<>/dev/tcp/download.docker.com/443' 2>/dev/null \
      && ok "download.docker.com reachable from containers" \
      || die "download.docker.com (Docker's apt repository) not reachable: corporate proxy/firewall? Ask IT to allow registry-1.docker.io, production.cloudflare.docker.com, download.docker.com, auth.docker.io."
  fi
  load_state
  if exists "$NET"; then
    SUBNET="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$NET")"; ok "network $NET exists ($SUBNET)"
  else
    SUBNET=""
    local s
    for s in "${SUBNETS[@]}"; do
      if docker network create --label "$LABEL" --subnet "$s" "$NET" >/dev/null 2>&1; then SUBNET="$s"; break; fi
      info "subnet $s is taken on this PC, trying the next one"
    done
    [ -n "$SUBNET" ] || die "could not create a Docker network on any of: ${SUBNETS[*]}"
    ok "network $NET created on $SUBNET"
  fi
  local pfx="${SUBNET%.*}"; SERVER_IP="$pfx.2"; SITE_IP="$pfx.4"
  if exists "$SERVER"; then
    HOST_PORT="$(docker inspect -f '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostPort}}{{end}}{{end}}' "$SERVER")"
    ok "server container exists, PatchGate published on 127.0.0.1:$HOST_PORT"
  else
    HOST_PORT=""
    local p
    for p in "${PORTS[@]}"; do
      if docker run -d --rm --name pgkit-portprobe --label "$LABEL" -p "127.0.0.1:$p:443" "$BASE_IMAGE" sleep 3 >/dev/null 2>&1; then
        docker rm -f pgkit-portprobe >/dev/null 2>&1 || true; HOST_PORT="$p"; break
      fi
      docker rm -f pgkit-portprobe >/dev/null 2>&1 || true
      info "port 127.0.0.1:$p is in use on this PC, trying the next one"
    done
    [ -n "$HOST_PORT" ] || die "no free port among ${PORTS[*]} on 127.0.0.1"
    ok "PatchGate will be published on 127.0.0.1:$HOST_PORT"
  fi
  save_state
}

make_container() { # name ip volume add-host-ip extra-args...
  local name="$1" ip="$2" vol="$3" hostip="$4"; shift 4
  if exists "$name"; then
    running "$name" || { docker start "$name" >/dev/null; sleep 3; }
    ok "$name exists ($(docker inspect -f '{{.State.Status}}' "$name"), $ip)"; return 0
  fi
  docker volume inspect "$vol" >/dev/null 2>&1 || docker volume create --label "$LABEL" "$vol" >/dev/null
  docker create --name "$name" --hostname "$name" --label "$LABEL" --privileged --init --cgroupns private \
    --network "$NET" --ip "$ip" --add-host "$DOMAIN:$hostip" -v "$vol:/var/lib/docker" \
    "$@" "$BASE_IMAGE" bash /usr/local/sbin/kit-boot.sh >/dev/null
  docker cp "$(hostpath "$KIT/lib/kit-boot.sh")" "$name:/usr/local/sbin/kit-boot.sh"
  docker start "$name" >/dev/null || die "could not start $name (docker logs $name)"
  sleep 2
  running "$name" || die "$name stopped right after start: $(docker logs --tail 5 "$name" 2>&1)"
  dx "$name" mkdir -p /root/kit/lib
  docker cp "$(hostpath "$KIT/lib")/." "$name:/root/kit/lib/"
  docker cp "$(hostpath "$KIT/VERSION")" "$name:/root/kit/VERSION"
  ok "$name created ($ip, privileged Ubuntu 24.04 with its own Docker data volume $vol)"
}

containers() {
  step "Containers: server ($SERVER_IP) and bank site ($SITE_IP)"
  # Inside the server its own name must point at itself (127.0.0.1): nginx only answers /api/ready to
  # private/loopback sources, and the smoke test runs on the server. The site resolves it to the server's IP.
  make_container "$SERVER" "$SERVER_IP" "$VOL_SERVER" 127.0.0.1 -p "127.0.0.1:$HOST_PORT:443"
  make_container "$SITE" "$SITE_IP" "$VOL_SITE" "$SERVER_IP"
  # Refresh the kit scripts on resume (harmless on the first run).
  docker cp "$(hostpath "$KIT/lib")/." "$SERVER:/root/kit/lib/"
  docker cp "$(hostpath "$KIT/lib")/." "$SITE:/root/kit/lib/"
}

server_docker() {
  step "Docker Engine inside the server (download.docker.com, key-pinned)"
  if is_done "$SERVER" docker; then dx "$SERVER" bash /root/kit/lib/install-docker.sh | sed 's/^/    /'; ok "already installed"; return; fi
  dx "$SERVER" bash /root/kit/lib/install-docker.sh 2>&1 | sed 's/^/    /' || die "installing Docker in $SERVER failed"
  mark_done "$SERVER" docker; ok "inner Docker running"
}

server_images() {
  step "PatchGate $VERSION images -> server (docker load from the kit)"
  if is_done "$SERVER" images; then ok "already loaded"; return; fi
  info "copying $(du -sh "$KIT/images" | cut -f1) of image archives into $SERVER"
  dx "$SERVER" mkdir -p /root/kit/images /root/kit/product /root/kit/site-bundle
  docker cp "$(hostpath "$KIT/images")/." "$SERVER:/root/kit/images/"
  in_server load-images || die "docker load failed"
  mark_done "$SERVER" images; ok "6 images loaded (web, tools, signer, egress-proxy, backup, connector)"
}

server_install() {
  step "PatchGate server: installers/server/install-patchgate.sh (real installer, 5-15 min)"
  if is_done "$SERVER" install; then ok "already installed"; return; fi
  docker cp "$(hostpath "$KIT/product")/." "$SERVER:/root/kit/product/"
  local rc=0
  in_server install || rc=$?
  [ "$rc" = 0 ] || die "server installer exited with $rc (see above; full log inside: docker exec $SERVER cat /var/log/patchgate-install.log)"
  dx "$SERVER" test -s /root/kit/secret/admin-temp-password || die "the installer's one-time admin password was not captured"
  docker cp "$SERVER:/opt/patchgate/deploy/tls/selfsigned-ca.pem" "$(hostpath "$CA_OUT")"
  mark_done "$SERVER" install; ok "server installed; test CA saved to $(basename "$CA_OUT")"
}

accounts() {
  step "Test bank + accounts through the real admin API (sign-in with password + TOTP)"
  if is_done "$SERVER" accounts; then ok "already created"; return; fi
  in_server accounts || die "creating the test bank/accounts failed"
  write_logins
  mark_done "$SERVER" accounts; ok "bank \"Test Bank\" (test-bank) and 4 accounts ready; logins.txt written"
}

bundle() {
  step "Site bundle: sign (throwaway key), upload, set PATCHGATE_SITE_BUNDLE_PUBKEY, rolling restart"
  if is_done "$SERVER" bundle; then ok "already uploaded"; return; fi
  docker cp "$(hostpath "$KIT/site-bundle")/." "$SERVER:/root/kit/site-bundle/"
  in_server bundle || die "bundle upload failed"
  mark_done "$SERVER" bundle; ok "online site bundle $VERSION served by PatchGate (signed)"
}

allowlist() {
  step "Connector allow-list: site address $SITE_IP (RUNBOOK §6 step 4)"
  in_server allowlist "$SITE_IP" || die "allow-list update failed"
  mark_done "$SERVER" allowlist
}

site_install() {
  step "Bank site: one-line ONLINE install (Docker from download.docker.com, Tactical from Docker Hub; 10-20 min)"
  if is_done "$SITE" install; then ok "already installed"; return; fi
  in_site prep || die "preparing the site container failed (internet?)"
  docker cp "$(hostpath "$CA_OUT")" "$SITE:/root/kit/patchgate-ca.pem"
  if ! dx "$SITE" test -f /opt/patchgate-site/etc/connector.json || ! dx "$SITE" grep -q '"identity"' /opt/patchgate-site/etc/connector.json; then
    in_server enrol "Head office" || die "creating the enrolment code failed"
    # The code goes server -> site through a pipe: never on screen, in a log or on a command line here.
    dx "$SERVER" cat /root/kit/secret/enrol.env | docker exec -i "$SITE" sh -c 'umask 077; cat > /root/kit/enrol.env'
  fi
  local rc=0
  in_site install "$SERVER_IP" || rc=$?
  dx "$SITE" rm -f /root/kit/enrol.env
  [ "$rc" = 0 ] || die "site install exited with $rc (see above; log inside: docker exec $SITE cat /var/log/patchgate-site-install.log)"
  mark_done "$SITE" install; ok "site installed and enrolled"
  write_logins
}

wait_connector() {
  step "Connector ACTIVE and healthy (server and site view)"
  local line=""
  for _ in $(seq 1 36); do
    line="$(in_server connector-status 2>/dev/null | grep 'ACTIVE' | grep 'online' | head -1 || true)"
    [ -n "$line" ] && break
    sleep 5
  done
  [ -n "$line" ] || { in_server connector-status || true; die "connector not ACTIVE/online on the server after 3 minutes"; }
  ok "server: $line"
  local out; out="$(in_site check 2>&1 || true)"
  printf '%s\n' "$out"
  printf '%s' "$out" | grep -q '"healthy":true' || die "connector self-check is not healthy"
  ok "site: connector self-check healthy"
  info "Tactical images on the site (pulled from Docker Hub, digest-pinned):"
  in_site digests || true
}

smoke_and_host() {
  step "Smoke test (deploy/scripts/smoke-test.sh) + reachability from this PC"
  local rc
  set +e; in_server smoke 2>&1 | sed 's/^/    /'; rc=${PIPESTATUS[0]}; set -e
  if [ "$rc" = 0 ]; then ok "smoke test PASS"; else warn "smoke test reported $rc failed check(s) (see above)"; fi
  SMOKE_RC=$rc
  local code1 code2
  code1="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --cacert "$CA_OUT" --resolve "$DOMAIN:$HOST_PORT:127.0.0.1" "https://$DOMAIN:$HOST_PORT/api/health" || true)"
  code2="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --cacert "$CA_OUT" --resolve "$DOMAIN:$HOST_PORT:127.0.0.1" "https://$DOMAIN:$HOST_PORT/login" || true)"
  if [ "$code2" = 200 ]; then ok "from this PC: https://$DOMAIN$(url_port)/login -> 200, /api/health -> $code1 (certificate verified with $(basename "$CA_OUT"))"
  else warn "from this PC: /login -> ${code2:-no answer}, /api/health -> ${code1:-no answer}"; fi
  HOST_LOGIN=$code2
}

write_logins() {
  local tmp; tmp="$(mktemp "$KIT/.logins.XXXXXX")"
  chmod 600 "$tmp" 2>/dev/null || true
  {
    echo "PatchGate $VERSION TEST KIT - sign-in details (KEEP PRIVATE; test accounts only, deleted by --cleanup)"
    echo "URL: https://$DOMAIN$(url_port)/      (hosts line needed: 127.0.0.1 $DOMAIN - see START-HERE.md)"
    echo
    echo "Every account signs in with password + 6-digit authenticator code. Either:"
    echo "  - get the current code:   ./test-on-my-pc.sh --code approver      (platform-admin | operator | bank-admin | approver)"
    echo "  - or add the TOTP secret / otpauth URI below to an authenticator app (Microsoft/Google Authenticator: 'enter a setup key')."
    echo "  A code works once: wait for the next one if it is refused."
    echo
    in_server logins 2>/dev/null || echo "(accounts not created yet)"
    if dx "$SITE" test -s /root/kit/tactical-admin-password 2>/dev/null; then
      echo "[tactical-admin]  Tactical RMM web admin on the site (reachable only inside the site container; not needed for the test)"
      echo "  user         : tacticaladmin"
      echo "  password     : $(dx "$SITE" cat /root/kit/tactical-admin-password)"
      echo
    fi
  } > "$tmp"
  mv -f "$tmp" "$LOGINS"; chmod 600 "$LOGINS" 2>/dev/null || true
}

summary() {
  end_step
  local port_note=""
  [ "$HOST_PORT" = 443 ] || port_note=" (port $HOST_PORT because 443 is used by something else on this PC)"
  cat <<TXT

${B}==================== PatchGate $VERSION is running on this PC (TEST SETUP) ====================${N}

  Open:      https://$DOMAIN$(url_port)/$port_note
  Logins:    $LOGINS   (passwords + authenticator secrets; current code: ./test-on-my-pc.sh --code <who>)

  1) Once, as Administrator, add the name to the hosts file. PowerShell (Run as Administrator):
       Add-Content -Path \$env:windir\\System32\\drivers\\etc\\hosts -Value "\`r\`n127.0.0.1 $DOMAIN"
     Linux/macOS:  echo "127.0.0.1 $DOMAIN" | sudo tee -a /etc/hosts
  2) The browser warns about the certificate (self-signed test CA): click Advanced -> Continue.
     Optional, no warning: import $(basename "$CA_OUT") into "Trusted Root Certification Authorities"
     (certmgr.msc, Current User) — remove it again after testing.
     Without the hosts line you can still check it works: curl --cacert $(basename "$CA_OUT") --resolve $DOMAIN:$HOST_PORT:127.0.0.1 https://$DOMAIN:$HOST_PORT/login

  What to try:
   a. Sign in as ${B}operator${N} (operator@pgi.test): Patches -> pick an update -> create a change request for Test Bank.
   b. Sign in as ${B}platform-admin${N} (admin@pgi.test) and try to approve it -> refused: a Test Bank approver must
      always approve (platform staff cannot replace the bank's decision).
   c. Sign in as ${B}approver${N} (approver@test-bank.test) and approve it -> the change is released for the bank.
   d. Connectors page (platform-admin): site "Head office" of Test Bank is ACTIVE / online.
   e. Audit page: every sign-in, approval, enrolment and bundle download is in the bank's tamper-evident chain.
   f. bank-admin (admin@test-bank.test): Administration -> Users shows only Test Bank's users.

  Status:   ./test-on-my-pc.sh --status        Clean up:  ./test-on-my-pc.sh --cleanup
  Log:      $LOG_FILE

  Time per step:
TXT
  local t; for t in "${TIMES[@]}"; do echo "    $t"; done
  local total=$(( $(date +%s) - RUN_T0 ))
  echo "    total: $((total / 60))m$((total % 60))s"
}

# ------------------------------------------------------------------ main
MODE=install; RESUME=0; WHO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cleanup) MODE=cleanup; shift ;;
    --status) MODE=status; shift ;;
    --code|--totp) MODE=code; WHO="${2:-}"; [ -n "$WHO" ] || die "--code needs: platform-admin | operator | bank-admin | approver"; shift 2 ;;
    --resume) RESUME=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option $1"; usage; exit 2 ;;
  esac
done

case "$MODE" in
  cleanup) do_cleanup; exit 0 ;;
  status) do_status; exit 0 ;;
  code) do_code "$WHO"; exit 0 ;;
esac

[ -d "$KIT/images" ] && [ -d "$KIT/site-bundle" ] && [ -d "$KIT/product" ] || die "run this from the unpacked kit folder (images/, site-bundle/, product/ missing)"
if [ -n "$(docker ps -aq --filter "label=$LABEL" 2>/dev/null)" ] && [ "$RESUME" = 0 ]; then
  echo "The PatchGate test kit containers already exist on this PC:"
  docker ps -a --filter "label=$LABEL" --format '    {{.Names}}  {{.Status}}'
  if [ -t 0 ]; then
    printf 'Resume / re-check the existing installation? [Y/n] (n = stop; start over with --cleanup first): '
    read -r a || a=n
    case "${a:-y}" in [Yy]*) RESUME=1 ;; *) echo "Nothing changed. To start over: ./test-on-my-pc.sh --cleanup && ./test-on-my-pc.sh"; exit 0 ;; esac
  else
    echo "Not a terminal: use --resume to continue, or --cleanup to start over."; exit 1
  fi
fi

LOG_FILE="$LOGS/test-on-my-pc-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
RUN_T0=$(date +%s)
echo "PatchGate $VERSION colleague test kit — $(date '+%Y-%m-%d %H:%M:%S') — log $LOG_FILE"
echo "TEST SETUP: self-signed TLS, throwaway bundle-signing key, server + bank site on this one PC."

preflight
containers
server_docker
server_images
server_install
accounts
bundle
allowlist
site_install
wait_connector
smoke_and_host
step "Sign-in check (bank approver via the real login API) and logins.txt"
in_server check-login approver || warn "approver sign-in check failed"
write_logins
ok "logins.txt written ($(wc -l < "$LOGINS") lines, mode 600)"
summary
[ "${SMOKE_RC:-1}" = 0 ] && [ "${HOST_LOGIN:-}" = 200 ] || exit 4
