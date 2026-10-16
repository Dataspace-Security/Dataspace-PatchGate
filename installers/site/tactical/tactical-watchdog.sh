#!/usr/bin/env bash
# PatchGate site watchdog for Tactical RMM's NATS message bus (official images, NOT modified).
#
# Why: after a reboot of the site VM, trmm-nats can lose a start-up race with tactical-init (nats-server starts
# before nats-rmm.conf is (re)written, supervisor gives up). The container stays "Up", but Tactical answers every
# script run with "natsdown": no PC is reachable and PatchGate deployments cannot be delivered.
#
# What it does (one pass; run every minute by patchgate-tactical-watchdog.timer, or cron where there is no systemd):
#   1. Only acts when the site is meant to be up: trmm-backend running and trmm-init finished (exit 0).
#      Never touches any container except trmm-nats. Paused while install-site.sh runs (state/watchdog.pause).
#   2. Checks NATS exactly like install-site.sh --status: nats-server process inside trmm-nats (pgrep).
#   3. Down -> `docker restart trmm-nats` (or `docker start` if the container was stopped). Tactical opens a new NATS
#      connection per command, so backend / celery need no restart; agents reconnect by themselves.
#      Back-off: a restart only after the previous one had time to come up (1, 2, 4, 8 ... min apart) and at most
#      PG_WATCHDOG_MAX_RESTARTS restarts per hour (default 6); then it only reports until the hour has passed.
#   4. Writes a non-secret health file the connector reads for its heartbeat (PatchGate shows + alerts on it):
#      <site>/etc/tactical-health.json  {"v":1,"nats":"ok|down|starting|unknown","since":…,"checkedAt":…,…}
#   5. Logs every action to journald (systemd) or syslog (logger), tag patchgate-tactical-watchdog.
#
# Manual: sudo /opt/patchgate-site/runtime/tactical/tactical-watchdog.sh [--dry-run]
#         journalctl -t patchgate-tactical-watchdog  (or: journalctl -u patchgate-tactical-watchdog)
# Exit: 0 healthy / nothing to do, 1 NATS down (after any restart attempt), 2 usage / environment error.
set -euo pipefail
umask 027

SITE_DIR="${PG_SITE_DIR:-/opt/patchgate-site}"
STATE_DIR="${PG_WATCHDOG_STATE_DIR:-$SITE_DIR/state}"
HEALTH_FILE="${PG_WATCHDOG_HEALTH_FILE:-$SITE_DIR/etc/tactical-health.json}"
MAX_RESTARTS="${PG_WATCHDOG_MAX_RESTARTS:-6}"     # per rolling hour
BASE_GAP_SEC="${PG_WATCHDOG_BASE_GAP_SEC:-60}"    # gap after the 1st restart; doubles per restart in the hour
MAX_GAP_SEC=1200
START_GRACE_SEC="${PG_WATCHDOG_START_GRACE_SEC:-90}"  # entrypoint sleeps 15 s + waits for tactical-init
VERIFY_SEC="${PG_WATCHDOG_VERIFY_SEC:-60}"        # wait this long for nats-server after a restart
PAUSE_MAX_AGE_SEC=7200                            # a pause file older than this is ignored (crashed installer)
CONNECTOR_GID="${PG_WATCHDOG_HEALTH_GID:-1000}"   # the connector container runs as 1000:1000
NATS=trmm-nats
BACKEND=trmm-backend
INIT=trmm-init
TAG=patchgate-tactical-watchdog
DRY_RUN=0

case "${1:-}" in
  "") ;;
  --dry-run) DRY_RUN=1 ;;
  -h|--help) sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac
[[ "$MAX_RESTARTS" =~ ^[0-9]+$ ]] && [[ "$BASE_GAP_SEC" =~ ^[0-9]+$ ]] || { echo "invalid PG_WATCHDOG_* setting" >&2; exit 2; }

# journald captures stderr of a systemd unit; elsewhere use syslog when available.
log() { # priority message
  local pri="$1"; shift
  if [ -n "${JOURNAL_STREAM:-}" ] || ! command -v logger >/dev/null 2>&1; then
    printf '%s: %s\n' "$pri" "$*" >&2
  else
    logger -t "$TAG" -p "daemon.$pri" -- "$*" 2>/dev/null || printf '%s: %s\n' "$pri" "$*" >&2
  fi
}

command -v docker >/dev/null 2>&1 || { log err "docker not found"; exit 2; }
NOW="$(date -u +%s)"
iso() { date -u -d "@$1" +%FT%TZ 2>/dev/null || date -u -r "$1" +%FT%TZ; }

# One pass at a time (timer + a manual run).
mkdir -p "$STATE_DIR"
if command -v flock >/dev/null 2>&1; then
  exec 9>"$STATE_DIR/watchdog.lock"
  flock -n 9 || exit 0
fi

# ------------------------------------------------------------------ persistent state (non-secret)
STATE_FILE="$STATE_DIR/watchdog.state"
DOWN_SINCE=""           # epoch NATS was first seen down in this episode
RESTARTS=()             # epochs of restarts in the last hour
GAVE_UP_LOGGED=0
if [ -f "$STATE_FILE" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      DOWN_SINCE) if [[ "$v" =~ ^[0-9]+$ ]]; then DOWN_SINCE="$v"; fi ;;
      RESTART) if [[ "$v" =~ ^[0-9]+$ ]] && [ $((NOW - v)) -lt 3600 ]; then RESTARTS+=("$v"); fi ;;
      GAVE_UP_LOGGED) if [ "$v" = 1 ]; then GAVE_UP_LOGGED=1; fi ;;
    esac
  done < "$STATE_FILE"
fi
save_state() {
  [ "$DRY_RUN" = 1 ] && return 0
  local tmp="$STATE_FILE.tmp" r
  { printf 'DOWN_SINCE=%s\n' "$DOWN_SINCE"; for r in "${RESTARTS[@]}"; do printf 'RESTART=%s\n' "$r"; done; printf 'GAVE_UP_LOGGED=%s\n' "$GAVE_UP_LOGGED"; } > "$tmp"
  mv -f "$tmp" "$STATE_FILE"
}

# ------------------------------------------------------------------ health file for the connector
write_health() { # nats-state detail
  [ "$DRY_RUN" = 1 ] && return 0
  local dir; dir="$(dirname "$HEALTH_FILE")"
  [ -d "$dir" ] || return 0
  local since="null" last="null" tmp
  if [ -n "$DOWN_SINCE" ]; then since="\"$(iso "$DOWN_SINCE")\""; fi
  if [ "${#RESTARTS[@]}" -gt 0 ]; then last="\"$(iso "${RESTARTS[${#RESTARTS[@]}-1]}")\""; fi
  tmp="$(mktemp "$dir/.tactical-health.XXXXXX")"
  printf '{"v":1,"nats":"%s","since":%s,"checkedAt":"%s","restartsLastHour":%d,"lastRestartAt":%s,"maxRestartsPerHour":%d,"detail":"%s"}\n' \
    "$1" "$since" "$(iso "$NOW")" "${#RESTARTS[@]}" "$last" "$MAX_RESTARTS" "$2" > "$tmp"
  chmod 0640 "$tmp"
  chown "0:$CONNECTOR_GID" "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$HEALTH_FILE"
}

state_of() { docker inspect -f '{{.State.Status}} {{.State.ExitCode}} {{.State.StartedAt}}' "$1" 2>/dev/null || echo "missing 0 -"; }
started_epoch() { local s; s="$(docker inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null || true)"; date -u -d "$s" +%s 2>/dev/null || echo 0; }
# Same probe as install-site.sh nats_running (no pgrep in a future image = cannot tell = assume running).
nats_running() { docker exec "$NATS" sh -c 'command -v pgrep >/dev/null 2>&1 || exit 0; pgrep -x nats-server >/dev/null' 2>/dev/null; }

# ------------------------------------------------------------------ 1. is the site meant to be up?
pause="$STATE_DIR/watchdog.pause"
if [ -f "$pause" ]; then
  age=$((NOW - $(date -u -r "$pause" +%s 2>/dev/null || echo 0)))
  if [ "$age" -lt "$PAUSE_MAX_AGE_SEC" ]; then exit 0; fi
  log warning "ignoring stale pause file $pause (age ${age}s)"
fi
read -r b_status _ _ <<< "$(state_of "$BACKEND")"
read -r i_status i_exit _ <<< "$(state_of "$INIT")"
if [ "$b_status" != running ] || { [ "$i_status" != missing ] && { [ "$i_status" != exited ] || [ "$i_exit" != 0 ]; }; }; then
  # Site stopped, being installed, or tactical-init still running/failed: not ours to fix.
  write_health unknown "Tactical not running (backend $b_status, init $i_status $i_exit)"
  exit 0
fi

# ------------------------------------------------------------------ 2. NATS health
read -r n_status _ _ <<< "$(state_of "$NATS")"
if [ "$n_status" = missing ]; then
  log err "$NATS container missing: re-run install-site.sh --upgrade or the bank installer (not created by the watchdog)"
  [ -n "$DOWN_SINCE" ] || DOWN_SINCE="$NOW"
  save_state; write_health down "container $NATS missing"
  exit 1
fi
if [ "$n_status" = restarting ]; then
  write_health starting "docker is restarting $NATS"
  exit 0
fi
if [ "$n_status" = running ]; then
  if nats_running; then
    if [ -n "$DOWN_SINCE" ]; then log notice "Tactical NATS healthy again (was down since $(iso "$DOWN_SINCE"))"; fi
    DOWN_SINCE=""; GAVE_UP_LOGGED=0
    save_state; write_health ok "nats-server running"
    exit 0
  fi
  if [ $((NOW - $(started_epoch "$NATS"))) -lt "$START_GRACE_SEC" ]; then
    write_health starting "container started less than ${START_GRACE_SEC}s ago"
    exit 0
  fi
fi

# ------------------------------------------------------------------ 3. down: restart with back-off
[ -n "$DOWN_SINCE" ] || { DOWN_SINCE="$NOW"; log warning "Tactical NATS message bus is DOWN ($NATS $n_status, nats-server not running): PCs cannot be reached"; }
n="${#RESTARTS[@]}"
if [ "$n" -ge "$MAX_RESTARTS" ]; then
  if [ "$GAVE_UP_LOGGED" = 0 ]; then
    log err "Tactical NATS still down after $n restarts in the last hour: no more restarts until the hour has passed. Check: docker logs $NATS; docker logs $INIT"
    GAVE_UP_LOGGED=1
  fi
  save_state; write_health down "gave up for this hour after $n restarts"
  exit 1
fi
if [ "$n" -gt 0 ]; then
  gap=$((BASE_GAP_SEC << (n - 1))); [ "$gap" -le "$MAX_GAP_SEC" ] || gap="$MAX_GAP_SEC"
  last="${RESTARTS[$((n - 1))]}"
  if [ $((NOW - last)) -lt "$gap" ]; then
    save_state; write_health down "next restart in $((gap - (NOW - last)))s (back-off)"
    exit 1
  fi
fi
if [ "$DRY_RUN" = 1 ]; then
  log notice "dry run: would $([ "$n_status" = running ] && echo restart || echo start) $NATS (restart $((n + 1))/$MAX_RESTARTS this hour)"
  exit 1
fi
if [ "$n_status" = running ]; then action=restart; else action=start; fi
log warning "Tactical NATS down -> docker $action $NATS (restart $((n + 1))/$MAX_RESTARTS this hour)"
RESTARTS+=("$NOW"); save_state
if ! docker "$action" "$NATS" >/dev/null 2>&1; then
  log err "docker $action $NATS failed"
  write_health down "docker $action failed"
  exit 1
fi
write_health starting "restarted by the watchdog"
waited=0
while [ "$waited" -lt "$VERIFY_SEC" ]; do
  sleep 5; waited=$((waited + 5))
  if nats_running; then
    NOW="$(date -u +%s)"
    log notice "Tactical NATS running again after docker $action (${waited}s; down since $(iso "$DOWN_SINCE"))"
    DOWN_SINCE=""; GAVE_UP_LOGGED=0
    save_state; write_health ok "recovered by the watchdog"
    exit 0
  fi
done
NOW="$(date -u +%s)"
log warning "Tactical NATS not running ${VERIFY_SEC}s after docker $action: retrying with back-off"
save_state; write_health down "not running after docker $action"
exit 1
