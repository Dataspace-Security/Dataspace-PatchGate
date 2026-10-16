#!/bin/sh
# PatchGate scheduler: POST /api/worker/tick every TICK_INTERVAL_SECONDS (default 60) to the first
# healthy web instance, and POST /api/worker/fetch every FETCH_INTERVAL_SECONDS (default 3600) to the
# fetcher (the only container with internet egress). Both endpoints take DB leases, so overlapping or
# duplicated calls are harmless ("skipped"). A fetch can run for up to 2 h: it runs in the background
# and a new one is not started while the previous call is still open.
# Logs are JSON lines (same shape as src/lib/log.ts). The token is never logged or put on a command line.
set -u

TICK_TARGETS="${TICK_TARGETS:-http://web-1:3000 http://web-2:3000}"
FETCH_TARGET="${FETCH_TARGET:-http://fetcher:3000}"
TICK_INTERVAL="${TICK_INTERVAL_SECONDS:-60}"
FETCH_INTERVAL="${FETCH_INTERVAL_SECONDS:-3600}"
FETCH_MAX="${FETCH_MAX_SECONDS:-7200}"
TICK_MAX="${TICK_MAX_SECONDS:-600}"
STATE=/tmp/scheduler
mkdir -p "$STATE"

log() { # level msg [key value]...
  level="$1"; msg="$2"; shift 2
  extra=""
  while [ $# -ge 2 ]; do extra="$extra,\"$1\":\"$(printf '%s' "$2" | tr -d '"\\\n' | cut -c1-300)\""; shift 2; done
  printf '{"ts":"%s","level":"%s","msg":"%s","component":"scheduler"%s}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$msg" "$extra"
}

[ -r "${WORKER_TOKEN_FILE:-}" ] || { log error scheduler.no_token; exit 1; }
# curl reads the header from a file (@file) so the token never appears in `ps`.
printf 'x-worker-token: %s\n' "$(tr -d '\r\n' < "$WORKER_TOKEN_FILE")" > "$STATE/headers"
chmod 600 "$STATE/headers"

call() { # url max_seconds -> prints "<http_code> <body excerpt>"
  out="$STATE/body.$$.$(date +%s)"
  code="$(curl -sS -o "$out" -w '%{http_code}' -m "$2" -X POST -H "@$STATE/headers" "$1" 2>/dev/null || echo 000)"
  printf '%s %s' "$code" "$(head -c 300 "$out" 2>/dev/null)"
  rm -f "$out"
}

tick() {
  for base in $TICK_TARGETS; do
    res="$(call "$base/api/worker/tick" "$TICK_MAX")"
    code="${res%% *}"
    if [ "$code" = "200" ]; then log info scheduler.tick.ok target "$base" body "${res#* }"; return 0; fi
    log warn scheduler.tick.failed target "$base" status "$code" body "${res#* }"
    # 401 = token mismatch: the next instance shares the token, stop and alert.
    [ "$code" = "401" ] && return 1
  done
  log error scheduler.tick.all_failed
  return 1
}

fetch_bg() {
  if [ -f "$STATE/fetch.pid" ] && kill -0 "$(cat "$STATE/fetch.pid")" 2>/dev/null; then
    log info scheduler.fetch.still_running
    return 0
  fi
  (
    res="$(call "$FETCH_TARGET/api/worker/fetch" "$FETCH_MAX")"
    code="${res%% *}"
    if [ "$code" = "200" ]; then log info scheduler.fetch.ok body "${res#* }"
    else log error scheduler.fetch.failed status "$code" body "${res#* }"; fi
    date -u +%s > "$STATE/fetch.last"
  ) &
  echo $! > "$STATE/fetch.pid"
}

log info scheduler.start tick_interval "$TICK_INTERVAL" fetch_interval "$FETCH_INTERVAL"
trap 'log info scheduler.stop; exit 0' TERM INT
last_fetch=0
while true; do
  started="$(date +%s)"
  tick
  if [ $((started - last_fetch)) -ge "$FETCH_INTERVAL" ]; then
    fetch_bg
    last_fetch="$started"
  fi
  elapsed=$(( $(date +%s) - started ))
  [ "$elapsed" -lt "$TICK_INTERVAL" ] && sleep $((TICK_INTERVAL - elapsed)) &
  wait $! 2>/dev/null || true
done
