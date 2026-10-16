#!/usr/bin/env bash
# Lab stand-in for our platform scheduler (systemd timer / k8s CronJob): worker tick every minute
# (signed connector jobs, results, schedules), internet fetch loop every hour.
# Usage: bash lab/patchgate/scheduler.sh   (after start.sh; same LAB_MODE)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/env.sh"
URL="${LAB_URL:-$PG_URL}"
CA="$PG_CERTS/ca.crt"
call() { curl -s --ssl-no-revoke --cacert "$CA" -m 1800 -X POST -H "x-worker-token: $WORKER_TOKEN" "$URL/api/worker/$1" | cut -c1-600; echo; }
n=0
while true; do
  echo "$(date -Is) tick: $(call tick)"
  if (( n % 60 == 0 )); then echo "$(date -Is) fetch: $(call fetch)"; fi
  n=$((n + 1)); sleep 60
done
