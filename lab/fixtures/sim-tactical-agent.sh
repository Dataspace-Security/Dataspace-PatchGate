#!/usr/bin/env bash
# LAB ONLY: simulated bank PC in the lab Tactical (there is no real Windows PC here). See sim-tactical-agent.py.
# Usage: bash lab/fixtures/sim-tactical-agent.sh create | approve <KB> | status | remove
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export MSYS_NO_PATHCONV=1
OP="${1:-status}"; KB="${2:-}"
docker cp "$(cygpath -w "$HERE/sim-tactical-agent.py")" trmm-backend:/tmp/pg-sim-agent.py >/dev/null
printf '{"op":"%s","kb":"%s"}' "$OP" "$KB" |
  docker exec -i -u 0 trmm-backend sh -c 'cat > /tmp/pg-sim-agent-args.json && chmod 0644 /tmp/pg-sim-agent-args.json /tmp/pg-sim-agent.py'
out="$(docker exec -w /opt/tactical/api trmm-backend sh -c 'python manage.py shell < /tmp/pg-sim-agent.py' 2>&1 || true)"
docker exec -u 0 trmm-backend rm -f /tmp/pg-sim-agent.py /tmp/pg-sim-agent-args.json >/dev/null 2>&1 || true
line="$(printf '%s\n' "$out" | grep '^PATCHGATE_SIM=' | tail -1 || true)"
[ -n "$line" ] || { printf '%s\n' "$out" | tail -15; echo "sim-tactical-agent $OP FAILED"; exit 1; }
echo "${line#PATCHGATE_SIM=}"
