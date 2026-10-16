#!/usr/bin/env bash
# Stop the hosted lab. Data is KEPT (patchgate_lab DB, Tactical volumes, connector state volume, caches).
#   bash lab/down-all.sh            → scheduler, PatchGate, Bank A connector + firewall, SIEM receiver, Tactical
#   bash lab/down-all.sh --keep-tactical   → everything except the Tactical containers
set -uo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "scheduler + PatchGate"
bash "$LAB/patchgate/stop.sh"

step "Bank A connector + bank firewall (state volume kept)"
(cd "$LAB/connector" && MSYS_NO_PATHCONV=1 docker compose stop)

step "lab SIEM receiver"
bash "$LAB/patchgate/stop.sh" siem

if [ "${1:-}" != "--keep-tactical" ]; then
  step "Bank A Tactical (containers stopped, volumes kept)"
  TRMM="$(cd "$LAB/../../tacticalrmm/docker" && pwd)"
  MSYS_NO_PATHCONV=1 docker compose -p patchgate-lab-trmm --env-file "$(cygpath -w "$LAB/tactical/.env")" \
    -f "$(cygpath -w "$TRMM/docker-compose.yml")" -f "$(cygpath -w "$LAB/tactical/docker-compose.lab.yml")" stop
fi
echo
echo "lab stopped. Start again: bash lab/up-all.sh"
