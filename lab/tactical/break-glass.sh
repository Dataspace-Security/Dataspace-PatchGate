#!/usr/bin/env bash
# Lab equivalent of `install-site.sh --break-glass on|off` (and `--status` seal check) for the sealed lab Tactical.
# Runs the SAME script a bank site uses (installers/site/tactical/break-glass.py) in trmm-backend. The lab's
# Tactical admin (TRMM_USER in lab/tactical/.env) plays the site's break-glass account tacticaladmin.
# Every change lands in Tactical's audit log → connector TACTICAL_AUDIT_SYNC → "Tactical activity" in PatchGate.
# Usage: bash lab/tactical/break-glass.sh on|off|check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export MSYS_NO_PATHCONV=1
STATE="${1:-}"
case "$STATE" in on|off|check) ;; *) echo "usage: $0 on|off|check"; exit 2 ;; esac
BG_USER="$(sed -n 's/^TRMM_USER=//p' "$HERE/.env" | tr -d '\r')"

docker cp "$(cygpath -w "$ROOT/installers/site/tactical/break-glass.py")" trmm-backend:/tmp/pg-break-glass.py >/dev/null
printf '{"state":"%s","by":"lab operator (%s)","user":"%s"}' "$STATE" "${USERNAME:-${USER:-lab}}" "$BG_USER" |
  docker exec -i -u 0 trmm-backend sh -c 'cat > /tmp/pg-break-glass-args.json && chmod 0644 /tmp/pg-break-glass-args.json /tmp/pg-break-glass.py'
out="$(docker exec -w /opt/tactical/api trmm-backend sh -c 'python manage.py shell < /tmp/pg-break-glass.py' 2>&1 || true)"
docker exec -u 0 trmm-backend rm -f /tmp/pg-break-glass-args.json /tmp/pg-break-glass.py >/dev/null 2>&1 || true
line="$(printf '%s\n' "$out" | grep -E '^PATCHGATE_(BREAK_GLASS|SEAL_CHECK)=' | tail -1 || true)"
[ -n "$line" ] || { printf '%s\n' "$out" | grep -viE 'key|token|pass' | tail -15; echo "break-glass $STATE FAILED"; exit 1; }
[ "$STATE" = check ] || printf '%s\n' "$STATE" > "$HERE/.break-glass"
echo "${line#PATCHGATE_}"
[ "$STATE" = on ] && echo "break-glass ON: $BG_USER may sign in at Tactical (password: TRMM_PASS in lab/tactical/.env). PatchGate alerts within ~1 min." || true
