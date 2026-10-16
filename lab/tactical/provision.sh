#!/usr/bin/env bash
# Provision + SEAL the lab Tactical for the Bank A connector with the SAME script a bank site uses
# (installers/site/tactical/provision-site.py): least-privilege service account + API key, client/site, the three
# fixed PatchGate scripts (install / WU scan / WU install), every patch policy manual, a 24 h agent install token,
# and the seal (dashboard login blocked for everybody, other API keys expired, agent auto-update off; written to
# Tactical's audit log, which the connector reports to PatchGate). Writes lab/tactical/provision.json (gitignored).
# The lab's Tactical admin (TRMM_USER in lab/tactical/.env, "labadmin") plays the site's break-glass account
# (tacticaladmin): bash lab/tactical/break-glass.sh on|off|check.
# Usage: bash lab/tactical/provision.sh [--rotate-key]   (the API key is kept unless --rotate-key)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ENDPOINT="$ROOT/patchgate-web/scripts/endpoint"
SITE_TACTICAL="$ROOT/installers/site/tactical"
export MSYS_NO_PATHCONV=1   # stop Git Bash on Windows from rewriting container paths
ROTATE=false; [ "${1:-}" = "--rotate-key" ] && ROTATE=true
BG_USER="$(sed -n 's/^TRMM_USER=//p' "$HERE/.env" | tr -d '\r')"
BG_STATE="$(cat "$HERE/.break-glass" 2>/dev/null || echo off)"   # keep an open lab break-glass session open
KEEP_BG=false; [ "$BG_STATE" = on ] && KEEP_BG=true

docker exec -u 0 trmm-backend sh -c 'rm -rf /tmp/pg-scripts && mkdir -p /tmp/pg-scripts'
for s in Install-PatchGatePackage.ps1 Invoke-PatchGateWuScan.ps1 Install-PatchGateWinUpdate.ps1; do
  docker cp "$(cygpath -w "$ENDPOINT/$s")" "trmm-backend:/tmp/pg-scripts/$s" >/dev/null
done
docker cp "$(cygpath -w "$SITE_TACTICAL/provision-site.py")" trmm-backend:/tmp/pg-provision-site.py >/dev/null
printf '{"client":"Lab Bank","site":"Branch-001 Pune","tokenHours":24,"rotateKey":%s,"scriptsDir":"/tmp/pg-scripts","keepBreakGlass":%s,"breakGlassUser":"%s"}' \
  "$ROTATE" "$KEEP_BG" "$BG_USER" |
  docker exec -i -u 0 trmm-backend sh -c 'cat > /tmp/pg-provision-args.json && chmod 0644 /tmp/pg-provision-args.json /tmp/pg-provision-site.py && chmod -R a+r /tmp/pg-scripts'
out="$(docker exec -w /opt/tactical/api trmm-backend sh -c 'python manage.py shell < /tmp/pg-provision-site.py' 2>&1 || true)"
docker exec -u 0 trmm-backend rm -rf /tmp/pg-provision-args.json /tmp/pg-provision-site.py /tmp/pg-scripts >/dev/null 2>&1 || true
line="$(printf '%s\n' "$out" | grep '^PATCHGATE_PROVISION=' | tail -1 || true)"
if [ -z "$line" ]; then
  echo "provisioning FAILED:"
  printf '%s\n' "$out" | grep -viE 'key|token|pass' | tail -25
  exit 1
fi
( umask 077; printf '%s\n' "${line#PATCHGATE_PROVISION=}" > "$HERE/provision.json" )
summary="$(node -e 'const p=require(process.argv[1]); console.log(`API key ${p.apiKeyState}; sealed: newly blocked [${p.sealBlocked||"none"}], other API keys expired ${p.sealExpiredApiKeys}, policies fixed ${p.sealPoliciesFixed}, agent auto-update ${p.agentAutoUpdate}, break-glass ${p.breakGlass}`)' "$(cygpath -m "$HERE/provision.json")")"
echo "wrote $HERE/provision.json (API key + enrollment token — gitignored)"
echo "Tactical $summary"
