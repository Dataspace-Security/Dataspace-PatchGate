#!/usr/bin/env bash
# Provision the lab Tactical for the Bank A connector (service account + API key, client/site, the three
# fixed PatchGate scripts (install / WU scan / WU install),
# manual patch policy, agent enrollment token). Writes lab/tactical/provision.json (gitignored).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENDPOINT="$HERE/../../patchgate-web/scripts/endpoint"
export MSYS_NO_PATHCONV=1   # stop Git Bash on Windows from rewriting container paths

for s in Install-PatchGatePackage.ps1 Invoke-PatchGateWuScan.ps1 Install-PatchGateWinUpdate.ps1; do
  docker cp "$(cygpath -w "$ENDPOINT/$s")" "trmm-backend:/tmp/$s"
done
docker cp "$(cygpath -w "$HERE/provision.py")" trmm-backend:/tmp/provision.py
out="$(docker exec -w /opt/tactical/api trmm-backend sh -c 'python manage.py shell < /tmp/provision.py' 2>&1 || true)"
line="$(printf '%s\n' "$out" | grep '^PATCHGATE_PROVISION=' || true)"
if [ -z "$line" ]; then
  echo "provisioning FAILED:"
  printf '%s\n' "$out" | tail -25
  exit 1
fi
printf '%s\n' "${line#PATCHGATE_PROVISION=}" | tail -1 > "$HERE/provision.json"
echo "wrote $HERE/provision.json (API key + enrollment token — gitignored)"
