#!/usr/bin/env bash
# Bring up the whole hosted lab (docs/ARCHITECTURE-HOSTED.md §6 phase 4) and prove its network shape.
#   our server : PatchGate  https://patchgate.<domain>:3443 (local login; password only) + scheduler   [this PC]
#   Bank A     : Tactical RMM (Docker, internal networks) + PatchGate Connector (Docker, egress = PatchGate only)
#                package cache https://pg-cache.<domain>:8443 (via trmm-lab-ingress) · bank SIEM tls://siem.<domain>:6514
# Safe to re-run: running pieces are kept, missing ones are started. Stop: bash lab/down-all.sh
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
DOMAIN="${LAB_DOMAIN:-patchgate-lab.internal}"
CA="$LAB/certs/out/ca.crt"
listening() { netstat -ano 2>/dev/null | grep LISTENING | grep -q "[:.]$1 "; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "1/7 lab PKI"
[ -f "$LAB/certs/out/fullchain.crt" ] || bash "$LAB/certs/make-certs.sh" "$DOMAIN"
echo "lab CA: $CA"

step "2/7 Bank A Tactical (offline, isolation proven)"
bash "$LAB/tactical/up.sh" "$DOMAIN" | tail -15
# Provision + seal (same script as a bank site). Re-run when provision.json predates the seal.
grep -q '"agentAutoUpdate"' "$LAB/tactical/provision.json" 2>/dev/null || bash "$LAB/tactical/provision.sh"
bash "$LAB/tactical/break-glass.sh" check

step "3/7 bank SIEM (lab TLS syslog receiver :6514)"
if listening 6514; then echo "already listening"; else
  (cd "$LAB" && nohup node siem/receiver.mjs 6514 >> siem/receiver.out 2>&1 &)
  sleep 2; listening 6514 && echo "started" || { echo "SIEM receiver failed (lab/siem/receiver.out)"; exit 1; }
fi

step "4/7 PatchGate = our server (https :3443, AUTH_MODE=local, signed connector jobs)"
if listening 3443; then echo "already listening (restart: bash lab/patchgate/stop.sh && bash lab/up-all.sh)"; else
  (cd "$LAB/.." && nohup bash lab/patchgate/start.sh > lab/patchgate/start.log 2>&1 &)
fi
for i in $(seq 1 60); do
  curl -s -m 60 --ssl-no-revoke --cacert "$CA" "https://patchgate.${DOMAIN}:3443/api/health" 2>/dev/null | grep -q '"ok"' && break
  sleep 5
done
curl -s -m 60 --ssl-no-revoke --cacert "$CA" "https://patchgate.${DOMAIN}:3443/api/health" | grep -q '"ok"' || { echo "PatchGate did not come up (lab/patchgate/start.log)"; exit 1; }
echo "https://patchgate.${DOMAIN}:3443 healthy"
bash "$LAB/patchgate/users.sh"

step "5/7 Bank A connector (enrol on first run, isolation proven)"
bash "$LAB/connector/up.sh"

step "6/7 scheduler (worker tick 1/min, fetch 1/h)"
scheduler_running() {
  local f
  for f in /proc/[0-9]*/cmdline; do
    { tr '\0' ' ' < "$f"; } 2>/dev/null | grep -q "^bash .*lab/patchgate/scheduler.sh" && return 0
  done
  return 1
}
if scheduler_running; then echo "already running"; else
  (cd "$LAB/.." && nohup bash lab/patchgate/scheduler.sh > lab/patchgate/scheduler.log 2>&1 &)
  echo "started (log: lab/patchgate/scheduler.log)"
fi

step "7/7 summary"
cat <<EOF
PatchGate (our server) : https://patchgate.${DOMAIN}:3443          (browser on this PC; trust lab/certs/out/ca.crt or accept the lab cert)
  sign-in              : local accounts in lab/patchgate/lab-users.json (gitignored)
  sign-in details      : node lab/patchgate/show-login.mjs <upn>   (password only, no code)
Bank A Tactical        : https://rmm.${DOMAIN}  (credentials: lab/tactical/.env)
Bank A connector cache : https://pg-cache.${DOMAIN}:8443/repo/...   (docker logs -f bank-a-connector)
Bank A SIEM            : lab/siem/received.log  ·  node lab/siem/check.mjs bank-a-connector-hq
Sandbox PC             : bash lab/sandbox/make-sandbox.sh 2.10.0 → double-click lab/sandbox/generated/PatchGateLab.wsb
Stop                   : bash lab/down-all.sh   (data kept)
EOF
