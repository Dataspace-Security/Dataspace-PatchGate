#!/usr/bin/env bash
# Start REAL Tactical RMM (official images) for the PatchGate lab — with NO internet access — and
# prove it. Usage: lab/tactical/up.sh [lab-domain]   (default patchgate-lab.internal)
#
# Images are pulled/built once by this script (install media, like an offline bundle); after that the
# Tactical containers have no outbound route. The run fails if any container can reach the internet.
set -euo pipefail

DOMAIN="${1:-patchgate-lab.internal}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TRMM="$(cd "$HERE/../../../tacticalrmm/docker" && pwd)"
CERTS="$HERE/../certs/out"
[ -f "$CERTS/fullchain.crt" ] || { echo "run lab/certs/make-certs.sh $DOMAIN first"; exit 1; }

rand() { openssl rand -hex 16; }
if [ ! -f "$HERE/.env" ] || ! grep -q "API_HOST=api.${DOMAIN}$" "$HERE/.env"; then
  cat > "$HERE/.env" <<EOF
IMAGE_REPO=tacticalrmm/
VERSION=latest
TRMM_USER=labadmin
TRMM_PASS=$(rand)
APP_HOST=rmm.${DOMAIN}
API_HOST=api.${DOMAIN}
MESH_HOST=mesh.${DOMAIN}
CSRF_COOKIE_DOMAIN=${DOMAIN}
SESSION_COOKIE_DOMAIN=${DOMAIN}
MESH_USER=labmesh
MESH_PASS=$(rand)
MONGODB_USER=mongolab
MONGODB_PASSWORD=$(rand)
MESH_PERSISTENT_CONFIG=0
POSTGRES_USER=postgres
POSTGRES_PASS=$(rand)
TRMM_DISABLE_WEB_TERMINAL=True
TRMM_DISABLE_SERVER_SCRIPTS=True
TRMM_DISABLE_SSO=True
CERT_PUB_KEY=$(base64 -w0 "$CERTS/fullchain.crt")
CERT_PRIV_KEY=$(base64 -w0 "$CERTS/server.key")
EOF
  echo "wrote $HERE/.env for ${DOMAIN} (lab credentials — gitignored)"
fi

COMPOSE=(docker compose -p patchgate-lab-trmm --env-file "$HERE/.env" -f "$TRMM/docker-compose.yml" -f "$HERE/docker-compose.lab.yml")
docker build -q -t patchgate-lab/tactical-meshcentral-offline:latest "$HERE/meshcentral-offline" >/dev/null
"${COMPOSE[@]}" up -d --no-build

echo "waiting for tactical-init (migrations etc.)..."
for i in $(seq 1 120); do
  state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' trmm-init 2>/dev/null || echo missing)"
  [ "$state" = "exited 0" ] && break
  # First boot: MeshCentral may start before its DB is ready and skip writing the login token.
  if docker logs --tail 3 trmm-init 2>&1 | grep -q "mesh_token: No such file"; then
    if ! docker exec trmm-meshcentral test -s /opt/tactical/tmp/mesh_token 2>/dev/null; then
      echo "mesh token missing -> restarting meshcentral"; docker restart trmm-meshcentral >/dev/null; sleep 60
    fi
  fi
  sleep 15
done
[ "$(docker inspect -f '{{.State.ExitCode}}' trmm-init)" = "0" ] || { docker logs --tail 40 trmm-init; exit 1; }

# PatchGate-required Tactical settings (ARCHITECTURE §6/§6B): Tactical never decides or downloads.
docker exec -u 0 trmm-backend sh -c 'grep -q "PatchGate lab" /opt/tactical/api/tacticalrmm/local_settings.py || cat >> /opt/tactical/api/tacticalrmm/local_settings.py <<EOF

# --- PatchGate lab: Tactical is a delivery pipe only, never reaches the internet ---
TRMM_DISABLE_APPROVE_UPDATES_TASK = True
TRMM_DISABLE_WINUPDATES_INSTALL_TASK = True
TRMM_DISABLE_AGENT_AUTO_UPDATE_TASK = True
INSTALL_NUSHELL = False
INSTALL_DENO = False
EOF'
docker restart trmm-backend trmm-celery trmm-celerybeat trmm-websockets >/dev/null

# Upstream start race: trmm-nats may start nats-server before tactical-init (re)wrote nats-rmm.conf; supervisor then
# gives up and Tactical answers every script run with "natsdown". Restart NATS until nats-server is running.
for _ in 1 2 3 4 5 6; do
  docker exec trmm-nats sh -c 'command -v pgrep >/dev/null 2>&1 || exit 0; pgrep -x nats-server >/dev/null' 2>/dev/null && { echo "NATS: nats-server running"; break; }
  echo "NATS: nats-server not running (start race) -> restarting trmm-nats"; docker restart trmm-nats >/dev/null; sleep 30
done
docker exec trmm-nats sh -c 'command -v pgrep >/dev/null 2>&1 || exit 0; pgrep -x nats-server >/dev/null' || { echo "NATS did not start (docker logs trmm-nats)"; exit 1; }

# ---- Prove isolation: raw IP (no DNS needed) and DNS, from every Tactical container ----
echo "isolation check (expect every line 'blocked'):"
fail=0
for c in trmm-backend trmm-celery trmm-celerybeat trmm-websockets trmm-nats trmm-meshcentral trmm-nginx trmm-frontend trmm-postgres trmm-redis trmm-mongodb; do
  out="$(docker exec "$c" sh -c '
    if command -v python >/dev/null 2>&1; then
      python -c "import socket
for t in [(\"1.1.1.1\",443),(\"140.82.112.3\",443)]:
    try:
        socket.create_connection(t,timeout=5); print(\"REACHABLE\", t[0]); raise SystemExit
    except OSError: pass
print(\"blocked\")"
    elif command -v nc >/dev/null 2>&1; then
      (nc -z -w 5 1.1.1.1 443 || nc -z -w 5 140.82.112.3 443) >/dev/null 2>&1 && echo REACHABLE || echo blocked
    elif command -v wget >/dev/null 2>&1; then
      wget -q -T 5 -O /dev/null http://1.1.1.1 >/dev/null 2>&1 && echo REACHABLE || echo blocked
    else
      (exec 3<>/dev/tcp/1.1.1.1/443) >/dev/null 2>&1 && echo REACHABLE || echo blocked
    fi' 2>&1 | tail -1)"
  echo "  $c: $out"
  case "$out" in *REACHABLE*) fail=1 ;; esac
done
[ "$fail" = 0 ] || { echo "ISOLATION BROKEN: a Tactical container reached the internet"; exit 2; }
echo "Tactical lab up and isolated: https://rmm.${DOMAIN}  (credentials in $HERE/.env)"
