#!/usr/bin/env bash
# Start the Bank A site connector and PROVE its network position:
#   - no internet egress (raw IP + DNS), exactly like lab/tactical/up.sh proves Tactical isolation
#   - PatchGate (our server) reachable — its ONLY egress — through the bank firewall container
#   - local Tactical API reachable on the bank LAN; Tactical containers still cannot reach PatchGate
#   - package cache served over HTTPS (lab CA) through the ingress at https://pg-cache.<domain>:8443
# Prereqs: lab/tactical/up.sh + provision.sh, lab/patchgate/start.sh running (hosted mode).
# Usage: bash lab/connector/up.sh          (enrols on first run via enroll.sh)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$(cd "$HERE/.." && pwd)"
DOMAIN="${LAB_DOMAIN:-patchgate-lab.internal}"
CERTS="$LAB/certs/out"
ETC="$HERE/bank-a/etc"
PROV="$LAB/tactical/provision.json"
dk() { MSYS_NO_PATHCONV=1 docker "$@"; }   # container paths must not be rewritten by Git Bash
[ -f "$PROV" ] || { echo "run lab/tactical/provision.sh first"; exit 1; }
dk network inspect patchgate-lab-trmm_proxy >/dev/null 2>&1 || { echo "run lab/tactical/up.sh first"; exit 1; }

# ---- image (built once from patchgate-connector/, like an offline install bundle) ----
# Rebuilt automatically when the connector source changed since the image was built (label pg.src).
PGC_DIR="$LAB/../patchgate-connector"
src_hash="$(cd "$PGC_DIR" && find src package.json package-lock.json Dockerfile tsconfig*.json -type f 2>/dev/null | LC_ALL=C sort | xargs cat | sha256sum | cut -c1-16)"
img_hash="$(dk image inspect -f '{{index .Config.Labels "pg.src"}}' patchgate-connector:1.0.0 2>/dev/null || true)"
if [ "$img_hash" != "$src_hash" ] || [ "${PGC_REBUILD:-0}" = "1" ]; then
  echo "building patchgate-connector:1.0.0 (source $src_hash) ..."
  dk build -q --label "pg.src=$src_hash" -t patchgate-connector:1.0.0 "$(cygpath -w "$PGC_DIR")" >/dev/null
fi

# ---- bank-side files: bank CA, PatchGate CA pin, Tactical API key, cache TLS cert from the bank PKI ----
mkdir -p "$ETC"
cp "$CERTS/ca.crt" "$ETC/bank-ca.pem"
cp "$CERTS/ca.crt" "$ETC/patchgate-ca.pem"   # lab: our server's cert is issued by the same lab CA
node -e 'process.stdout.write(require(process.argv[1]).apiKey)' "$(cygpath -m "$PROV")" > "$ETC/tactical-api-key"
if [ ! -f "$ETC/cache-cert.pem" ]; then
  ( cd "$ETC"
    openssl genrsa -out cache-key.pem 2048 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pg-cache.%s\n' "$DOMAIN" > cache.ext
    MSYS_NO_PATHCONV=1 openssl req -new -key cache-key.pem -subj "/C=IN/O=Bank A (PatchGate Lab)/CN=pg-cache.${DOMAIN}" -out cache.csr
    openssl x509 -req -in cache.csr -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial -days 397 -sha256 \
      -extfile cache.ext -out cache-cert.pem 2>/dev/null
    rm -f cache.csr cache.ext
    chmod 644 cache-key.pem )   # read by uid 1000 in the container (bind mount from Windows)
  echo "issued cache certificate pg-cache.${DOMAIN} from the lab CA"
fi
# Bank A's own trust policy (connector.json "trust"): generated ONCE from the verified catalog as a starting
# point; afterwards it is the bank's file (edit it, or delete it to regenerate). PatchGate cannot change it.
TRUST="$HERE/bank-a/trust-policy.json"
if [ ! -f "$TRUST" ]; then
  q() { dk exec patchgate-dev-db psql -U patchgate -d patchgate_lab -tAF'|' -c "$1"; }
  { q 'select a."wingetId", coalesce(v."signerOrg", a."expectedPublisher", $$$$) from "App" a join "AppVersion" v on v."appId"=a.id where v.verification=$$VERIFIED$$'
    echo "--"
    q 'select sha256 from "MirroredRelease" where component=$$TACTICAL_AGENT$$ and verification=$$VERIFIED$$'
  } | node "$(cygpath -m "$HERE/make-trust-policy.mjs")" "$(cygpath -m "$TRUST")"
fi
node "$(cygpath -m "$HERE/write-config.mjs")"

# ---- ingress: the bank PCs reach the cache through trmm-lab-ingress :8443 (lab/tactical override) ----
if ! dk port trmm-lab-ingress 8443 >/dev/null 2>&1; then
  echo "recreating trmm-lab-ingress with the :8443 cache port"
  TRMM="$(cd "$LAB/../../tacticalrmm/docker" && pwd)"
  dk compose -p patchgate-lab-trmm --env-file "$(cygpath -w "$LAB/tactical/.env")" -f "$(cygpath -w "$TRMM/docker-compose.yml")" \
    -f "$(cygpath -w "$LAB/tactical/docker-compose.lab.yml")" up -d --no-build --no-deps lab-ingress >/dev/null
fi

cd "$HERE"
dk compose up -d bank-a-firewall >/dev/null
node -e 'process.exit(require(process.argv[1]).identity?0:1)' "$(cygpath -m "$ETC/connector.json")" || bash "$HERE/enroll.sh"
dk compose up -d --force-recreate connector >/dev/null
echo "connector starting..."; sleep 8

# ---- proofs ----
fail=0
probe() { dk exec bank-a-connector node -e "$1" 2>&1 | tail -1; }
echo "isolation check, connector (expect: internet blocked, PatchGate + Tactical reachable):"
NET_JS='const net=require("net"),dns=require("dns");const tcp=(h,p)=>new Promise(r=>{const s=net.connect({host:h,port:p,timeout:5000});s.on("connect",()=>{s.destroy();r(true)});s.on("timeout",()=>{s.destroy();r(false)});s.on("error",()=>r(false))});'
for t in 1.1.1.1:443 140.82.112.3:443 8.8.8.8:53; do
  out="$(probe "$NET_JS tcp('${t%:*}',${t#*:}).then(ok=>console.log(ok?'REACHABLE':'blocked'))")"
  echo "  raw $t: $out"; case "$out" in *REACHABLE*) fail=1 ;; esac
done
out="$(probe "require('dns').lookup('github.com',e=>console.log(e?'blocked ('+e.code+')':'RESOLVED'))")"
echo "  dns github.com: $out"; case "$out" in *RESOLVED*) fail=1 ;; esac
out="$(probe "$NET_JS tcp('10.231.51.10',22).then(ok=>console.log(ok?'REACHABLE':'blocked'))")"
echo "  bank firewall, any other port (22): $out"; case "$out" in *REACHABLE*) fail=1 ;; esac
HTTPS_JS='const https=require("https"),fs=require("fs");const get=(u)=>new Promise(r=>https.get(u,{ca:fs.readFileSync("/etc/patchgate-connector/bank-ca.pem"),timeout:15000},s=>{r("HTTP "+s.statusCode);s.resume()}).on("error",e=>r("ERROR "+e.code)));'
out="$(probe "$HTTPS_JS get('https://patchgate.${DOMAIN}:3443/api/health').then(console.log)")"
echo "  PatchGate https://patchgate.${DOMAIN}:3443/api/health: $out"; [ "$out" = "HTTP 200" ] || fail=1
out="$(probe "$HTTPS_JS get('https://api.${DOMAIN}:4443/core/version/').then(console.log)")"
echo "  Tactical https://api.${DOMAIN}:4443 (bank LAN): $out"; case "$out" in HTTP*) ;; *) fail=1 ;; esac
echo "isolation check, Tactical -> PatchGate / bank firewall (expect blocked):"
for c in trmm-backend trmm-nginx; do
  out="$(dk exec "$c" sh -c '(command -v python >/dev/null && python -c "import socket
try:
    socket.create_connection((\"10.231.51.10\",3443),timeout=5); print(\"REACHABLE\")
except OSError: print(\"blocked\")") || ( (exec 3<>/dev/tcp/10.231.51.10/3443) >/dev/null 2>&1 && echo REACHABLE || echo blocked)' 2>&1 | tail -1)"
  echo "  $c -> bank firewall :3443: $out"; case "$out" in *REACHABLE*) fail=1 ;; esac
done
[ "$fail" = 0 ] || { echo "ISOLATION BROKEN (see above)"; dk logs --tail 30 bank-a-connector; exit 2; }

echo "connector self-check:"
dk exec bank-a-connector node /opt/patchgate-connector/patchgate-connector.mjs check | sed 's/^/  /' || true
code="$(curl -s -o /dev/null -w '%{http_code}' --ssl-no-revoke --cacert "$CERTS/ca.crt" --resolve "pg-cache.${DOMAIN}:8443:127.0.0.1" "https://pg-cache.${DOMAIN}:8443/healthz" || true)"
echo "cache via ingress https://pg-cache.${DOMAIN}:8443/healthz (lab CA): HTTP $code"
[ "$code" = "200" ] || { echo "cache not reachable through the ingress"; exit 3; }
echo "Bank A connector up and isolated."
