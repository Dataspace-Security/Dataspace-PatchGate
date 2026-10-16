#!/bin/bash
# PatchGate colleague test kit — steps that run INSIDE the kit's server container (TEST KIT ONLY).
# Called by test-on-my-pc.sh:  docker exec pgkit-server bash /root/kit/lib/server-steps.sh <step> [args]
# Never prints secrets: the installer's one-time admin password is diverted into /root/kit/secret/ (0600).
set -euo pipefail
K=/root/kit
V="$(cat "$K/VERSION")"
DOMAIN="${KIT_DOMAIN:-patchgate.pgi.test}"
D=/opt/patchgate/deploy
DC=(docker compose -f docker-compose.prod.yml --env-file .env.production)
install -d -m 0700 "$K/secret"

tools() { # run the kit API client with the release's tools image on this container's network
  docker run --rm --network host --user 0 --add-host "$DOMAIN:127.0.0.1" \
    -e PG_URL="https://$DOMAIN" -e NODE_EXTRA_CA_CERTS=/pgtls/selfsigned-ca.pem \
    -v "$K:/kit" -v "$D/tls/selfsigned-ca.pem:/pgtls/selfsigned-ca.pem:ro" \
    --entrypoint node "patchgate-tools:$V" /kit/lib/kit-api.mjs "$@"
}
wait_healthy() { # service timeout
  local cid st
  for _ in $(seq 1 "$(( $2 / 5 ))"); do
    cid="$(cd "$D" && "${DC[@]}" ps -q "$1" 2>/dev/null | head -1 || true)"
    st="$( [ -n "$cid" ] && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo missing)"
    [ "$st" = healthy ] && return 0
    sleep 5
  done
  echo "    $1 not healthy after $2 s (state: $st)"; return 1
}
psql_q() { (cd "$D" && "${DC[@]}" exec -T -u postgres db psql -d patchgate -qtAc "$1"); }

case "${1:-}" in
  load-images)
    for f in "$K"/images/*.tar.gz; do
      printf '    docker load %s ... ' "$(basename "$f")"
      docker load -i "$f" | sed -n 's/^Loaded image: //p' | tr '\n' ' '; echo
    done
    for n in web tools signer egress-proxy backup connector; do
      docker image inspect "patchgate-$n:$V" >/dev/null 2>&1 || { echo "    MISSING patchgate-$n:$V after docker load"; exit 1; }
    done
    docker images --format '    {{.Repository}}:{{.Tag}}  {{.ID}}  {{.Size}}' | grep "patchgate-.*:$V" ;;

  install)
    # The real server installer, non-interactive. Registry mode with an EMPTY registry = use the images
    # loaded above (incl. the release's signer/egress-proxy/backup images). Self-signed TLS (test only).
    rm -rf /root/pg && mkdir -p /root/pg && cp -a "$K/product/installers" "$K/product/deploy" /root/pg/
    find /root/pg -type f \( -name '*.sh' -o -name '*.conf' -o -name '*.yml' -o -name '*.template' \) -exec sed -i 's/\r$//' {} +
    chmod 0755 /root/pg/installers/server/install-patchgate.sh
    rm -f "$K/secret/admin-temp-password"
    set +e
    cd /root/pg/installers/server && PG_REGISTRY="" ./install-patchgate.sh --non-interactive --domain "$DOMAIN" \
      --admin-email admin@pgi.test --admin-name "Platform Admin" --tls self-signed \
      --image-source registry --version "$V" --no-firewall 2>&1 | \
      awk -v f="$K/secret/admin-temp-password" '
        grab { pw = $0; sub(/^[ \t]+/, "", pw); if (pw != "") { printf "%s\n", pw > f; close(f); print "        <one-time password hidden: written to logins.txt>"; grab = 0; next } }
        /Temporary password for/ { grab = 1 }
        { print; fflush() }'
    rc=${PIPESTATUS[0]}
    set -e
    [ -s "$K/secret/admin-temp-password" ] && chmod 0600 "$K/secret/admin-temp-password"
    exit "$rc" ;;

  accounts)
    tools setup ;;

  bundle)
    # Throwaway Ed25519 bundle-signing key (TEST ONLY), sign the site SHA256SUMS, upload per RUNBOOK §6.1,
    # bake the public key into the server (PATCHGATE_SITE_BUNDLE_PUBKEY) and restart web-1, then web-2.
    B="$K/site-bundle"; KEY="$K/secret/bundle-signing"; OUT="$K/bundle-out"
    install -d -m 0700 "$KEY"; rm -rf "$OUT"; mkdir -p "$OUT"
    [ -s "$KEY/sign.pem" ] || openssl genpkey -algorithm ed25519 -out "$KEY/sign.pem" 2>/dev/null
    chmod 0600 "$KEY/sign.pem"
    openssl pkey -in "$KEY/sign.pem" -pubout -out "$KEY/sign.pub.pem"
    # Only the online bundle travels with the kit: keep the SHA256SUMS lines of the files we have.
    ONL="patchgate-site-$V-online.tar.gz"
    grep -E " [* ]?($ONL|install-site\.sh)\$" "$B/site-SHA256SUMS" > "$OUT/SHA256SUMS"
    [ "$(wc -l < "$OUT/SHA256SUMS")" = 2 ] || { echo "    site-SHA256SUMS does not list $ONL and install-site.sh"; exit 1; }
    cp "$B/$ONL" "$B/install-site.sh" "$OUT/"
    (cd "$OUT" && sha256sum --strict -c SHA256SUMS | sed 's/^/    /')
    openssl pkeyutl -sign -rawin -inkey "$KEY/sign.pem" -in "$OUT/SHA256SUMS" -out "$OUT/SHA256SUMS.sig"
    openssl pkeyutl -verify -pubin -inkey "$KEY/sign.pub.pem" -rawin -in "$OUT/SHA256SUMS" -sigfile "$OUT/SHA256SUMS.sig" | sed 's/^/    /'
    PUB="ed25519:$(openssl pkey -pubin -in "$KEY/sign.pub.pem" -outform DER | tail -c 32 | base64 -w0)"
    echo "    bundle-signing public key (throwaway, test only): $PUB"
    VOLN="$(docker volume ls -q | grep -E '(^|_)site-bundles$' | head -1)"
    [ -n "$VOLN" ] || { echo "    site-bundles volume not found"; exit 1; }
    VOL="$(docker volume inspect -f '{{.Mountpoint}}' "$VOLN")"
    install -d -o 10001 -g 10001 -m 0755 "$VOL/$V"
    install -o 10001 -g 10001 -m 0444 "$OUT/SHA256SUMS" "$OUT/SHA256SUMS.sig" "$OUT/$ONL" "$OUT/install-site.sh" "$VOL/$V/"
    (cd "$VOL/$V" && sha256sum --strict -c SHA256SUMS | sed 's/^/    /')
    echo "$V" > "$VOL/LATEST.tmp" && chown 10001:10001 "$VOL/LATEST.tmp" && mv -f "$VOL/LATEST.tmp" "$VOL/LATEST"
    echo "    uploaded to volume $VOLN: $V/ (+ LATEST -> $V)"
    cd "$D"
    if grep -q '^PATCHGATE_SITE_BUNDLE_PUBKEY=' .env.production; then sed -i "s#^PATCHGATE_SITE_BUNDLE_PUBKEY=.*#PATCHGATE_SITE_BUNDLE_PUBKEY=$PUB#" .env.production
    elif grep -q '^# *PATCHGATE_SITE_BUNDLE_PUBKEY=' .env.production; then sed -i "s|^# *PATCHGATE_SITE_BUNDLE_PUBKEY=.*|PATCHGATE_SITE_BUNDLE_PUBKEY=$PUB|" .env.production
    else echo "PATCHGATE_SITE_BUNDLE_PUBKEY=$PUB" >> .env.production; fi
    echo "    .env.production: $(grep -n '^PATCHGATE_SITE_BUNDLE_PUBKEY=' .env.production | cut -c1-40)..."
    for svc in web-1 web-2; do
      "${DC[@]}" up -d --no-deps "$svc" 2>&1 | grep -v '^\s*$' | tail -1 | sed 's/^/    /'
      wait_healthy "$svc" 300
      echo "    $svc healthy with the new key"
    done
    code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$D/tls/selfsigned-ca.pem" "https://$DOMAIN/install/site.sh" || true)"
    echo "    https://$DOMAIN/install/site.sh from this server: HTTP $code (connector allow-list decides; next step adds the site)" ;;

  allowlist)
    # RUNBOOK §6 step 4: one file per bank in connectors.d + an explicit include line; reload nginx.
    SITE_IP="$2"
    A="$D/nginx/allowlists"
    printf '# Test Bank (test-bank) — colleague test kit site container. TEST ONLY.\n%s/32 1;\n' "$SITE_IP" > "$A/connectors.d/test-bank.conf"
    chmod 0644 "$A/connectors.d/test-bank.conf"
    grep -q '^include /etc/nginx/allowlists/connectors.d/test-bank.conf;' "$A/connectors.conf" || \
      echo 'include /etc/nginx/allowlists/connectors.d/test-bank.conf;' >> "$A/connectors.conf"
    cd "$D"
    "${DC[@]}" exec -T nginx nginx -t 2>&1 | tail -1 | sed 's/^/    /'
    "${DC[@]}" exec -T nginx nginx -s reload
    echo "    connector allow-list: $SITE_IP/32 (connectors.d/test-bank.conf), nginx reloaded" ;;

  enrol)
    tools enrol "${2:-Head office}" ;;

  connector-status)
    psql_q "select name || ' | ' || status || ' | lastSeen ' || coalesce(to_char(\"lastSeenAt\",'YYYY-MM-DD HH24:MI:SS'),'never') || ' | ' || case when \"lastSeenAt\" > now() - interval '3 minutes' then 'online' else 'offline' end || ' | version ' || coalesce(version,'?') from \"Connector\" order by \"enrolledAt\"" ;;

  smoke)
    cd "$D" && CA_FILE=tls/selfsigned-ca.pem ./scripts/smoke-test.sh "https://$DOMAIN" ;;

  ps)
    cd "$D" && "${DC[@]}" ps --format 'table {{.Service}}\t{{.Status}}\t{{.Image}}' ;;

  audit)
    psql_q "select action || ': ' || count(*) from \"AuditEvent\" where action like 'connector.%' or action like 'user.%' or action like 'tenant.%' or action like 'auth.%' group by action order by action" ;;

  totp) tools totp "$2" ;;
  check-login) tools check-login "$2" ;;
  logins) tools logins ;;
  *) echo "usage: server-steps.sh load-images|install|accounts|bundle|allowlist <ip>|enrol [site]|connector-status|smoke|ps|audit|totp <who>|check-login <who>|logins"; exit 2 ;;
esac
