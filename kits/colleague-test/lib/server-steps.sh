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
  prep-images)
    # The tools image first (the kit's API client and test SIEM run on it, before the installer); the other five
    # are loaded by the installer itself from a directory (--image-archive DIR), like an offline server.
    f="$K/images/patchgate-tools-$V.tar.gz"
    [ -f "$f" ] || { echo "    missing $(basename "$f")"; exit 1; }
    if ! docker image inspect "patchgate-tools:$V" >/dev/null 2>&1; then
      printf '    docker load %s ... ' "$(basename "$f")"; docker load -i "$f" | sed -n 's/^Loaded image: //p'
    fi
    rm -rf "$K/images-installer"; mkdir -p "$K/images-installer"
    for g in "$K"/images/*.tar.gz; do [ "$g" = "$f" ] || ln -s "$g" "$K/images-installer/"; done
    echo "    for the installer (--image-archive $K/images-installer): $(cd "$K/images-installer" && ls | tr '\n' ' ')" ;;

  images)
    for n in web tools signer egress-proxy backup connector; do
      docker image inspect "patchgate-$n:$V" >/dev/null 2>&1 || { echo "    MISSING patchgate-$n:$V"; exit 1; }
    done
    docker images --format '{{.Repository}}:{{.Tag}}  {{.ID}}  {{.Size}}' | grep "patchgate-.*:$V" | sed 's/^/    /' ;;

  siem)
    # Stand-in platform SIEM (syslog over TLS) on this server, so the audit export really runs and the
    # readiness check / smoke test can pass. TEST ONLY: a real installation uses the platform SIEM.
    SIP="$2"; S="$K/siem"; install -d -m 0755 "$S"
    if [ ! -s "$S/cert.pem" ]; then
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=PatchGate kit test SIEM CA" \
        -keyout "$S/ca.key" -out "$S/ca.pem" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
      openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$SIP" -keyout "$S/key.pem" -out "$S/req.csr" 2>/dev/null
      printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n' "$SIP" > "$S/ext.cnf"
      openssl x509 -req -in "$S/req.csr" -CA "$S/ca.pem" -CAkey "$S/ca.key" -CAcreateserial -days 397 -sha256 -extfile "$S/ext.cnf" -out "$S/cert.pem" 2>/dev/null
      rm -f "$S/req.csr" "$S/ext.cnf" "$S/ca.srl" "$S/ca.key"
      chmod 0644 "$S/key.pem" "$S/cert.pem" "$S/ca.pem"   # throwaway test key, read by the sink's node user
    fi
    docker rm -f pgkit-test-siem >/dev/null 2>&1 || true
    docker run -d --name pgkit-test-siem --restart unless-stopped --network host --user 0 \
      -v "$S:/siem" -v "$K/lib/siem-sink.mjs:/siem-sink.mjs:ro" --entrypoint node "patchgate-tools:$V" /siem-sink.mjs >/dev/null
    for _ in $(seq 1 20); do (exec 3<>"/dev/tcp/127.0.0.1/6514") 2>/dev/null && break; sleep 1; done
    (exec 3<>"/dev/tcp/127.0.0.1/6514") 2>/dev/null || { docker logs pgkit-test-siem; echo "    test SIEM did not start"; exit 1; }
    echo "    test SIEM: tls://$SIP:6514 (CA $S/ca.pem), container pgkit-test-siem" ;;

  siem-status)
    cat "$K/siem/received.txt" 2>/dev/null || echo "no test SIEM" ;;

  install)
    # The real server installer, non-interactive. Registry mode with an EMPTY registry = use the images
    # loaded above (incl. the release's signer/egress-proxy/backup images). Self-signed TLS (test only).
    SIP="$2"
    # First account of users.conf (test-on-my-pc.sh KIT_USERS) = the platform admin the installer creates.
    first="$(grep -v -e '^#' -e '^BANK|' -e '^[[:space:]]*$' "$K/users.conf" | head -1)"
    ADMIN_UPN="$(printf '%s' "$first" | cut -d'|' -f2)"; ADMIN_NAME="$(printf '%s' "$first" | cut -d'|' -f3)"
    [ -n "$ADMIN_UPN" ] || { echo "    $K/users.conf has no accounts"; exit 1; }
    rm -rf /root/pg && mkdir -p /root/pg && cp -a "$K/product/installers" "$K/product/deploy" /root/pg/
    find /root/pg -type f \( -name '*.sh' -o -name '*.conf' -o -name '*.yml' -o -name '*.template' \) -exec sed -i 's/\r$//' {} +
    chmod 0755 /root/pg/installers/server/install-patchgate.sh
    rm -f "$K/secret/admin-temp-password"
    set +e
    cd /root/pg/installers/server && PG_REGISTRY="" ./install-patchgate.sh --non-interactive --domain "$DOMAIN" \
      --admin-email "$ADMIN_UPN" --admin-name "$ADMIN_NAME" --tls self-signed \
      --image-source registry --image-archive "$K/images-installer" --version "$V" --no-firewall \
      --siem-url "tls://$SIP:6514" --siem-ca "$K/siem/ca.pem" 2>&1 | {
        # Line by line (live progress); the line after "Temporary password for" is the one-time password.
        grab=0
        while IFS= read -r line; do
          if [ "$grab" = 1 ] && [ -n "${line// /}" ]; then
            (umask 077; printf '%s\n' "${line#"${line%%[! ]*}"}" > "$K/secret/admin-temp-password")
            echo "        <one-time password hidden: written to logins.txt>"; grab=0; continue
          fi
          case "$line" in *"Temporary password for"*) grab=1 ;; esac
          # docker compose layer-by-layer pull progress (thousands of lines): keep only the per-image lines
          [[ "$line" =~ ^\ *[0-9a-f]{12}\ (Pulling|Waiting|Downloading|Verifying|Download|Extracting|Pull\ complete|Already) ]] && continue
          printf '%s\n' "$line"
        done; }
    rc=${PIPESTATUS[0]}
    set -e
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
    "${DC[@]}" exec -T nginx nginx -s reload 2>&1 | sed 's/^/    /'
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

  fixture)
    # TEST FIXTURE: one clearly-labelled sample Windows update in the shared catalogue, so change requests can be
    # tried on a PC without real Windows endpoints reporting updates (the catalogue normally fills from the bank
    # PCs' scans via the connector). Inserted as the DB superuser; nothing else is touched.
    psql_q "INSERT INTO \"Patch\" (id, kind, \"externalId\", kb, title, classification, \"releasedAt\") VALUES ('kit-fixture-windows-1', 'WINDOWS', 'kit-fixture-00000000-0000-4000-8000-000000000001', 'KB0000001', 'TEST FIXTURE - sample Windows update (PatchGate test kit, not a real update)', 'Security Updates', now()) ON CONFLICT (id) DO NOTHING" >/dev/null
    ring="$(psql_q "select r.id from \"Ring\" r join \"Tenant\" t on t.id = r.\"tenantId\" where t.slug = '${2:-test-bank}' order by r.\"order\" limit 1")"
    [ -n "$ring" ] || { echo "    no ring for bank ${2:-test-bank}"; exit 1; }
    echo "    sample patch kit-fixture-windows-1 (KB0000001, TEST FIXTURE) in the catalogue; first ring of ${2:-test-bank}: $ring"
    printf '%s\n' "$ring" > "$K/ring.id" ;;

  cr-check)
    tools cr-check "$(cat "$K/ring.id")" kit-fixture-windows-1 "$2" ;;

  totp) tools totp "$2" ;;
  check-login) tools check-login "$2" ;;
  logins) tools logins ;;
  *) echo "usage: server-steps.sh load-images|siem <ip>|siem-status|install <siem-ip>|accounts|bundle|allowlist <ip>|enrol [site]|connector-status|smoke|ps|audit|totp <who>|check-login <who>|logins"; exit 2 ;;
esac
