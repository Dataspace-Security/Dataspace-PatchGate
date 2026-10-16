#!/bin/bash
# PatchGate colleague test kit — steps that run INSIDE the kit's site container (TEST KIT ONLY).
# The site container stands in for the bank's fresh Ubuntu 24.04 site VM WITH internet (online mode):
# the documented one-line install pulls Docker from download.docker.com and Tactical from Docker Hub.
set -euo pipefail
K=/root/kit
DOMAIN="${KIT_DOMAIN:-patchgate.pgi.test}"
SITE_DOMAIN="${KIT_SITE_DOMAIN:-test-bank.pgi.test}"

case "${1:-}" in
  prep)
    # What a minimal Ubuntu server image has and the container image lacks (curl, CA store, ss, gpg, iptables).
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg iproute2 iptables openssl procps sudo >/dev/null
    echo "    base tools installed: $(curl --version | head -1 | cut -d' ' -f1-2), $(openssl version | cut -d' ' -f1-2)" ;;

  install)
    # The one-line site install exactly as shown in PatchGate (Connectors -> Add site), plus the answers a
    # bank IT person would type at the prompts (no terminal under docker exec), plus the test-only bits:
    # --patchgate-ca (our self-signed test CA) and --patchgate-ip (the container has no DNS for our name).
    PG_IP="$2"
    [ -s "$K/enrol.env" ] || { echo "    $K/enrol.env missing (enrolment code)"; exit 1; }
    # shellcheck disable=SC1091
    . "$K/enrol.env"   # CODE, FP, SERVER — never echoed
    echo "    curl -fsSL https://$DOMAIN/install/site.sh | sudo bash -s -- --code <one-time code> --fingerprint ${FP:0:16}... \\"
    echo "         --online --site-name \"Head office\" --domain $SITE_DOMAIN --tls self-signed \\"
    echo "         --patchgate-ca $K/patchgate-ca.pem --patchgate-ip $PG_IP --no-lockdown --non-interactive"
    set +e
    curl -fsSL --cacert "$K/patchgate-ca.pem" "https://$DOMAIN/install/site.sh" | sudo bash -s -- \
      --code "$CODE" --fingerprint "$FP" --online --site-name "Head office" --domain "$SITE_DOMAIN" \
      --tls self-signed --patchgate-ca "$K/patchgate-ca.pem" --patchgate-ip "$PG_IP" --no-lockdown --non-interactive 2>&1 | \
      awk -v f="$K/tactical-admin-password" '
        grab { pw = $0; sub(/^[ \t]+/, "", pw); printf "%s\n", pw > f; close(f); print "        <hidden: written to logins.txt>"; grab = 0; next }
        /Tactical admin .tacticaladmin. password/ { grab = 1 }
        { print; fflush() }'
    rc=("${PIPESTATUS[@]}")
    set -e
    [ -f "$K/tactical-admin-password" ] && chmod 0600 "$K/tactical-admin-password"
    [ "${rc[0]}" = 0 ] || { echo "    downloading https://$DOMAIN/install/site.sh failed (curl exit ${rc[0]})"; exit 9; }
    exit "${rc[1]}" ;;

  check)
    docker exec pg-site-connector node /opt/patchgate-connector/patchgate-connector.mjs check 2>&1 | sed 's/^/    /' ;;

  digests)
    docker image ls --digests --format '{{.Repository}}:{{.Tag}} {{.Digest}}' | grep -E '^(tacticalrmm/|mongo:|postgres:|redis:)' | sort | sed 's/^/    /'
    if [ -f /opt/patchgate-site/runtime/images/IMAGES.lock ]; then
      echo "    pinned in the bundle (images/IMAGES.lock):"
      sed 's/^/      /' /opt/patchgate-site/runtime/images/IMAGES.lock
    fi ;;

  ps)
    docker ps --format 'table {{.Names}}\t{{.Status}}' | sed 's/^/    /' ;;

  *) echo "usage: site-steps.sh prep|install <patchgate-ip>|check|digests|ps"; exit 2 ;;
esac
