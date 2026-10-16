#!/usr/bin/env bash
# Run the lab PatchGate = "our server" of the hosted architecture (docs/ARCHITECTURE-HOSTED.md).
#   bash lab/patchgate/start.sh                 → https://patchgate.<domain>:3443, local login (password only),
#                                                 banks reached ONLY through their connectors (signed jobs)
#   LAB_MODE=dev bash lab/patchgate/start.sh    → old single-bank dev setup: http://localhost:3000, dev user
#                                                 switcher, direct Tactical link (LAB_HTTPS=1 for https :3443)
# Only ONE `next dev` per patchgate-web folder: stop any other one first (lab/down-all.sh does).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/env.sh"

docker exec patchgate-dev-db createdb -U patchgate patchgate_lab 2>/dev/null || true
(cd "$PG_APP" && npx prisma migrate deploy >/dev/null)

cd "$PG_APP"
if [ "$LAB_MODE" = "dev" ]; then
  NODE_ENV=development npx tsx prisma/seed.ts >/dev/null 2>&1 || true   # dev users + sample bank PCs
fi

if [ "$LAB_MODE" = "hosted" ] || [ "${LAB_HTTPS:-0}" = "1" ]; then
  # NB: `next dev --experimental-https` REPLACES NODE_EXTRA_CA_CERTS with --experimental-https-ca, so the
  # lab CA must be passed here too — otherwise server-side TLS (Tactical in dev mode, SIEM) fails.
  echo "PatchGate ($LAB_MODE) → ${PG_URL}"
  exec npx next dev -H 0.0.0.0 -p 3443 \
    --experimental-https --experimental-https-key "$PG_CERTS/server.key" --experimental-https-cert "$PG_CERTS/fullchain.crt" \
    --experimental-https-ca "$PG_CERTS/ca.crt"
fi

echo "PatchGate (dev) → ${PG_URL}"
exec npx next dev -p 3000
