#!/usr/bin/env bash
# Proves PostgreSQL server-certificate verification with the REAL production compose file, on a throw-away,
# isolated compose project (unique name, 10.249.x subnets, no host ports, no ./secrets of the real install).
#
#   ./scripts/test-db-tls.sh            # needs images: postgres:16-bookworm, patchgate-backup:local,
#                                       #               $PATCHGATE_TOOLS_IMAGE (default patchgate-tools:rc1)
#   KEEP=1 ./scripts/test-db-tls.sh     # leave the project running for inspection (tear down by hand)
#
# Checks: generate-secrets.sh issues CA + server cert; db serves TLS; libpq (backup: psql + a real
# `patchgate-backup now`) with verify-full PASSES with the right CA and FAILS with a wrong CA and a wrong
# hostname; Prisma (migrate: real `prisma migrate deploy` + a query) with sslaccept=strict PASSES / FAILS the
# same way; non-TLS is refused; the replica streams over verify-full and serves TLS as db-replica.
# Everything is torn down at the end (containers, networks, volumes, temp dir).
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS_IMAGE="${PATCHGATE_TOOLS_IMAGE:-patchgate-tools:rc1}"
PROJECT="pgtls-test-$(date +%s)-$$"
WORK="$(mktemp -d)"
win() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }

pass=0 fail=0
ok()  { echo "PASS  $1"; pass=$((pass + 1)); }
bad() { echo "FAIL  $1"; [ -n "${2:-}" ] && echo "      $2"; fail=$((fail + 1)); }
expect_ok()   { local name="$1"; shift; local out; if out="$("$@" 2>&1)"; then ok "$name -> $(echo "$out" | tail -1)"; else bad "$name (expected success)" "$(echo "$out" | tail -2 | tr '\n' ' ')"; fi; }
expect_fail() { local name="$1" pattern="$2"; shift 2; local out; if out="$("$@" 2>&1)"; then bad "$name (expected failure, got success)" "$(echo "$out" | tail -1)"; elif echo "$out" | grep -qiE "$pattern"; then ok "$name -> refused: $(echo "$out" | grep -oiE "$pattern" | head -1)"; else bad "$name (failed for another reason)" "$(echo "$out" | tail -2 | tr '\n' ' ')"; fi; }

cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then echo "KEEP=1: project $PROJECT left running (dir $WORK)"; return; fi
  (cd "$WORK" && "${DC[@]}" --profile replica --profile ops down -v --remove-orphans >/dev/null 2>&1)
  rm -rf "$WORK"
  echo "torn down: $PROJECT"
}

# ---- 1. throw-away copy of the deploy files + fresh secrets
cp -r "$HERE/docker-compose.prod.yml" "$HERE/postgres" "$HERE/scripts" "$WORK/"
mkdir -p "$WORK/ca" "$WORK/backups"
bash "$WORK/scripts/generate-secrets.sh" --dir "$WORK/secrets" >/dev/null || { echo "generate-secrets.sh failed"; exit 1; }
openssl verify -CAfile "$WORK/secrets/pg_ca_cert" "$WORK/secrets/pg_tls_cert" >/dev/null && ok "generate-secrets: pg_tls_cert issued by pg_ca_cert (SAN: $(openssl x509 -in "$WORK/secrets/pg_tls_cert" -noout -ext subjectAltName | tail -1 | xargs))" || bad "generate-secrets: cert chain"
mkdir -p "$WORK/wrong"
MSYS2_ARG_CONV_EXCL="/CN=" openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -subj "/CN=Wrong CA" -keyout "$WORK/wrong/ca.key" -out "$WORK/wrong/ca.crt" 2>/dev/null
chmod 0644 "$WORK/wrong/ca.crt"
# Git Bash: docker args with container paths must not be rewritten (openssl above needed the rewrite).
export MSYS_NO_PATHCONV=1
AGE_KEY="$(docker run --rm --entrypoint age-keygen patchgate-backup:local 2>/dev/null)"
AGE_PUB="$(echo "$AGE_KEY" | grep -o 'age1[0-9a-z]*' | head -1)"

cat > "$WORK/.env.production" <<EOF
PATCHGATE_IMAGE=$TOOLS_IMAGE
PATCHGATE_TOOLS_IMAGE=$TOOLS_IMAGE
PATCHGATE_HOSTNAME=pgtls.test.invalid
BACKUP_AGE_RECIPIENTS=$AGE_PUB
BACKUP_REPO=never
DB_ADMIN_SUBNET=10.249.5.0/24
SIEM_OUT_SUBNET=10.249.6.0/24
FETCH_EGRESS_SUBNET=10.249.7.0/24
EGRESS_PROXY_IP=10.249.7.10
PG_SHARED_BUFFERS=128MB
PG_EFFECTIVE_CACHE_SIZE=512MB
PG_MAINTENANCE_WORK_MEM=64MB
DB_MEMORY=1g
DB_CPUS=1
EOF
cat > "$WORK/isolation.override.yml" <<'EOF'
networks:
  edge: { ipam: { config: [{ subnet: 10.249.0.0/24 }] } }
  app: { ipam: { config: [{ subnet: 10.249.1.0/24 }] } }
  data: { ipam: { config: [{ subnet: 10.249.2.0/24 }] } }
  signer: { ipam: { config: [{ subnet: 10.249.3.0/24 }] } }
  fetch-ctl: { ipam: { config: [{ subnet: 10.249.4.0/24 }] } }
EOF
DC=(docker compose -p "$PROJECT" -f docker-compose.prod.yml -f isolation.override.yml --env-file .env.production)
trap cleanup EXIT
cd "$WORK" || exit 1

"${DC[@]}" config -q && ok "docker compose config (prod file + isolation override)" || { bad "docker compose config"; exit 1; }

# ---- 2. primary
"${DC[@]}" up -d --wait db >/dev/null 2>&1 || { bad "db did not become healthy"; "${DC[@]}" logs db | tail -20; exit 1; }
DBC="${PROJECT}-db-1"
expect_ok "db: SHOW ssl" bash -c "[ \"\$(${DC[*]} exec -T -u postgres db psql -XAtc 'SHOW ssl')\" = on ] && echo on"

# ---- 3. libpq client (backup container: db-admin network, superuser, PGSSLMODE=verify-full)
SQL="SELECT 'ssl='||ssl||' '||version FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
# psql with the password the way backup.sh loads it (PGPASSWORD_FILE), so failures below are TLS, not auth.
bk() { "${DC[@]}" run --rm --no-deps -T -v "$(win "$WORK/wrong"):/run/wrong:ro" "$@" --entrypoint bash backup          -c 'export PGPASSWORD="$(cat "$PGPASSWORD_FILE")"; exec psql -XAtc "$0"' "$SQL"; }
expect_ok   "libpq verify-full, right CA, host db"   bk
expect_fail "libpq verify-full, WRONG CA"            "certificate verify failed|self-signed certificate|unable to get local issuer" bk -e PGSSLROOTCERT=/run/wrong/ca.crt
expect_fail "libpq verify-full, WRONG hostname ($DBC)" "does not match host name" bk -e PGHOST="$DBC"
expect_fail "libpq sslmode=disable (no TLS)"         "no pg_hba.conf entry|no encryption|rejects connection" bk -e PGSSLMODE=disable
expect_ok   "backup: real 'patchgate-backup now' over verify-full" bash -c "${DC[*]} run --rm --no-deps -T backup now | tail -1"

# ---- 4. Prisma client (migrate container: the image entrypoint builds DATABASE_URL from DB_URL_PARAMS)
expect_ok "prisma migrate deploy (sslaccept=strict, right CA)" bash -c "${DC[*]} --profile ops run --rm --no-deps -T migrate | tail -1"
PQ='const {PrismaClient}=require("@prisma/client");new PrismaClient().$queryRawUnsafe("SELECT ssl, current_user AS u FROM pg_stat_ssl WHERE pid=pg_backend_pid()").then(r=>{console.log(JSON.stringify(r));process.exit(0)},e=>{console.error(String(e.message));process.exit(1)})'
MG=("${DC[@]}" --profile ops run --rm --no-deps -T -v "$(win "$WORK/wrong"):/run/wrong:ro")
WRONG_PARAMS="connection_limit=1&sslmode=require&sslaccept=strict&sslcert=/run/wrong/ca.crt"
expect_ok   "prisma strict, right CA, host db"        "${MG[@]}" migrate node -e "$PQ"
expect_fail "prisma strict, WRONG CA"                 "certificate verify failed" "${MG[@]}" -e DB_URL_PARAMS="$WRONG_PARAMS" migrate node -e "$PQ"
expect_fail "prisma strict, WRONG hostname ($DBC)"    "hostname mismatch" "${MG[@]}" -e DB_HOST="$DBC" migrate node -e "$PQ"

# ---- 5. replica: streams over verify-full, serves TLS with SAN db-replica
if "${DC[@]}" --profile replica up -d --wait db-replica >/dev/null 2>&1; then
  expect_ok "replica streams over TLS (pg_stat_replication JOIN pg_stat_ssl)" bash -c "r=\$(${DC[*]} exec -T -u postgres db psql -XAtc \"SELECT s.ssl FROM pg_stat_replication r JOIN pg_stat_ssl s USING (pid)\"); [ \"\$r\" = t ] && echo ssl=\$r"
  expect_ok "replica conninfo has verify-full" bash -c "${DC[*]} exec -T -u postgres db-replica psql -XAtc \"SELECT conninfo FROM pg_stat_wal_receiver\" | grep -o 'sslmode=verify-full'"
  expect_ok   "prisma strict -> db-replica (SAN), right CA" "${MG[@]}" -e DB_HOST=db-replica migrate node -e "$PQ"
  expect_fail "prisma strict -> db-replica, WRONG CA"      "certificate verify failed" "${MG[@]}" -e DB_HOST=db-replica -e DB_URL_PARAMS="$WRONG_PARAMS" migrate node -e "$PQ"
else
  bad "db-replica did not become healthy" "$("${DC[@]}" logs db-replica 2>&1 | tail -5 | tr '\n' ' ')"
fi

echo
echo "result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
