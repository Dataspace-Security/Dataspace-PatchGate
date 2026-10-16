#!/usr/bin/env bash
# Restore a PatchGate database backup (age-encrypted pg_dump custom format).
#
# Drill (default, non-disruptive): restore into a NEW scratch database next to production, verify it,
# print a report, and (with --drop) remove it again. Production keeps running.
#   ./scripts/restore.sh --file backups/db/patchgate-20261015T010000Z.dump.age --identity /media/usb/age-identity.txt --drop
#
# Real restore (disruptive): restore into a scratch DB, verify, then stop the app, swap databases
# (the current DB is KEPT as patchgate_pre_restore_<ts>), start the app and check readiness.
#   ./scripts/restore.sh --file ... --identity ... --swap
#
# Requirements: run from deploy/, stack up (at least `db`), .env.production present, the backup image
# built (docker compose build backup). Plaintext is never written to disk: decrypt streams into pg_restore.
# The secrets in ./secrets must be the ones the backup was taken with (AUDIT_HMAC_KEY verifies the audit
# chain, AUTH_ENC_KEY decrypts TOTP secrets) — this script compares fingerprints from the manifest.
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker-compose.prod.yml --env-file .env.production)
FILE="" IDENTITY="" SWAP=0 DROP=0 YES=0
DB_NAME="$(grep -E '^POSTGRES_DB=' .env.production 2>/dev/null | cut -d= -f2- || true)"; DB_NAME="${DB_NAME:-patchgate}"
OWNER="$(grep -E '^DB_OWNER_USER=' .env.production 2>/dev/null | cut -d= -f2- || true)"; OWNER="${OWNER:-patchgate_owner}"
APP="$(grep -E '^DB_APP_USER=' .env.production 2>/dev/null | cut -d= -f2- || true)"; APP="${APP:-patchgate_app}"
APP_SERVICES=(scheduler fetcher web-1 web-2)

usage() { sed -n '2,17p' "$0"; exit 2; }
die() { echo "restore: ERROR: $*" >&2; exit 1; }
say() { echo "restore: $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --file) FILE="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --swap) SWAP=1; shift ;;
    --drop) DROP=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument $1" ;;
  esac
done
[ -n "$FILE" ] && [ -n "$IDENTITY" ] || usage
[ -r "$FILE" ] || die "cannot read $FILE"
[ -r "$IDENTITY" ] || die "cannot read identity $IDENTITY"
[ $SWAP -eq 1 ] && [ $DROP -eq 1 ] && die "--swap and --drop are mutually exclusive"

# Absolute host path for `docker run -v` (pwd -W: Git Bash on a Windows admin workstation; no-op on Linux).
abs_path() { (cd "$(dirname "$1")" && { pwd -W 2>/dev/null || pwd; }) | tr -d '\r' | sed "s#\$#/$(basename "$1")#"; }
export MSYS_NO_PATHCONV=1
FILE_ABS="$(abs_path "$FILE")"
IDENTITY_ABS="$(abs_path "$IDENTITY")"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SCRATCH="${DB_NAME}_restore_${TS,,}"

# Unix socket inside the db container (peer auth): no network hop, so no TLS involved. Network clients
# (app, backup, replica) verify the server certificate — RUNBOOK §4.2.
psql_db() { "${COMPOSE[@]}" exec -T -u postgres db psql -v ON_ERROR_STOP=1 -XAt "$@"; }

# 1. Integrity of the encrypted file.
if [ -r "$FILE.sha256" ]; then
  expected="$(cut -d' ' -f1 "$FILE.sha256")"
  actual="$(sha256sum "$FILE" | cut -d' ' -f1)"
  [ "$expected" = "$actual" ] || die "checksum mismatch for $FILE"
  say "checksum ok ($actual)"
else
  say "WARNING: no $FILE.sha256 — integrity of the encrypted file not checked"
fi

# 2. Secrets must match the ones used when the backup was taken.
MANIFEST="${FILE%.dump.age}.manifest.json"
if [ -r "$MANIFEST" ] && [ -r secrets/fingerprints.sha256 ]; then
  mismatch=0
  while read -r hash name; do
    want="$(grep -o "\"$name\":\"[0-9a-f]*\"" "$MANIFEST" | cut -d'"' -f4 || true)"
    if [ -n "$want" ] && [ "$want" != "$hash" ]; then
      echo "restore: WARNING: secret '$name' differs from the one in use when the backup was taken"
      mismatch=1
    fi
  done < secrets/fingerprints.sha256
  if [ $mismatch -eq 1 ]; then
    echo "restore: audit_hmac_key mismatch => audit chain verification fails; auth_enc_key mismatch => TOTP enrolments unusable."
    [ $YES -eq 1 ] || die "restore the matching secrets from escrow first (or pass --yes to continue anyway)"
  else
    say "secrets fingerprints match the backup manifest"
  fi
else
  say "WARNING: manifest or secrets/fingerprints.sha256 missing — secrets not compared"
fi

# 3. Restore into a scratch database (streaming decrypt -> pg_restore, no plaintext on disk).
say "creating scratch database $SCRATCH"
psql_db -d postgres -c "CREATE DATABASE \"$SCRATCH\" OWNER \"$OWNER\"" >/dev/null
psql_db -d "$SCRATCH" >/dev/null <<SQL
ALTER SCHEMA public OWNER TO "$OWNER";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE "$SCRATCH" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE "$SCRATCH" TO "$APP";
GRANT USAGE ON SCHEMA public TO "$APP";
SQL

say "decrypting + restoring (this can take a while)"
"${COMPOSE[@]}" run --rm --no-deps -T \
  -v "$FILE_ABS:/restore/backup.age:ro" -v "$IDENTITY_ABS:/run/age-identity:ro" \
  backup decrypt /restore/backup.age /run/age-identity \
| "${COMPOSE[@]}" exec -T -u postgres db \
  pg_restore --dbname="$SCRATCH" --no-owner --role="$OWNER" --exit-on-error

# Runtime role needs DML on everything restored (ACLs in the dump may reference other role names).
psql_db -d "$SCRATCH" >/dev/null <<SQL
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "$APP";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "$APP";
ANALYZE;
SQL

# 4. Verify.
say "verification of $SCRATCH:"
pending="$(psql_db -d "$SCRATCH" -c 'SELECT count(*) FROM "_prisma_migrations" WHERE finished_at IS NULL OR rolled_back_at IS NOT NULL')"
head="$(psql_db -d "$SCRATCH" -c 'SELECT migration_name FROM "_prisma_migrations" WHERE finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1')"
echo "  migration head: ${head:-<none>}  (unfinished/rolled back: $pending)"
[ "$pending" = "0" ] || die "restored database has unfinished migrations"
echo "  row counts:"
psql_db -d "$SCRATCH" -F $'\t' <<'SQL' | sed 's/^/    /'
SELECT format('SELECT %L, count(*) FROM %I.%I', relname, schemaname, relname)
FROM pg_stat_user_tables ORDER BY relname \gexec
SQL

if [ $SWAP -eq 0 ]; then
  if [ $DROP -eq 1 ]; then
    psql_db -d postgres -c "DROP DATABASE \"$SCRATCH\"" >/dev/null
    say "drill OK — scratch database dropped"
  else
    say "drill OK — scratch database $SCRATCH kept (drop it with: DROP DATABASE \"$SCRATCH\")"
  fi
  exit 0
fi

# 5. Swap (disruptive).
if [ $YES -ne 1 ]; then
  read -r -p "Stop PatchGate and replace database '$DB_NAME' with the restored copy? Type RESTORE: " answer
  [ "$answer" = "RESTORE" ] || die "aborted (scratch database $SCRATCH kept)"
fi
say "stopping ${APP_SERVICES[*]}"
"${COMPOSE[@]}" stop "${APP_SERVICES[@]}"
psql_db -d postgres >/dev/null <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ('$DB_NAME', '$SCRATCH') AND pid <> pg_backend_pid();
ALTER DATABASE "$DB_NAME" RENAME TO "${DB_NAME}_pre_restore_${TS,,}";
ALTER DATABASE "$SCRATCH" RENAME TO "$DB_NAME";
SQL
say "databases swapped (previous kept as ${DB_NAME}_pre_restore_${TS,,})"
"${COMPOSE[@]}" up -d "${APP_SERVICES[@]}"
say "started; checking readiness"
for i in $(seq 1 30); do
  if "${COMPOSE[@]}" exec -T web-1 node -e "fetch('http://127.0.0.1:3000/api/ready').then(r=>r.text().then(t=>{console.log(t);process.exit(r.ok?0:1)}),()=>process.exit(1))"; then
    say "restore complete. Check that checks.auditChain is true; then run scripts/smoke-test.sh."
    exit 0
  fi
  sleep 5
done
die "web-1 not ready after restore — inspect logs; previous DB is ${DB_NAME}_pre_restore_${TS,,}"
