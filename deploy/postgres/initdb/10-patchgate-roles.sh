#!/bin/bash
# Runs ONCE, on first initialisation of an empty data directory (official image /docker-entrypoint-initdb.d).
#
# Roles (least privilege):
#   postgres            superuser — DB container, backups, restore only. Never used by the app.
#   patchgate_owner     owns the database/schema; used ONLY by the one-shot `migrate` job (DDL).
#   patchgate_app       runtime role for web/fetcher: DML only, NOT owner, NOT superuser — so PostgreSQL
#                       Row-Level Security policies apply to it (owners/superusers bypass RLS).
#   patchgate_tenant    NOLOGIN, NOBYPASSRLS: the app does SET LOCAL ROLE to it inside withTenant()/withPlatform().
#   replicator          streaming replication only (profile "replica").
#
# The official entrypoint SOURCES *.sh files that are not executable (e.g. after a Windows checkout), so
# the whole body runs in a subshell: its `set` options and `exit` never leak into the entrypoint.
(
set -euo pipefail

owner="${PATCHGATE_DB_OWNER:-patchgate_owner}"
app="${PATCHGATE_DB_APP:-patchgate_app}"
db="${POSTGRES_DB:-patchgate}"
secrets=/run/pg-secrets

read_secret() {
  local f="$secrets/$1"
  [ -s "$f" ] || { echo "initdb: missing secret $1" >&2; exit 1; }
  tr -d '\r\n' < "$f"
}

owner_pw="$(read_secret db_owner_password)"
app_pw="$(read_secret db_app_password)"
repl_pw=""
[ -s "$secrets/replication_password" ] && repl_pw="$(read_secret replication_password)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" \
  -v owner="$owner" -v app="$app" -v db="$db" \
  -v owner_pw="$owner_pw" -v app_pw="$app_pw" -v repl_pw="$repl_pw" <<'SQL'
CREATE ROLE :"owner" LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE :"app"   LOGIN PASSWORD :'app_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

ALTER DATABASE :"db" OWNER TO :"owner";
ALTER SCHEMA public OWNER TO :"owner";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO :"app";
GRANT USAGE ON SCHEMA public TO :"app";

-- RLS role used by withTenant()/withPlatform() (SET LOCAL ROLE patchgate_tenant; migration
-- 20261015020000_rls). Created here because the owner has no CREATEROLE; the migration's
-- "IF NOT EXISTS" then skips creation, and its "GRANT patchgate_tenant TO CURRENT_USER" needs ADMIN.
CREATE ROLE patchgate_tenant NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
GRANT patchgate_tenant TO :"owner" WITH ADMIN OPTION;
GRANT patchgate_tenant TO :"app";

-- Everything the migrate job creates later is usable (DML only) by the runtime role.
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO :"app";

SELECT CASE WHEN :'repl_pw' <> '' THEN 1 ELSE 0 END AS want_repl \gset
\if :want_repl
CREATE ROLE replicator LOGIN REPLICATION PASSWORD :'repl_pw';
\endif
SQL

# Client authentication (incl. replication) is NOT configured here: db-entrypoint.sh generates pg_hba on
# every start (hba_file in a tmpfs) — superuser only from the db-admin network, TLS-only network access.
echo "initdb: roles $owner, $app${repl_pw:+, replicator} created"
)
