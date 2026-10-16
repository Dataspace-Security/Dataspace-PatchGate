#!/bin/bash
# Hot-standby streaming replica (compose profile "replica"). Runs as root, then hands over to the
# official entrypoint (which drops to "postgres").
#
# First start (empty volume): pg_basebackup from the primary, creating a physical replication slot
# so the primary keeps WAL until the replica has it. Later starts: just run the standby.
# Promote on primary loss:  docker compose ... exec -u postgres db-replica pg_ctl promote -D "$PGDATA"
# Remove the slot on the primary if the replica is decommissioned (else WAL accumulates):
#   SELECT pg_drop_replication_slot('patchgate_replica_1');
#
# TLS, both directions (RUNBOOK §4.2):
#   - as a CLIENT of the primary (pg_basebackup + walreceiver): sslmode=verify-full against the internal DB
#     CA (pg_ca_cert), so the replica only streams from a server holding a certificate for "db";
#   - as a SERVER: the same server certificate (SAN db + db-replica, pg_tls_key/pg_tls_cert), so clients can
#     keep verify-full when they are pointed at db-replica after a promotion.
set -euo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
primary="${PRIMARY_HOST:-db}"
slot="${REPLICA_SLOT:-patchgate_replica_1}"
export PGSSLMODE="${PGSSLMODE:-verify-full}"
export PGSSLROOTCERT="${PGSSLROOTCERT:-/run/secrets/pg_ca_cert}"
case "$PGSSLMODE" in verify-full|verify-ca) [ -r "$PGSSLROOTCERT" ] || { echo "replica: $PGSSLROOTCERT missing (secret pg_ca_cert)" >&2; exit 1; } ;; esac

dest=/run/pg-secrets
install -d -m 0700 -o postgres -g postgres "$dest"
server_tls=()
if [ -r /run/secrets/pg_tls_key ] && [ -r /run/secrets/pg_tls_cert ]; then
  install -m 0400 -o postgres -g postgres /run/secrets/pg_tls_key "$dest/pg_tls_key"
  install -m 0400 -o postgres -g postgres /run/secrets/pg_tls_cert "$dest/pg_tls_cert"
  server_tls=(-c ssl=on -c "ssl_cert_file=$dest/pg_tls_cert" -c "ssl_key_file=$dest/pg_tls_key" -c ssl_min_protocol_version=TLSv1.2)
else
  echo '{"level":"warn","msg":"db.tls_disabled","component":"db-replica","reason":"pg_tls_key/pg_tls_cert secrets missing"}' >&2
fi

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  install -d -m 0700 -o postgres -g postgres "$PGDATA"
  passfile=/var/run/postgresql/.pgpass
  install -d -m 0775 -o postgres -g postgres /var/run/postgresql
  printf '%s:5432:replication:replicator:%s\n' "$primary" "$(tr -d '\r\n' < /run/secrets/replication_password)" > "$passfile"
  chown postgres:postgres "$passfile"
  chmod 0600 "$passfile"
  until gosu postgres pg_isready -h "$primary" -p 5432 -q; do echo "replica: waiting for $primary"; sleep 3; done
  gosu postgres env PGPASSFILE="$passfile" \
    pg_basebackup -h "$primary" -U replicator -D "$PGDATA" -X stream -R -C -S "$slot" --checkpoint=fast --progress
  # Keep the password out of postgresql.auto.conf: point primary_conninfo at a passfile in PGDATA.
  install -m 0600 -o postgres -g postgres "$passfile" "$PGDATA/.pgpass_replication"
  rm -f "$passfile"
  echo "replica: base backup complete"
fi

# (Re)written on every start, so existing replicas pick up the TLS verification settings too.
sed -i '/^primary_conninfo/d' "$PGDATA/postgresql.auto.conf"
echo "primary_conninfo = 'host=$primary port=5432 user=replicator passfile=$PGDATA/.pgpass_replication application_name=$slot sslmode=$PGSSLMODE sslrootcert=$PGSSLROOTCERT'" >> "$PGDATA/postgresql.auto.conf"
chown postgres:postgres "$PGDATA/postgresql.auto.conf"

exec docker-entrypoint.sh postgres -c hot_standby=on -c "primary_slot_name=$slot" -c max_connections="${PG_MAX_CONNECTIONS:-200}" "${server_tls[@]}"
