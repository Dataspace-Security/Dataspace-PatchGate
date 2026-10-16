#!/bin/bash
# PatchGate backup sidecar.
#
#   patchgate-backup schedule     # default: run daily at BACKUP_HOUR_UTC, forever
#   patchgate-backup now          # one database backup now (+ repo if BACKUP_REPO=always)
#   patchgate-backup repo         # one package-store backup now
#   patchgate-backup prune        # apply retention only
#   patchgate-backup decrypt <file.age> <identity-file>   # used by scripts/restore.sh (writes to stdout)
#
# Output in /backups (host: ${BACKUP_DIR}):
#   db/patchgate-<UTC>.dump.age          pg_dump custom format, age-encrypted to BACKUP_AGE_RECIPIENTS
#   db/patchgate-<UTC>.dump.age.sha256   checksum of the encrypted file
#   db/patchgate-<UTC>.manifest.json     metadata: sizes, server version, migration head, secrets fingerprints
#   repo/repo-<UTC>.tar.age              package store snapshot (weekly by default)
#
# The server only holds the age PUBLIC key: it can write backups but never read them. The private
# identity lives offline (two custodians) and is needed only for restore.
set -euo pipefail
umask 077

OUT=/backups
DB_DIR="$OUT/db"
REPO_OUT="$OUT/repo"
REPO_SRC=/data/repo
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-35}"
REPO_RETENTION_WEEKS="${BACKUP_REPO_RETENTION_WEEKS:-4}"
HOUR="${BACKUP_HOUR_UTC:-1}"
REPO_MODE="${BACKUP_REPO:-weekly}" # weekly | always | never

log() { # JSON lines, same shape as src/lib/log.ts
  local level="$1" msg="$2"; shift 2
  local extra=""
  for kv in "$@"; do extra="$extra,\"${kv%%=*}\":\"${kv#*=}\""; done
  printf '{"ts":"%s","level":"%s","msg":"%s","component":"backup"%s}\n' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$level" "$msg" "$extra"
}

load_password() {
  if [ -z "${PGPASSWORD:-}" ] && [ -n "${PGPASSWORD_FILE:-}" ]; then
    PGPASSWORD="$(tr -d '\r\n' < "$PGPASSWORD_FILE")"
    export PGPASSWORD
  fi
}

recipients_args() {
  local args=() r
  [ -n "${BACKUP_AGE_RECIPIENTS:-}" ] || { log error backup.no_recipient; exit 1; }
  for r in ${BACKUP_AGE_RECIPIENTS//,/ }; do args+=(-r "$r"); done
  printf '%s\n' "${args[@]}"
}

backup_db() {
  load_password
  mkdir -p "$DB_DIR"
  local ts file tmp
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  file="$DB_DIR/patchgate-$ts.dump.age"
  tmp="$file.partial"
  mapfile -t rargs < <(recipients_args)
  log info backup.db.start file="$(basename "$file")"
  # Stream: pg_dump -> age -> disk. No plaintext ever touches the disk.
  if ! pg_dump --format=custom --compress=6 --no-password --serializable-deferrable | age "${rargs[@]}" -o "$tmp"; then
    rm -f "$tmp"; log error backup.db.failed; return 1
  fi
  mv "$tmp" "$file"
  (cd "$DB_DIR" && sha256sum "$(basename "$file")" > "$(basename "$file").sha256")

  local server_version migration_head size fp="null"
  server_version="$(psql -XAtc 'SHOW server_version' 2>/dev/null || echo unknown)"
  migration_head="$(psql -XAtc 'SELECT migration_name FROM "_prisma_migrations" WHERE finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1' 2>/dev/null || echo unknown)"
  size="$(stat -c %s "$file")"
  if [ -r /etc/patchgate/secrets.sha256 ]; then
    fp="$(awk 'BEGIN{printf "{"} NR>1{printf ","} {printf "\"%s\":\"%s\"", $2, $1} END{printf "}"}' /etc/patchgate/secrets.sha256)"
  fi
  cat > "$DB_DIR/patchgate-$ts.manifest.json" <<JSON
{"createdAt":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","file":"$(basename "$file")","bytes":$size,"sha256":"$(cut -d' ' -f1 "$file.sha256")","database":"${PGDATABASE}","serverVersion":"$server_version","migrationHead":"$migration_head","secretsFingerprints":$fp}
JSON
  log info backup.db.done file="$(basename "$file")" bytes="$size"
}

backup_repo() {
  [ -d "$REPO_SRC" ] || { log warn backup.repo.missing; return 0; }
  mkdir -p "$REPO_OUT"
  local ts file
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  file="$REPO_OUT/repo-$ts.tar.age"
  mapfile -t rargs < <(recipients_args)
  log info backup.repo.start
  # Packages are already compressed installers: tar without compression.
  if ! tar -C "$REPO_SRC" -cf - . | age "${rargs[@]}" -o "$file.partial"; then
    rm -f "$file.partial"; log error backup.repo.failed; return 1
  fi
  mv "$file.partial" "$file"
  (cd "$REPO_OUT" && sha256sum "$(basename "$file")" > "$(basename "$file").sha256")
  log info backup.repo.done bytes="$(stat -c %s "$file")"
}

prune() {
  [ -d "$DB_DIR" ] && find "$DB_DIR" -type f -name 'patchgate-*' -mtime +"$RETENTION_DAYS" -print -delete | sed 's/^/pruned /' || true
  [ -d "$REPO_OUT" ] && find "$REPO_OUT" -type f -name 'repo-*' -mtime +"$((REPO_RETENTION_WEEKS * 7))" -print -delete | sed 's/^/pruned /' || true
  find "$OUT" -name '*.partial' -mmin +720 -delete 2>/dev/null || true
}

run_once() {
  local rc=0
  backup_db || rc=1
  if [ "$REPO_MODE" = "always" ] || { [ "$REPO_MODE" = "weekly" ] && [ "$(date -u +%u)" = "7" ]; }; then
    backup_repo || rc=1
  fi
  prune
  # Heartbeat file for monitoring (alert if older than 26 h or status != ok).
  printf '{"ts":"%s","status":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ $rc -eq 0 ] && echo ok || echo failed)" > "$OUT/last-run.json"
  return $rc
}

seconds_until_next_run() {
  local now target
  now="$(date -u +%s)"
  target="$(date -u -d "today ${HOUR}:00" +%s)"
  [ "$target" -gt "$now" ] || target="$(date -u -d "tomorrow ${HOUR}:00" +%s)"
  echo $((target - now))
}

case "${1:-schedule}" in
  now) run_once ;;
  repo) backup_repo ;;
  prune) prune ;;
  decrypt)
    [ $# -eq 3 ] || { echo "usage: decrypt <file.age> <identity>" >&2; exit 2; }
    age -d -i "$3" "$2"
    ;;
  schedule)
    log info backup.scheduler.start hourUtc="$HOUR" retentionDays="$RETENTION_DAYS" repo="$REPO_MODE"
    while true; do
      wait_s="$(seconds_until_next_run)"
      log info backup.scheduler.sleep seconds="$wait_s"
      sleep "$wait_s"
      run_once || log error backup.run.failed
    done
    ;;
  *) exec "$@" ;;
esac
