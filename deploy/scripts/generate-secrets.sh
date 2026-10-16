#!/usr/bin/env bash
# Generate PatchGate production secrets as files in deploy/secrets/ (mounted as Docker secrets).
#
#   sudo ./scripts/generate-secrets.sh                          # create missing secrets, never overwrite
#   sudo ./scripts/generate-secrets.sh --rotate worker_token    # replace ONE secret (see RUNBOOK §9)
#   sudo ./scripts/generate-secrets.sh --job-key <tenantId>     # create a bank's OWN job-signing key
#   sudo ./scripts/generate-secrets.sh --rotate-job-key <tenantId|default>   # new key, old one retired
#   sudo ./scripts/generate-secrets.sh --rotate auth_enc_key    # current key -> auth_enc_key_previous, new key
#                                                               # (RUNBOOK §9.4; refuses to replace a DIFFERENT
#                                                               #  existing previous key unless --force)
#
# Files are 0600, owned by uid/gid 10001 (the PatchGate container user); root-started containers
# (postgres, backup) read them via capabilities. Exceptions: job_signer_token is 0640 (group 10001 so the
# signer, uid 10002/gid 10001, can read it), metrics_token is 0640 (Prometheus runs as 65534:10001),
# grafana_admin_password is owned by uid 472 (Grafana) and secrets/job-signing-keys/ belongs to the signer (uid 10002,
# 0700/0600) so no PatchGate web/fetcher process can read a private key even if mis-mounted.
# Run as root so ownership can be set.
#
# NEVER rotate audit_hmac_key or auth_enc_key casually: the audit chain is HMAC'd with the first, TOTP
# secrets are encrypted with the second (procedures in docs/RUNBOOK.md §9). Escrow a copy of
# secrets/ (encrypted, two custodians) — a database backup is useless without the matching keys.
set -euo pipefail
umask 077

cd "$(dirname "$0")/.."
DIR=secrets
APP_UID=10001
APP_GID=10001
SIGNER_UID=10002
ROTATE=""
JOB_KEY=""
ROTATE_JOB_KEY=""
FORCE=0
TENANT_RE='^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'

while [ $# -gt 0 ]; do
  case "$1" in
    --rotate) ROTATE="$2"; shift 2 ;;
    --job-key) JOB_KEY="$2"; shift 2 ;;
    --rotate-job-key) ROTATE_JOB_KEY="$2"; shift 2 ;;
    --dir) DIR="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
# Backwards compatible alias: the single legacy key is now the signer's default key.
[ "$ROTATE" = "job_signing_key" ] && { ROTATE=""; ROTATE_JOB_KEY="default"; }
for id in "$JOB_KEY" "$ROTATE_JOB_KEY"; do
  [ -z "$id" ] || [ "$id" = default ] || [[ "$id" =~ $TENANT_RE ]] || { echo "invalid tenant id: $id (use the Tenant.id, [A-Za-z0-9_-], max 64)" >&2; exit 2; }
done

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
mkdir -p "$DIR"
chmod 0700 "$DIR"
KEYDIR="$DIR/job-signing-keys"
mkdir -p "$KEYDIR"
chmod 0700 "$KEYDIR"

hex32() { openssl rand -hex 32; }   # 32 random bytes = 64 hex chars (URL-safe, >= 32 chars)

# name -> generator
declare -A GEN=(
  [postgres_superuser_password]=hex32
  [db_owner_password]=hex32
  [db_app_password]=hex32
  [replication_password]=hex32
  [audit_hmac_key]=hex32          # AUDIT_HMAC_KEY  (>= 32 chars)
  [worker_token]=hex32            # WORKER_TOKEN    (>= 32 chars)
  [wsus_token]=hex32              # WSUS_TOKEN      (>= 32 chars)
  [auth_enc_key]=hex32            # AUTH_ENC_KEY    (exactly 64 hex = 32-byte AES-256-GCM key)
  [tactical_api_key]=hex32        # TACTICAL_API_KEY: placeholder in the hosted model (connectors talk to Tactical)
  [job_signer_token]=hex32        # web-1/2 -> signer bearer token (JOB_SIGNER_TOKEN_FILE / SIGNER_TOKEN_FILE)
  [metrics_token]=hex32           # METRICS_TOKEN (web-1/2 METRICS_TOKEN_FILE) = Prometheus bearer credentials_file
  [grafana_admin_password]=hex32  # Grafana admin (GF_SECURITY_ADMIN_PASSWORD__FILE; profile "monitoring")
)

write_secret() { # name value
  local tmp
  tmp="$(mktemp "$DIR/.tmp.XXXXXX")"
  printf '%s' "$2" > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$DIR/$1"
}

created=()
# AUTH_ENC_KEY rotation (RUNBOOK §9.4): the current key becomes the decrypt-only auth_enc_key_previous
# (AUTH_ENC_KEY_PREVIOUS_FILE via docker-compose.rotation.yml) before a new auth_enc_key is generated below.
# A previous key that already equals the current one (§9.4 step 1 `cp -p`) is fine; a DIFFERENT one means an
# earlier rotation was not finished (its re-encryption may still need it) -> refuse unless --force.
if [ "$ROTATE" = "auth_enc_key" ] && [ -s "$DIR/auth_enc_key" ]; then
  if [ -s "$DIR/auth_enc_key_previous" ] && ! cmp -s "$DIR/auth_enc_key" "$DIR/auth_enc_key_previous" && [ "$FORCE" -ne 1 ]; then
    echo "auth_enc_key_previous exists and differs from auth_enc_key: finish the previous rotation first" >&2
    echo "(RUNBOOK §9.4 step 4: re-encrypt, then remove auth_enc_key_previous) or pass --force to replace it" >&2
    exit 2
  fi
  write_secret auth_enc_key_previous "$(cat "$DIR/auth_enc_key")"
  created+=("auth_enc_key_previous")
fi
for name in "${!GEN[@]}"; do
  if [ -s "$DIR/$name" ] && [ "$ROTATE" != "$name" ]; then continue; fi
  write_secret "$name" "$(${GEN[$name]})"
  created+=("$name")
done

# ---- PostgreSQL TLS with server verification (app/backup/replica <-> db on the internal networks).
#   pg_ca_key  / pg_ca_cert   small internal DB CA (ECDSA P-256, 10 years). The CA key is used ONLY here
#                             (never mounted into a container); pg_ca_cert is public and given to every
#                             DB client, which verifies the server with sslmode=verify-full (libpq) or
#                             sslaccept=strict + sslcert (Prisma) — RUNBOOK §4.2.
#   pg_tls_key / pg_tls_cert  server certificate for the DB service names db + db-replica, signed by the CA
#                             (825 days). Re-issued automatically when it is missing, not signed by the
#                             current CA (e.g. the old self-signed one), lacks a SAN, or expires within 30 days.
#   --rotate pg_tls           new server key + certificate (same CA: clients need no change)
#   --rotate pg_ca            new CA AND server certificate: restart db, db-replica and ALL clients together.
PG_SANS="DNS:db,DNS:db-replica"
# Git Bash (admin workstation) would rewrite "-subj /CN=..." into a Windows path; no effect on Linux.
export MSYS2_ARG_CONV_EXCL="${MSYS2_ARG_CONV_EXCL:+$MSYS2_ARG_CONV_EXCL;}/CN="
if [ ! -s "$DIR/pg_ca_key" ] || [ ! -s "$DIR/pg_ca_cert" ] || [ "$ROTATE" = "pg_ca" ]; then
  ck="$(mktemp "$DIR/.tmp.XXXXXX")"; cc="$(mktemp "$DIR/.tmp.XXXXXX")"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -sha256 \
    -subj "/CN=PatchGate internal DB CA/O=PatchGate internal" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -keyout "$ck" -out "$cc" 2>/dev/null
  chmod 0600 "$ck"; chmod 0644 "$cc"
  mv -f "$ck" "$DIR/pg_ca_key"; mv -f "$cc" "$DIR/pg_ca_cert"
  created+=("pg_ca_key" "pg_ca_cert")
fi
pg_server_cert_ok() {
  [ -s "$DIR/pg_tls_key" ] && [ -s "$DIR/pg_tls_cert" ] || return 1
  openssl verify -CAfile "$DIR/pg_ca_cert" "$DIR/pg_tls_cert" >/dev/null 2>&1 || return 1
  openssl x509 -in "$DIR/pg_tls_cert" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
  local san; san="$(openssl x509 -in "$DIR/pg_tls_cert" -noout -ext subjectAltName 2>/dev/null)"
  [[ "$san" == *"DNS:db,"* || "$san" == *"DNS:db" ]] && [[ "$san" == *"DNS:db-replica"* ]]
}
if ! pg_server_cert_ok || [ "$ROTATE" = "pg_tls" ] || [ "$ROTATE" = "pg_ca" ]; then
  [ -s "$DIR/pg_tls_cert" ] && [ "$ROTATE" != "pg_tls" ] && [ "$ROTATE" != "pg_ca" ] \
    && echo "pg_tls_cert is not a valid certificate from pg_ca_cert (old self-signed / SAN / expiry) — re-issuing"
  tk="$(mktemp "$DIR/.tmp.XXXXXX")"; tr_="$(mktemp "$DIR/.tmp.XXXXXX")"; tc="$(mktemp "$DIR/.tmp.XXXXXX")"
  ext="$(mktemp "$DIR/.tmp.XXXXXX")"
  printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" "subjectAltName=$PG_SANS" "authorityKeyIdentifier=keyid" > "$ext"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 \
    -subj "/CN=db/O=PatchGate internal" -keyout "$tk" -out "$tr_" 2>/dev/null
  openssl x509 -req -in "$tr_" -CA "$DIR/pg_ca_cert" -CAkey "$DIR/pg_ca_key" -set_serial "0x$(openssl rand -hex 16)" \
    -days 825 -sha256 -extfile "$ext" -out "$tc" 2>/dev/null
  rm -f "$tr_" "$ext"
  openssl verify -CAfile "$DIR/pg_ca_cert" "$tc" >/dev/null || { rm -f "$tk" "$tc"; echo "pg_tls_cert: issuing failed" >&2; exit 1; }
  chmod 0600 "$tk"; chmod 0644 "$tc"
  mv -f "$tk" "$DIR/pg_tls_key"; mv -f "$tc" "$DIR/pg_tls_cert"
  created+=("pg_tls_key" "pg_tls_cert")
fi

# ---- Job-signing keys (Ed25519) — live ONLY in the signer container (secrets/job-signing-keys/).
#   default.pem      used for every bank without its own key
#   <tenantId>.pem   a bank's own key (recommended for every production bank)
# Connectors pin the PUBLIC key (enrolment) and its fingerprint (--job-key-fingerprint at init):
# fingerprint = SHA-256 (hex) of the raw 32-byte Ed25519 public key. Rotation = re-pin (RUNBOOK §9.1).
new_job_key() { # id
  local tmp
  tmp="$(mktemp "$KEYDIR/.tmp.XXXXXX")"
  openssl genpkey -algorithm ed25519 -out "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$KEYDIR/$1.pem"
  openssl pkey -in "$KEYDIR/$1.pem" -pubout -out "$KEYDIR/$1.pub.pem"
  chmod 0644 "$KEYDIR/$1.pub.pem"
  created+=("job-signing-keys/$1.pem")
}
retire_job_key() { # id — keep the old key (not loaded: name no longer ends in .pem) for audits/rollback
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  [ -f "$KEYDIR/$1.pem" ] && mv -f "$KEYDIR/$1.pem" "$KEYDIR/$1.pem.retired-$ts"
  [ -f "$KEYDIR/$1.pub.pem" ] && mv -f "$KEYDIR/$1.pub.pem" "$KEYDIR/$1.pub.pem.retired-$ts"
  return 0
}
job_key_fingerprint() { # pem file -> sha256 hex of the raw 32-byte public key
  openssl pkey -in "$1" -pubout -outform DER | tail -c 32 | openssl dgst -sha256 -r | cut -d' ' -f1
}

if [ ! -s "$KEYDIR/default.pem" ]; then
  if [ -s "$DIR/job_signing_key.pem" ]; then
    # Upgrade from the single-key layout: keep the key connectors already pinned.
    install -m 0600 "$DIR/job_signing_key.pem" "$KEYDIR/default.pem"
    openssl pkey -in "$KEYDIR/default.pem" -pubout -out "$KEYDIR/default.pub.pem"
    chmod 0644 "$KEYDIR/default.pub.pem"
    echo "migrated secrets/job_signing_key.pem -> job-signing-keys/default.pem (delete the old file after verifying the signer)"
  else
    new_job_key default
  fi
fi
if [ -n "$ROTATE_JOB_KEY" ]; then
  retire_job_key "$ROTATE_JOB_KEY"
  new_job_key "$ROTATE_JOB_KEY"
fi
if [ -n "$JOB_KEY" ]; then
  if [ -s "$KEYDIR/$JOB_KEY.pem" ]; then echo "job key for $JOB_KEY already exists (use --rotate-job-key)" >&2; exit 2; fi
  new_job_key "$JOB_KEY"
fi

if [ -n "$ROTATE" ] && [ "${#created[@]}" -eq 0 ]; then
  echo "unknown secret name for --rotate: $ROTATE" >&2; exit 2
fi

# Sanity checks (same rules as src/lib/env.ts).
[[ "$(cat "$DIR/auth_enc_key")" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "auth_enc_key must be 64 hex chars" >&2; exit 1; }
if [ -s "$DIR/auth_enc_key_previous" ]; then
  [[ "$(cat "$DIR/auth_enc_key_previous")" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "auth_enc_key_previous must be 64 hex chars" >&2; exit 1; }
  ! cmp -s "$DIR/auth_enc_key" "$DIR/auth_enc_key_previous" || { echo "auth_enc_key_previous equals auth_enc_key: run --rotate auth_enc_key" >&2; exit 1; }
fi
for n in audit_hmac_key worker_token wsus_token job_signer_token metrics_token; do
  [ "$(wc -c < "$DIR/$n")" -ge 32 ] || { echo "$n must be >= 32 chars" >&2; exit 1; }
done
for f in "$KEYDIR"/*.pem; do
  case "$f" in *.pub.pem) continue ;; esac
  openssl pkey -in "$f" -noout -text 2>/dev/null | grep -q "ED25519" || { echo "$f is not Ed25519" >&2; exit 1; }
done

# Job-key fingerprints (NOT secret): what each bank pins (--job-key-fingerprint). Confirm out-of-band.
(
  cd "$KEYDIR"
  for f in *.pem; do
    case "$f" in *.pub.pem) continue ;; esac
    printf '%s  %s\n' "$(job_key_fingerprint "$f")" "${f%.pem}"
  done
) > "$KEYDIR/FINGERPRINTS.txt"
chmod 0644 "$KEYDIR/FINGERPRINTS.txt"

# Fingerprints (NOT secret): copied into every backup manifest so a restore can prove it uses the
# same keys. Format: "<sha256>  <name>".
(
  cd "$DIR"
  for f in audit_hmac_key auth_enc_key worker_token wsus_token job_signer_token metrics_token grafana_admin_password db_owner_password db_app_password postgres_superuser_password replication_password tactical_api_key pg_tls_cert pg_ca_cert; do
    printf '%s  %s\n' "$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)" "$f"
  done
  if [ -s auth_enc_key_previous ]; then   # only during an AUTH_ENC_KEY rotation (RUNBOOK §9.4)
    printf '%s  %s\n' "$(openssl dgst -sha256 -r auth_enc_key_previous | cut -d' ' -f1)" auth_enc_key_previous
  fi
  for f in job-signing-keys/*.pem; do
    case "$f" in *.pub.pem) continue ;; esac
    printf '%s  %s\n' "$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)" "$f"
  done
) > "$DIR/fingerprints.sha256"
chmod 0644 "$DIR/fingerprints.sha256"

chmod 0640 "$DIR/job_signer_token"
# metrics_token: read by web-1/2 (uid 10001) AND Prometheus, which runs as 65534:10001 (compose) -> group read.
chmod 0640 "$DIR/metrics_token"
GRAFANA_UID=472
if [ "$(id -u)" = "0" ]; then
  chown "$APP_UID:$APP_GID" "$DIR"
  find "$DIR" -maxdepth 1 -type f -exec chown "$APP_UID:$APP_GID" {} +
  chown -R "$SIGNER_UID:$APP_GID" "$KEYDIR"
  chown "$GRAFANA_UID:0" "$DIR/grafana_admin_password"   # 0600, Grafana container user 472
else
  echo "WARNING: not root — run: sudo chown $APP_UID:$APP_GID $(pwd)/$DIR $(pwd)/$DIR/* && sudo chown -R $SIGNER_UID:$APP_GID $(pwd)/$KEYDIR && sudo chown $GRAFANA_UID:0 $(pwd)/$DIR/grafana_admin_password"
fi

echo "secrets in $(pwd)/$DIR:"
ls -l "$DIR" "$KEYDIR"
if [ "${#created[@]}" -gt 0 ]; then echo "created/rotated: ${created[*]}"; else echo "nothing created (all present)"; fi
echo
echo "Job-signing key fingerprints (banks pin these; confirm by phone):"
sed 's/^/  /' "$KEYDIR/FINGERPRINTS.txt"
if [ -n "$ROTATE_JOB_KEY$JOB_KEY" ]; then
  echo "Reload the signer: docker compose -f docker-compose.prod.yml --env-file .env.production kill -s HUP signer"
fi
cat <<'TXT'

Next:
  1. Escrow an encrypted copy of secrets/ offline (two custodians). Without audit_hmac_key + auth_enc_key
     a restored database cannot verify its audit chain or accept TOTP logins.
  2. Backups: generate the age key pair OFFLINE (age-keygen -o patchgate-backup.agekey) and put only the
     public key ("age1...") into BACKUP_AGE_RECIPIENTS in .env.production.
  3. Give each bank its job-signing key fingerprint (job-signing-keys/FINGERPRINTS.txt) out-of-band;
     connectors pin it at init (--job-key-fingerprint). Prefer one key per bank: --job-key <tenantId>.
TXT
