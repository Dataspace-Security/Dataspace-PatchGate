# shellcheck shell=bash
# Shared environment for the lab PatchGate ("our server") — sourced by start.sh, users.sh and lab helpers.
#   LAB_MODE=hosted (default): https://patchgate.<domain>:3443, AUTH_MODE=local (password + TOTP),
#                              signed connector jobs (JOB_SIGNING_KEY_FILE), NO route to any bank Tactical.
#   LAB_MODE=dev             : the old single-bank dev setup (dev user switcher, direct Tactical link,
#                              http://localhost:3000, or https :3443 with LAB_HTTPS=1).
# Secrets are generated once into lab/patchgate/secrets.env + lab/patchgate/secrets/ (gitignored).

LAB_MODE="${LAB_MODE:-hosted}"
DOMAIN="${LAB_DOMAIN:-patchgate-lab.internal}"
PG_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_APP="$(cd "$PG_HERE/../../patchgate-web" && pwd)"
PG_CERTS="$(cd "$PG_HERE/../certs/out" && pwd)"
PG_PROV="$PG_HERE/../tactical/provision.json"
PG_URL="https://patchgate.${DOMAIN}:3443"
[ "$LAB_MODE" = "dev" ] && [ "${LAB_HTTPS:-0}" != "1" ] && PG_URL="http://localhost:3000"
export LAB_MODE DOMAIN PG_HERE PG_APP PG_CERTS PG_URL

DB_URL="postgresql://patchgate:patchgate-dev-only@127.0.0.1:55432/patchgate_lab?schema=public"

# ---- secrets (generated once) ----
SECRETS="$PG_HERE/secrets.env"
[ -f "$SECRETS" ] || : > "$SECRETS"
for k in AUDIT_HMAC_KEY WORKER_TOKEN WSUS_TOKEN AUTH_ENC_KEY; do
  grep -q "^$k=" "$SECRETS" || echo "$k=$(openssl rand -hex 32)" >> "$SECRETS"
done
mkdir -p "$PG_HERE/secrets"
JOB_KEY="$PG_HERE/secrets/job-signing-key.pem"
if [ ! -f "$JOB_KEY" ]; then
  openssl genpkey -algorithm ed25519 -out "$JOB_KEY" 2>/dev/null
  chmod 600 "$JOB_KEY" 2>/dev/null || true
fi
set -a; . "$SECRETS"; set +a

export DATABASE_URL="$DB_URL"
export REPO_DIR="$(cygpath -m "$PG_HERE/repo-data")"
export QUARANTINE_HOURS=0                     # lab: no 48 h wait
export NODE_EXTRA_CA_CERTS="$(cygpath -m "$PG_CERTS/ca.crt")" # lab CA (bank PKI stand-in)

json() { node -e "console.log(require(process.argv[1])[process.argv[2]])" "$PG_PROV" "$1"; }

if [ "$LAB_MODE" = "hosted" ]; then
  # Our server never reaches into a bank: every bank site is served by its connector (outbound from the
  # bank). env.ts still REQUIRES the legacy direct-Tactical variables, so they point at a name that can
  # never resolve (RFC 2606 .invalid) — any accidental direct call fails fast instead of reaching Tactical.
  export TACTICAL_API_URL="https://tactical-direct-link-disabled.invalid"
  export TACTICAL_API_KEY="hosted-lab-no-direct-tactical-link"
  unset TACTICAL_INSTALL_SCRIPT_ID
  export PATCH_REPO_URL="${PG_URL}/repo"     # legacy path only; PCs use their site's connector cache
  export AUTH_MODE=local
  export JOB_SIGNING_KEY_FILE="$(cygpath -m "$JOB_KEY")"
  export PUBLIC_BASE_URL="$PG_URL"
  # The bank SIEM receives the bank's audit chain through the CONNECTOR relay (not from our server).
  unset SIEM_SYSLOG_URL SIEM_CA_FILE SIEM_HOSTNAME DEV_USER_UPN
else
  [ -f "$PG_PROV" ] || { echo "run lab/tactical/provision.sh first"; return 1 2>/dev/null || exit 1; }
  export TACTICAL_API_URL="https://api.${DOMAIN}"
  export TACTICAL_API_KEY="$(json apiKey)"
  export TACTICAL_INSTALL_SCRIPT_ID="$(json installScriptId)"
  export PATCH_REPO_URL="${PG_URL}/repo"
  export SIEM_SYSLOG_URL="tls://siem.${DOMAIN}:6514"
  export SIEM_CA_FILE="$PG_CERTS/ca.crt"
  export SIEM_HOSTNAME="patchgate-lab"
  export AUTH_MODE=dev
  export DEV_USER_UPN="admin@dev.local"         # development login (switch at /dev-login)
fi
