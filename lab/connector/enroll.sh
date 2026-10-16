#!/usr/bin/env bash
# Onboard "Bank A" on the lab PatchGate through its REAL admin API (signed in as the lab platform admin
# with password + TOTP), then enrol the Bank A connector with a one-time code:
#   1. bank "bank-a" (POST /api/admin/tenants) + its users (lab/patchgate/users.sh → create-user.ts)
#   2. Bank A opts in to every verified third-party app (POST /api/apps/{id}/enable, bank selected)
#   3. one-time enrolment code for site "Bank A HQ" (POST /api/connector/admin/enrollments)
#   4. `patchgate-connector init` in the connector container (key generated INSIDE the bank, code via env)
# Usage: bash lab/connector/enroll.sh [--force]   (--force re-enrols with a new key)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$(cd "$HERE/.." && pwd)"
. "$LAB/patchgate/env.sh"
export PG_URL
ADMIN="lab-admin@patchgate.lab"
SITE="Bank A HQ"
FORCE="${1:-}"
api() { MSYS_NO_PATHCONV=1 node "$(cygpath -m "$LAB/patchgate/pg-api.mjs")" "$ADMIN" "$@"; }
jget() { node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>{const v=new Function("j","return "+process.argv[1])(JSON.parse(s));console.log(v??"")})' "$1"; }
psql_q() { docker exec patchgate-dev-db psql -q -U patchgate -d patchgate_lab -tAc "$1"; }

echo "== 1. bank-a"
TENANT="$(api GET /api/admin/tenants | jget '(j.data.items??j.data).find(t=>t.slug==="bank-a")?.id')"
if [ -z "$TENANT" ]; then
  TENANT="$(api POST /api/admin/tenants '{"slug":"bank-a","name":"Bank A","requireBankApproval":true}' | jget 'j.data.id')"
  echo "   created bank-a ($TENANT)"
else
  echo "   exists bank-a ($TENANT)"
fi
bash "$LAB/patchgate/users.sh" | sed 's/^/   /'
# LAB FIXTURE (app gap): onboarding a bank creates no rollout rings and nothing in the app can create them,
# but a change request needs a ring. Same rings as the dev seed; no maintenance window (deploy on approval).
docker exec -i patchgate-dev-db psql -q -U patchgate -d patchgate_lab >/dev/null <<SQL
SET app.scope = 'platform';
INSERT INTO "Ring" (id, name, "wsusGroup", "order", "tenantId") VALUES
  ('ring-bank-a-0', 'Ring0-Test',  'Ring0-Test',  0, '$TENANT'),
  ('ring-bank-a-1', 'Ring1-Pilot', 'Ring1-Pilot', 1, '$TENANT'),
  ('ring-bank-a-2', 'Ring2-Prod',  'Ring2-Prod',  2, '$TENANT')
ON CONFLICT DO NOTHING;
SQL
echo "   rings: $(psql_q "SET app.scope='platform'; select string_agg(name, ', ' order by \"order\") from \"Ring\" where \"tenantId\"='$TENANT'")"

echo "== 2. Bank A opts in to the verified apps"
api POST /api/tenant/select "{\"tenantId\":\"$TENANT\"}" >/dev/null
for app in $(psql_q "select distinct a.id from \"App\" a join \"AppVersion\" v on v.\"appId\"=a.id where v.verification='VERIFIED'"); do
  api POST "/api/apps/$app/enable" | jget '"   enabled " + j.data.appId'
done

echo "== 3+4. connector enrolment"
CFG="$HERE/bank-a/etc/connector.json"
if [ "$FORCE" != "--force" ] && node -e 'process.exit(require(process.argv[1]).identity?0:1)' "$CFG" 2>/dev/null; then
  echo "   already enrolled ($(node -e 'console.log(require(process.argv[1]).identity.connectorId)' "$CFG")) — use --force to re-enrol"
  exit 0
fi
CODE="$(api POST /api/connector/admin/enrollments "{\"tenantId\":\"$TENANT\",\"name\":\"$SITE\"}" | jget 'j.data.code')"
[ -n "$CODE" ] || { echo "could not create an enrolment code"; exit 1; }
echo "   one-time code created for \"$SITE\" (24 h, single use; not printed)"
# Out-of-band channel stand-in: our operator gives the bank the job-signing key FINGERPRINT (SHA-256 of
# the raw 32-byte Ed25519 public key); `init` refuses to pin any other key (e.g. one injected by a proxy).
FPR="$(node -e '
  const c = require("crypto"), fs = require("fs");
  const spki = c.createPublicKey(c.createPrivateKey(fs.readFileSync(process.argv[1]))).export({ format: "der", type: "spki" });
  console.log(c.createHash("sha256").update(spki.subarray(spki.length - 32)).digest("hex"));' "$JOB_SIGNING_KEY_FILE")"
echo "   job-signing key fingerprint (given to the bank out of band): $FPR"
cd "$HERE"
docker compose up -d bank-a-firewall >/dev/null
# `init` runs as a one-off container with the service's fixed IPs: the running service must step aside.
WAS_RUNNING="$(MSYS_NO_PATHCONV=1 docker inspect -f '{{.State.Running}}' bank-a-connector 2>/dev/null || echo false)"
[ "$WAS_RUNNING" = "true" ] && docker compose stop connector >/dev/null
trap '[ "$WAS_RUNNING" = "true" ] && (cd "$HERE" && docker compose up -d --force-recreate connector >/dev/null)' EXIT
PGC_ETC_MODE=rw PATCHGATE_ENROLL_CODE="$CODE" PATCHGATE_JOB_KEY_FINGERPRINT="$FPR" MSYS_NO_PATHCONV=1 \
  docker compose run --rm --no-deps -e PATCHGATE_ENROLL_CODE -e PATCHGATE_JOB_KEY_FINGERPRINT \
  connector init --server "$PG_URL" --ca /etc/patchgate-connector/patchgate-ca.pem $FORCE
node -e 'const c=require(process.argv[1]).identity;console.log(`   enrolled: connector ${c.connectorId}, bank ${c.tenantId}, "${c.name}"`)' "$CFG"
