#!/usr/bin/env bash
# Create the lab's local PatchGate accounts with the app's own CLI (scripts/admin/create-user.ts):
#   platform:  lab-admin@patchgate.lab (ADMIN = maker), lab-auditor@patchgate.lab (AUDITOR = read-only)
#   bank-a:    admin@bank-a.lab (ADMIN), approver@bank-a.lab (a SECOND bank ADMIN = checker, so maker ≠ checker
#              works inside the bank), viewer@bank-a.lab (AUDITOR = read-only; historic UPN kept)
# Two roles everywhere (patchgate-web/src/lib/auth/roles.ts). Existing accounts keep their UPN; their roles were
# mapped by migration 20261016140100_role_scope (lab-operator@patchgate.lab became an AUDITOR and is not used).
# Bank users are created only once the bank exists (lab/connector/enroll.sh creates it, then re-runs this).
# Passwords are random and stored in lab/patchgate/lab-users.json (gitignored, mode 0600). With AUTH_MFA=off (lab
# default, env.sh) sign-in is password only; with AUTH_MFA=required TOTP is enrolled at first sign-in (pg-api.mjs
# records the secret there as well). Safe to re-run: also re-syncs the recorded roles with the database.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/env.sh"
USERS="$HERE/lab-users.json"
[ -f "$USERS" ] || echo '{"users":{}}' > "$USERS"
chmod 600 "$USERS" 2>/dev/null || true

bank_exists() {
  docker exec patchgate-dev-db psql -U patchgate -d patchgate_lab -tAc "select 1 from \"Tenant\" where slug='$1'" | grep -q 1
}
user_exists() {
  docker exec patchgate-dev-db psql -U patchgate -d patchgate_lab -tAc "select 1 from \"User\" where upn='$1'" | grep -q 1
}

create() { # upn name role [tenant-slug]
  local upn="$1" name="$2" role="$3" tenant="${4:-}"
  if user_exists "$upn"; then echo "  exists  $upn"; return; fi
  local pw; pw="Lab-$(openssl rand -hex 12)-Pg"
  local args=(--upn "$upn" --name "$name" --role "$role"); [ -n "$tenant" ] && args+=(--tenant "$tenant")
  (cd "$PG_APP" && printf '%s\n%s\n' "$pw" "$pw" | NODE_ENV=development npx tsx scripts/admin/create-user.ts "${args[@]}" >/dev/null)
  node -e '
    const fs = require("fs"); const [f, upn, pw, role, tenant] = process.argv.slice(1);
    const j = JSON.parse(fs.readFileSync(f, "utf8"));
    j.users[upn] = { password: pw, role, tenant: tenant || null };
    fs.writeFileSync(f, JSON.stringify(j, null, 2));' "$USERS" "$upn" "$pw" "$role" "$tenant"
  echo "  created $upn ($role${tenant:+, bank $tenant})"
}

echo "lab users (credentials: $USERS):"
create lab-admin@patchgate.lab "Lab Platform Admin" ADMIN
create lab-auditor@patchgate.lab "Lab Platform Auditor" AUDITOR
if bank_exists bank-a; then
  create admin@bank-a.lab "Bank A Admin" ADMIN bank-a
  create approver@bank-a.lab "Bank A Admin 2 (checker)" ADMIN bank-a
  create viewer@bank-a.lab "Bank A Auditor" AUDITOR bank-a
else
  echo "  (bank-a not created yet — bank users follow after lab/connector/enroll.sh)"
fi

# Record the CURRENT database role of every listed account (roles change with migrations / admin edits).
for upn in $(node -e 'console.log(Object.keys(require(process.argv[1]).users).join(" "))' "$USERS"); do
  role="$(docker exec patchgate-dev-db psql -U patchgate -d patchgate_lab -tAc "select role from \"User\" where upn='$upn'" | tr -d '[:space:]')"
  [ -n "$role" ] || continue
  node -e '
    const fs = require("fs"); const [f, upn, role] = process.argv.slice(1);
    const j = JSON.parse(fs.readFileSync(f, "utf8"));
    if (j.users[upn] && j.users[upn].role !== role) { j.users[upn].role = role; fs.writeFileSync(f, JSON.stringify(j, null, 2)); console.log(`  role    ${upn} -> ${role}`); }' "$USERS" "$upn" "$role"
done
