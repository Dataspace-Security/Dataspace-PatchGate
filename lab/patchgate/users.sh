#!/usr/bin/env bash
# Create the lab's local PatchGate accounts with the app's own CLI (scripts/admin/create-user.ts):
#   platform:  lab-admin@patchgate.lab (ADMIN), lab-operator@patchgate.lab (OPERATOR = maker)
#   bank-a:    admin@bank-a.lab (ADMIN), approver@bank-a.lab (APPROVER = checker), viewer@bank-a.lab (VIEWER)
# Bank users are created only once the bank exists (lab/connector/enroll.sh creates it, then re-runs this).
# Passwords are random and stored in lab/patchgate/lab-users.json (gitignored, mode 0600). TOTP is enrolled
# at first sign-in (pg-api.mjs records the secret there as well). Safe to re-run.
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
create lab-operator@patchgate.lab "Lab Platform Operator" OPERATOR
if bank_exists bank-a; then
  create admin@bank-a.lab "Bank A Admin" ADMIN bank-a
  create approver@bank-a.lab "Bank A Approver" APPROVER bank-a
  create viewer@bank-a.lab "Bank A Viewer" VIEWER bank-a
else
  echo "  (bank-a not created yet — bank users follow after lab/connector/enroll.sh)"
fi
