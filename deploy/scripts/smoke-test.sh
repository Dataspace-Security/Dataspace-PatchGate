#!/usr/bin/env bash
# Post-deploy smoke test.
#   ./scripts/smoke-test.sh https://patchgate.example.com            # public checks
#   CA_FILE=tls/ca.pem ./scripts/smoke-test.sh https://...            # private CA
#   INTERNAL=1 ./scripts/smoke-test.sh https://...                    # + checks inside the compose network
#   WSUS_ENABLED=1 / REPO_ENABLED=1                                   # legacy routes deliberately opened
# /api/ready is answered at the edge only for allowlists/health.conf sources (404 elsewhere); from other
# sources run with INTERNAL=1 (readiness is then read from web-1 directly).
# Exit code = number of failed checks (0 = all good).
set -uo pipefail

BASE="${1:?usage: smoke-test.sh https://host}"
BASE="${BASE%/}"
HOST="$(printf '%s' "$BASE" | sed -E 's#^https?://([^/:]+).*#\1#')"
PORT="$(printf '%s' "$BASE" | sed -nE 's#^https://[^/:]+:([0-9]+).*#\1#p')"; PORT="${PORT:-443}"
CURL=(curl -sS --max-time 20)
[ -n "${CA_FILE:-}" ] && CURL+=(--cacert "$CA_FILE")
fails=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "PatchGate smoke test: $BASE"

# --- TLS
echo "TLS"
check "certificate valid for $HOST (curl verifies chain + name)" "${CURL[*]} -o /dev/null https://$HOST:$PORT/api/health"
if command -v openssl >/dev/null; then
  enddate="$(echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
  if [ -n "$enddate" ]; then
    days=$(( ($(date -d "$enddate" +%s) - $(date +%s)) / 86400 ))
    check "certificate expires in > 21 days ($days days)" "[ $days -gt 21 ]"
  else
    fail "could not read certificate expiry"
  fi
  check "TLS 1.1 refused" "! echo | openssl s_client -connect $HOST:$PORT -servername $HOST -tls1_1 >/dev/null 2>&1"
  check "TLS 1.2 accepted" "echo | openssl s_client -connect $HOST:$PORT -servername $HOST -tls1_2 >/dev/null 2>&1"
fi
HTTP_URL="${HTTP_URL:-http://$HOST/}"   # override when port 80 is remapped (HTTP_PORT)
code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$HTTP_URL" || true)"; code="${code:0:3}"; code="${code:-000}"
check "http:// redirects to https (got $code)" "[ '$code' = 308 ] || [ '$code' = 301 ]"

# --- liveness / readiness
echo "Health"
code="$("${CURL[@]}" -o "$TMP/health" -w '%{http_code}' "$BASE/api/health" || true)"; code="${code:0:3}"; code="${code:-000}"
check "/api/health 200 (got $code)" "[ '$code' = 200 ] && grep -q '\"ok\"' '$TMP/health'"
DC=(docker compose -f docker-compose.prod.yml --env-file .env.production)
code="$("${CURL[@]}" -o "$TMP/ready" -w '%{http_code}' "$BASE/api/ready" || true)"; code="${code:0:3}"; code="${code:-000}"
if [ "$code" = 404 ]; then
  pass "/api/ready restricted at the edge for this source (404; allowlists/health.conf)"
  if [ "${INTERNAL:-0}" = "1" ]; then
    "${DC[@]}" exec -T web-1 node -e "fetch('http://127.0.0.1:3000/api/ready').then(r=>r.text().then(t=>{process.stdout.write(t);process.exit(r.ok?0:1)}),()=>process.exit(1))" > "$TMP/ready" 2>/dev/null
    code=$?; [ "$code" = 0 ] && code=200 || code=503
  else
    printf '  HINT  this source cannot read /api/ready: re-run with INTERNAL=1 (or from a health.conf address) — the readiness checks below will fail until then\n'
  fi
fi
check "/api/ready 200 (got $code)" "[ '$code' = 200 ]"
for c in database migrations repository; do
  check "ready.checks.$c = true" "grep -q '\"$c\":true' '$TMP/ready'"
done
check "ready.checks.auditChain = true" "grep -q '\"auditChain\":true' '$TMP/ready'"
check "ready.checks.siemExport != false" "! grep -q '\"siemExport\":false' '$TMP/ready'"

# --- security headers (set by the app, passed through by nginx; HSTS by nginx)
echo "Security headers"
"${CURL[@]}" -o /dev/null -D "$TMP/h" "$BASE/login" || true
hdr() { grep -i "^$1:" "$TMP/h" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ //'; }
check "Strict-Transport-Security max-age >= 1 year" "hdr strict-transport-security | grep -Eq 'max-age=(3153[6-9][0-9]{3}|[4-9][0-9]{7,}|[0-9]{9,})'"
check "Content-Security-Policy has frame-ancestors 'none'" "hdr content-security-policy | grep -q \"frame-ancestors 'none'\""
check "Content-Security-Policy has object-src 'none'" "hdr content-security-policy | grep -q \"object-src 'none'\""
check "X-Content-Type-Options nosniff" "hdr x-content-type-options | grep -qi nosniff"
check "X-Frame-Options DENY" "hdr x-frame-options | grep -qi deny"
check "Referrer-Policy present" "[ -n \"\$(hdr referrer-policy)\" ]"
check "no Server version / X-Powered-By" "! grep -Eiq '^(x-powered-by:|server: .*[0-9])' '$TMP/h'"

# --- access control
echo "Access control"
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/worker/tick" || true)"; code="${code:0:3}"; code="${code:-000}"
check "/api/worker/tick without token rejected at edge (got $code)" "[ '$code' = 404 ] || [ '$code' = 401 ] || [ '$code' = 403 ]"
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST -H 'x-worker-token: wrong-token-wrong-token-wrong-token' "$BASE/api/worker/fetch" || true)"; code="${code:0:3}"; code="${code:-000}"
check "/api/worker/fetch with bad token rejected (got $code)" "[ '$code' = 404 ] || [ '$code' = 401 ] || [ '$code' = 403 ]"
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/api/dev-login" || true)"; code="${code:0:3}"; code="${code:-000}"
check "/api/dev-login not reachable (got $code)" "[ '$code' = 404 ]"
if [ "${REPO_ENABLED:-0}" != "1" ]; then
  code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/repo/" || true)"; code="${code:0:3}"; code="${code:-000}"
  check "/repo/ not served at the edge (got $code)" "[ '$code' = 404 ]"
fi
if [ "${WSUS_ENABLED:-0}" != "1" ]; then
  code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/api/wsus/catalog" || true)"; code="${code:0:3}"; code="${code:-000}"
  check "/api/wsus/* blocked at the edge (got $code)" "[ '$code' = 404 ]"
fi

# --- UI
echo "UI"
code="$("${CURL[@]}" -o "$TMP/login" -w '%{http_code}' "$BASE/login" || true)"; code="${code:0:3}"; code="${code:-000}"
check "login page loads (got $code)" "[ '$code' = 200 ] && grep -qi '<html' '$TMP/login'"
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/" || true)"; code="${code:0:3}"; code="${code:-000}"
check "/ without session redirects or 200 (got $code)" "[ '$code' = 200 ] || [ '$code' = 307 ] || [ '$code' = 302 ] || [ '$code' = 303 ]"

# --- inside the stack (run on the server, from deploy/)
if [ "${INTERNAL:-0}" = "1" ]; then
  echo "Internal"
  for svc in web-1 web-2 fetcher; do
    code="$("${DC[@]}" exec -T scheduler curl -s -o /dev/null -w '%{http_code}' -X POST "http://$svc:3000/api/worker/tick" 2>/dev/null || true)"; code="${code:0:3}"; code="${code:-000}"
    check "$svc /api/worker/tick without token → 401 (got $code)" "[ '$code' = 401 ]"
  done
  check "web-1 has no direct internet egress (host firewall, RUNBOOK §4.3)" "! ${DC[*]} exec -T web-1 node -e \"fetch('https://github.com',{signal:AbortSignal.timeout(5000)}).then(()=>process.exit(0),()=>process.exit(1))\" 2>/dev/null"
  check "fetcher cannot bypass the proxy (host firewall, RUNBOOK §4.3)" "! ${DC[*]} exec -T -e NODE_USE_ENV_PROXY=0 fetcher node -e \"fetch('https://api.github.com',{signal:AbortSignal.timeout(5000)}).then(()=>process.exit(0),()=>process.exit(1))\" 2>/dev/null"
  check "fetcher reaches allow-listed vendor via proxy" "${DC[*]} exec -T fetcher node -e \"fetch('https://api.github.com',{signal:AbortSignal.timeout(10000)}).then(()=>process.exit(0),()=>process.exit(1))\" 2>/dev/null"
  check "fetcher cannot reach a non-allow-listed host" "! ${DC[*]} exec -T fetcher node -e \"fetch('https://example.com',{signal:AbortSignal.timeout(10000)}).then(()=>process.exit(0),()=>process.exit(1))\" 2>/dev/null"
  check "osslsigncode present in image" "${DC[*]} exec -T web-1 osslsigncode --version >/dev/null 2>&1"
  # Key isolation (SECURITY.md §5): only the signer holds job-signing keys; the fetcher holds no signing material.
  probe() { "${DC[@]}" exec -T "$1" node -e "fetch('$2',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))" >/dev/null 2>&1; }
  check "web-1 reaches the signer" "probe web-1 http://signer:8080/healthz"
  check "fetcher cannot reach the signer" "! probe fetcher http://signer:8080/healthz"
  check "fetcher cannot reach web-1" "! probe fetcher http://web-1:3000/api/health"
  check "fetcher has no signing token / AUTH_ENC_KEY / job key mounted" "! ${DC[*]} exec -T fetcher sh -c 'ls /run/secrets' 2>/dev/null | grep -Eq 'job_sign|auth_enc_key|tactical_api_key|wsus_token'"
  check "web-1 has no job-signing private key mounted" "! ${DC[*]} exec -T web-1 sh -c 'ls /run/secrets' 2>/dev/null | grep -q 'job_signing_key'"
  check "signer has no internet egress" "! ${DC[*]} exec -T signer node -e \"fetch('https://github.com',{signal:AbortSignal.timeout(5000)}).then(()=>process.exit(0),()=>process.exit(1))\" 2>/dev/null"
  check "DB: all network clients use TLS" "[ \"\$(${DC[*]} exec -T -u postgres db psql -XAtc \"SELECT coalesce(bool_and(s.ssl),true) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.client_addr IS NOT NULL\" 2>/dev/null | tr -d '[:space:]')\" = t ]"
fi

echo
if [ "$fails" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "$fails CHECK(S) FAILED"; fi
exit "$fails"
