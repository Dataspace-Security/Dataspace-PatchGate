# Shared by lab/sandbox/make-sandbox.sh (Windows Sandbox) and lab/pc-kit/build-kit.sh (spare physical PC).
# Source it, then call in order:
#   bankpc_init <agent-version>       checks the agent is staged AND in the Bank A connector cache; sets AGENT_*
#   bankpc_mint_token                 fresh 24 h Tactical install token (does NOT rotate the connector API key)
#   bankpc_write_config <config-dir>  bootstrap.ps1 + ca.crt + lab.json (what bootstrap.ps1 reads)
#   bankpc_token_expiry               prints the token expiry (ISO 8601)
# Environment: LAB_DOMAIN (patchgate-lab.internal), LAB_HOST_IP (192.168.1.33).
# shellcheck shell=bash

BANKPC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "$BANKPC_LIB_DIR/.." && pwd)"
SANDBOX_DIR="$LAB/sandbox"
DOMAIN="${LAB_DOMAIN:-patchgate-lab.internal}"
HOST_IP="${LAB_HOST_IP:-192.168.1.33}"
CA="$LAB/certs/out/ca.crt"
CACHE="https://pg-cache.${DOMAIN}:8443/repo"

bankpc_init() { # agent-version
  AGENT_VER="$1"
  ASSET="tacticalagent-v${AGENT_VER}-windows-amd64.exe"
  REPO_PATH="tactical/agent/${AGENT_VER}/${ASSET}"
  local file="$LAB/patchgate/repo-data/${REPO_PATH}" code
  [ -f "$CA" ] || { echo "lab CA missing ($CA): bash lab/certs/make-certs.sh ${DOMAIN}"; return 1; }
  [ -f "$file" ] || { echo "agent ${AGENT_VER} is not staged ($file): bash lab/fixtures/stage-old-agent.sh ${AGENT_VER}"; return 1; }
  AGENT_SHA="$(sha256sum "$file" | cut -d' ' -f1)"

  # The installer must already be in Bank A's site cache (that is where the PC gets it from).
  code="$(curl -s -o /dev/null -w '%{http_code}' -I --ssl-no-revoke --cacert "$CA" --resolve "pg-cache.${DOMAIN}:8443:127.0.0.1" "$CACHE/$REPO_PATH" || true)"
  if [ "$code" != "200" ]; then
    echo "agent ${AGENT_VER} is not in the Bank A connector cache (HTTP $code). Run:"
    echo "  bash lab/connector/cache.sh --stage-agent ${AGENT_VER} agent:${AGENT_VER}:amd64   # then wait ~1 min"
    return 1
  fi
}

bankpc_mint_token() {
  local line
  MSYS_NO_PATHCONV=1 docker cp "$(cygpath -w "$LAB/tactical/install-token.py")" trmm-backend:/tmp/install-token.py
  line="$(MSYS_NO_PATHCONV=1 docker exec -w /opt/tactical/api trmm-backend sh -c 'python manage.py shell < /tmp/install-token.py' 2>&1 | grep '^PATCHGATE_INSTALL_TOKEN=' | tail -1)"
  [ -n "$line" ] || { echo "could not create a Tactical install token"; return 1; }
  TOKEN_JSON="${line#PATCHGATE_INSTALL_TOKEN=}"
}

bankpc_token_expiry() { node -e 'console.log(JSON.parse(process.argv[1]).expiresAt)' "$TOKEN_JSON"; }

bankpc_write_config() { # config-dir
  local cfgdir="$1"
  mkdir -p "$cfgdir"
  cp "$SANDBOX_DIR/bootstrap.ps1" "$cfgdir/"
  cp "$CA" "$cfgdir/ca.crt"
  node -e '
const [tok, domain, ip, ver, cache, repoPath, sha, out] = process.argv.slice(1);
const t = JSON.parse(tok);
const cfg = {
  hostIp: ip,
  // Bank PC name resolution: its site Tactical + its site cache. PatchGate is deliberately NOT here.
  hostNames: ["api", "rmm", "mesh", "pg-cache"].map((h) => `${h}.${domain}`),
  allowedPorts: ["443", "8443"],
  tacticalHealthUrl: `https://api.${domain}/core/version/`,
  cacheHealthUrl: `https://pg-cache.${domain}:8443/healthz`,
  // Must be UNREACHABLE from a bank PC (by name and by IP): proves PCs never talk to our server.
  patchgateUrls: [`https://patchgate.${domain}:3443/api/health`, `https://${ip}:3443/api/health`],
  tacticalApiUrl: `https://api.${domain}`,
  agentUrl: `${cache}/${repoPath}`,
  agentSha256: sha,
  agentVersion: ver,
  clientId: t.clientId,
  siteId: t.siteId,
  installToken: t.installToken,
  installTokenExpiresAt: t.expiresAt,
};
require("fs").writeFileSync(out, JSON.stringify(cfg, null, 2));
' "$TOKEN_JSON" "$DOMAIN" "$HOST_IP" "$AGENT_VER" "$CACHE" "$REPO_PATH" "$AGENT_SHA" "$(cygpath -m "$cfgdir/lab.json")"
}
