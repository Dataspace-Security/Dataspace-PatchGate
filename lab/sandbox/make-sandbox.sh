#!/usr/bin/env bash
# Generate the Windows Sandbox "Bank A PC" for the hosted lab.
# Usage: lab/sandbox/make-sandbox.sh [initial-agent-version=2.10.0]
# Output: lab/sandbox/generated/PatchGateLab.wsb  (double-click to start the sandbox)
#
# The PC behaves like a real bank PC in the hosted architecture: it can reach ONLY its site's Tactical
# (api/rmm/mesh on :443) and the site connector's package cache (pg-cache on :8443) — never PatchGate,
# never the internet. Its Tactical agent comes from the CONNECTOR CACHE (SHA-256 checked) and enrols with
# a fresh 24 h Tactical install token. Old third-party apps are pre-installed (stage-fixtures.mjs).
set -euo pipefail

AGENT_VER="${1:-2.10.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
GEN="$HERE/generated"
# Shared with the spare-PC kit (lab/pc-kit/build-kit.sh): agent/cache checks, install token, lab.json.
# shellcheck source=../pc-kit/bank-pc-common.sh
. "$HERE/../pc-kit/bank-pc-common.sh"

bankpc_init "$AGENT_VER" || exit 1
bankpc_mint_token || exit 1   # fresh 24 h enrollment token (does NOT rotate the connector's Tactical API key)

mkdir -p "$GEN/config" "$GEN/out"
rm -f "$GEN/out/"* 2>/dev/null || true
bankpc_write_config "$GEN/config"                 # bootstrap.ps1 + ca.crt + lab.json
cp "$HERE/../vm/run-bank-pc.ps1" "$GEN/config/"   # VirtualBox variant of the bank PC (lab/vm)

[ -f "$GEN/config/fixtures.json" ] || node "$(cygpath -m "$HERE/stage-fixtures.mjs")"

WIN_GEN="$(cygpath -w "$GEN")"
cat > "$GEN/PatchGateLab.wsb" <<EOF
<Configuration>
  <Networking>Enable</Networking>
  <VGpu>Disable</VGpu>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>${WIN_GEN}\\config</HostFolder>
      <SandboxFolder>C:\\PatchGateLab\\config</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>${WIN_GEN}\\out</HostFolder>
      <SandboxFolder>C:\\PatchGateLab\\out</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\PatchGateLab\\config\\bootstrap.ps1</Command>
  </LogonCommand>
</Configuration>
EOF
echo "Sandbox ready: $GEN/PatchGateLab.wsb"
echo "  agent ${AGENT_VER} from the Bank A cache (sha256 ${AGENT_SHA}); Tactical install token valid until $(bankpc_token_expiry)"
echo "  fixtures: $(node -e 'console.log(require(process.argv[1]).length)' "$(cygpath -m "$GEN/config/fixtures.json")") outdated apps"
