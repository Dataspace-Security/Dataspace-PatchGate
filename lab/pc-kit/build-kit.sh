#!/usr/bin/env bash
# Build the "spare PC" kit: a self-contained folder that turns a spare physical Windows 10/11 PC on the same
# LAN into the offline Bank A PC (for hosts where Windows Sandbox / VirtualBox cannot be used).
#
#   bash lab/pc-kit/build-kit.sh [agent-version=2.10.0] [--no-fixtures]
#
# Output: lab/pc-kit/generated/PatchGateBankPC/   (gitignored: contains a 24 h Tactical install token)
#   Start-BankPC.ps1  Undo-BankPC.ps1  README.txt  KIT-INFO.txt
#   config/  bootstrap.ps1 ca.crt lab.json fixtures.json fixtures/*   (same files the Sandbox gets)
#   out/     results come back here (Start-BankPC.ps1 copies C:\PatchGateLab\out)
# Copy the whole folder to a USB stick; the user follows README.txt. Rebuild for every new PC or after 24 h.
set -euo pipefail

AGENT_VER="2.10.0"
FIXTURES=1
for a in "$@"; do
  case "$a" in
    --no-fixtures) FIXTURES=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    -*) echo "unknown option $a" >&2; exit 2 ;;
    *) AGENT_VER="$a" ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=bank-pc-common.sh
. "$HERE/bank-pc-common.sh"
KIT="$HERE/generated/PatchGateBankPC"
SB_CFG="$SANDBOX_DIR/generated/config"   # stage-fixtures.mjs writes the fixtures here (shared with the Sandbox)

bankpc_init "$AGENT_VER" || exit 1
bankpc_mint_token || exit 1

# Fresh kit every time (the old token must not linger); keep nothing from a previous build except fixtures.
mkdir -p "$KIT/config" "$KIT/out"
find "$KIT" -mindepth 1 -maxdepth 1 ! -name config -exec rm -rf {} +
find "$KIT/config" -mindepth 1 -maxdepth 1 ! -name fixtures -exec rm -rf {} +
mkdir -p "$KIT/out"
bankpc_write_config "$KIT/config"

if [ "$FIXTURES" = 1 ]; then
  [ -f "$SB_CFG/fixtures.json" ] || node "$(cygpath -m "$SANDBOX_DIR/stage-fixtures.mjs")"
  mkdir -p "$KIT/config/fixtures"
  cp "$SB_CFG/fixtures.json" "$KIT/config/fixtures.json"
  # Copy only what changed (the installers are ~650 MB); drop installers no longer listed.
  names="$(node -e 'for (const f of require(process.argv[1])) console.log(f.name)' "$(cygpath -m "$SB_CFG/fixtures.json")" | tr -d '\r')"
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    src="$SB_CFG/fixtures/$n"; dst="$KIT/config/fixtures/$n"
    [ -f "$src" ] || { echo "fixture missing: $src (re-run node lab/sandbox/stage-fixtures.mjs)"; exit 1; }
    if [ ! -f "$dst" ] || [ "$(stat -c %s "$src")" != "$(stat -c %s "$dst")" ]; then cp "$src" "$dst"; fi
  done <<< "$names"
  for f in "$KIT/config/fixtures"/*; do
    [ -e "$f" ] || continue
    grep -qxF "$(basename "$f")" <<< "$names" || rm -f "$f"
  done
  # The PC re-checks every hash; check here too so a bad copy is caught before the USB stick leaves.
  node -e '
const fs = require("fs"), crypto = require("crypto"), path = require("path");
const [list, dir] = process.argv.slice(1);
let bad = 0;
for (const f of JSON.parse(fs.readFileSync(list, "utf8"))) {
  const h = crypto.createHash("sha256").update(fs.readFileSync(path.join(dir, f.name))).digest("hex");
  if (h !== f.sha256) { console.error("hash mismatch: " + f.name); bad++; }
}
process.exit(bad ? 1 : 0);
' "$(cygpath -m "$KIT/config/fixtures.json")" "$(cygpath -m "$KIT/config/fixtures")"
else
  rm -rf "$KIT/config/fixtures" "$KIT/config/fixtures.json"
fi

cp "$HERE/Start-BankPC.ps1" "$HERE/Undo-BankPC.ps1" "$KIT/"
sed 's/\r*$/\r/' "$HERE/README.txt" > "$KIT/README.txt"   # CRLF for Notepad

EXPIRES="$(bankpc_token_expiry)"
nfix=0; [ -f "$KIT/config/fixtures.json" ] && nfix="$(node -e 'console.log(require(process.argv[1]).length)' "$(cygpath -m "$KIT/config/fixtures.json")")"
{
  echo "PatchGate lab - spare PC kit"
  echo "built:          $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "lab host:       $HOST_IP  (names: api/rmm/mesh/pg-cache.$DOMAIN)"
  echo "agent:          $AGENT_VER from the Bank A connector cache, sha256 $AGENT_SHA"
  echo "install token:  valid until $EXPIRES  (rebuild the kit after that)"
  echo "outdated apps:  $nfix"
} | sed 's/$/\r/' > "$KIT/KIT-INFO.txt"

# PowerShell syntax check of everything the PC will run (no execution).
if command -v powershell.exe >/dev/null; then
  for f in "$KIT/Start-BankPC.ps1" "$KIT/Undo-BankPC.ps1" "$KIT/config/bootstrap.ps1"; do
    powershell.exe -NoProfile -Command "\$e=\$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$(cygpath -w "$f")',[ref]\$null,[ref]\$e); if (\$e.Count) { \$e | ForEach-Object { Write-Output \$_.ToString() }; exit 1 }" \
      || { echo "PowerShell parse errors in $f"; exit 1; }
  done
fi

echo "Kit ready: $(cygpath -w "$KIT")"
echo "  size $(du -sh "$KIT" | cut -f1); agent ${AGENT_VER} (sha256 ${AGENT_SHA}); $nfix outdated apps"
echo "  Tactical install token valid until $EXPIRES"
echo "  Copy the WHOLE PatchGateBankPC folder to a USB stick; the user follows README.txt."
