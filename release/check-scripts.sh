#!/usr/bin/env bash
# Static checks of every shipped / CI script (used by release.sh and .github/workflows/ci.yml):
#   1. PowerShell: real parser (pwsh, Windows PowerShell, or the PowerShell container) — no execution
#   2. bash: shellcheck (local binary or the koalaman/shellcheck container); fails at SHELLCHECK_FAIL_ON
#      (default "error"; warnings are listed but do not fail — set SHELLCHECK_FAIL_ON=warning to tighten)
#   3. bash -n on every script (syntax), so a missing shellcheck still catches the worst
# Exit 0 = all good.
set -euo pipefail
# shellcheck source=release/lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
cd "$RELEASE_ROOT"
FAIL_ON="${SHELLCHECK_FAIL_ON:-error}"
rc=0

mapfile -t PS < <(list_scripts ps1)
mapfile -t SH < <(list_scripts sh)

step "PowerShell parse check (${#PS[@]} scripts)"
if [ "${#PS[@]}" -gt 0 ]; then
  if command -v pwsh >/dev/null 2>&1; then
    pwsh -NoProfile -NonInteractive -File release/lib/check-powershell.ps1 "${PS[@]}" || rc=1
  elif command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File release/lib/check-powershell.ps1 "${PS[@]}" || rc=1
  elif command -v docker >/dev/null 2>&1; then
    dk run --rm --network none -v "$(hostpath "$RELEASE_ROOT"):/src:ro" -w /src "$POWERSHELL_IMAGE" \
      pwsh -NoProfile -NonInteractive -File release/lib/check-powershell.ps1 "${PS[@]}" || rc=1
  else
    warn "no pwsh / powershell / docker: PowerShell parse check skipped"; rc=1
  fi
fi

step "bash syntax (bash -n, ${#SH[@]} scripts)"
n_bad=0
for f in "${SH[@]}"; do bash -n "$f" 2>/dev/null || { printf '    FAIL  %s\n' "$f"; bash -n "$f" || true; n_bad=$((n_bad + 1)); }; done
[ "$n_bad" -eq 0 ] && ok "all ${#SH[@]} parse" || rc=1

step "shellcheck (fail on: $FAIL_ON)"
sc() {
  if command -v shellcheck >/dev/null 2>&1; then shellcheck "$@"
  else dk run --rm --network none -v "$(hostpath "$RELEASE_ROOT"):/mnt:ro" -w /mnt "$SHELLCHECK_IMAGE" "$@"; fi
}
if sc -f gcc -S "$FAIL_ON" "${SH[@]}"; then
  ok "no findings at severity $FAIL_ON or above"
else
  rc=1
fi
if [ "$FAIL_ON" != warning ] && [ "$FAIL_ON" != info ] && [ "$FAIL_ON" != style ]; then
  warnings="$(sc -f gcc -S warning "${SH[@]}" 2>/dev/null || true)"
  if [ -n "$warnings" ]; then
    info "warnings (not failing; owners please fix):"
    printf '%s\n' "$warnings" | sed 's/^/      /'
  fi
fi

[ "$rc" -eq 0 ] && printf '\nScript checks PASSED\n' || printf '\nScript checks FAILED\n' >&2
exit "$rc"
