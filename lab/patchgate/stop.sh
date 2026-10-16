#!/usr/bin/env bash
# Stop the lab PatchGate processes on this Windows host.
#   bash lab/patchgate/stop.sh            → scheduler + PatchGate (`next dev` of patchgate-web)
#   bash lab/patchgate/stop.sh scheduler  → only the scheduler loop
#   bash lab/patchgate/stop.sh siem       → only the lab SIEM receiver
set -uo pipefail
what="${1:-all}"

kill_bash_loop() { # Git Bash processes running a given script
  local f pid
  for f in /proc/[0-9]*/cmdline; do
    pid="${f#/proc/}"; pid="${pid%/cmdline}"
    [ "$pid" = "$$" ] && continue
    if { tr '\0' ' ' < "$f"; } 2>/dev/null | grep -q "^bash .*$1"; then
      kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null; echo "stopped $1 (pid $pid)"
    fi
  done
}
kill_node() { # Windows node.exe processes whose command line matches a regex (+ their children)
  powershell -NoProfile -Command "
    \$ps = Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object { \$_.CommandLine -match '$1' }
    foreach (\$p in \$ps) { Stop-Process -Id \$p.ProcessId -Force -ErrorAction SilentlyContinue; Write-Output ('stopped node pid ' + \$p.ProcessId) }" | tr -d '\r'
}

if [ "$what" = all ] || [ "$what" = scheduler ]; then
  kill_bash_loop "lab/patchgate/scheduler.sh"
fi
if [ "$what" = all ]; then
  kill_bash_loop "lab/patchgate/start.sh"
  kill_node 'patchgate-web.*(next.dist.bin.next|start-server\.js|\.next.dev)|npx-cli\.js next dev'
fi
if [ "$what" = siem ]; then
  kill_node 'siem.receiver\.mjs'
fi
exit 0
