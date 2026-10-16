#!/usr/bin/env bash
# LAB: have the Bank A connector cache packages now (signed CACHE_PACKAGE jobs via PatchGate's own service).
#   bash lab/connector/cache.sh Mozilla.Firefox agent:2.10.0:amd64
#   bash lab/connector/cache.sh --stage-agent 2.10.0 agent:2.10.0:amd64     (Sandbox agent installer)
#   bash lab/connector/cache.sh --sync                                       (sync Tactical agents now)
# The connector picks the job up on its next poll (≤ 25 s); PatchGate applies the result on the next tick.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../patchgate/env.sh"
cd "$PG_APP"
NODE_ENV=development npx tsx "$(cygpath -m "$HERE/cache-package.ts")" "$@"
