#!/usr/bin/env bash
# LAB FIXTURE: stage an OLDER Tactical agent in the PatchGate repo so the sandbox PC starts outdated
# and PatchGate has something real to upgrade. Verified against GitHub's published SHA-256 digest.
# Usage: lab/fixtures/stage-old-agent.sh 2.10.0
set -euo pipefail
VER="${1:?agent version, e.g. 2.10.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HERE/../patchgate/repo-data/tactical/agent/$VER"
mkdir -p "$DEST"
gh api "repos/amidaware/rmmagent/releases/tags/v$VER" --jq '.assets[] | select(.name|test("windows-(amd64|386)\\.exe$")) | "\(.name) \(.digest) \(.browser_download_url)"' |
while read -r name digest url; do
  expected="${digest#sha256:}"
  curl -sSL -o "$DEST/$name" "$url"
  got="$(sha256sum "$DEST/$name" | cut -d' ' -f1)"
  if [ "$got" != "$expected" ]; then rm -f "$DEST/$name"; echo "HASH MISMATCH $name"; exit 1; fi
  echo "staged $name sha256=$got (matches GitHub digest)"
done
