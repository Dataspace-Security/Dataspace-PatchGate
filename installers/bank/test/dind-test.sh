#!/usr/bin/env bash
# TEST HARNESS ONLY (developers): run installers/bank/install.sh end to end inside ONE privileged Ubuntu 24.04
# Docker-in-Docker container acting as the bank server, with THIS working tree (unpushed changes included).
#
#   installers/bank/test/dind-test.sh [--logs DIR] [--keep] [--from-head] [-- <extra install.sh options>]
#     --from-head   committed HEAD + only installers/bank/ and installers/server/install-patchgate.sh from the tree
#   installers/bank/test/dind-test.sh --cleanup        remove ONLY the objects labelled com.patchgate.kit=bank-test
#
# Same DinD + cgroup v2 approach as kits/colleague-test (kit-boot.sh). Runs from Git Bash (Docker Desktop) or Linux.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
LABEL="com.patchgate.kit=bank-test"
NAME=pgbank-test; VOL=pgbank-test-docker; IMAGE=ubuntu:24.04
LOGS="${PG_BANK_TEST_LOGS:-$HOME/patchgate-bank-test-logs}"
KEEP=0; CLEANUP=0; FROM_HEAD=0; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --logs) LOGS="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --cleanup) CLEANUP=1; shift ;;
    --from-head) FROM_HEAD=1; shift ;;
    --) shift; EXTRA=("$@"); break ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
cleanup() {
  local id
  for id in $(docker ps -aq --filter "label=$LABEL"); do
    [ "$(docker inspect -f '{{index .Config.Labels "com.patchgate.kit"}}' "$id")" = bank-test ] || continue
    docker exec "$id" sh -c 'docker ps -q | xargs -r docker stop -t 10 >/dev/null 2>&1; pkill dockerd; sleep 5' >/dev/null 2>&1 || true
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
  for id in $(docker volume ls -q --filter "label=$LABEL"); do docker volume rm "$id" >/dev/null; done
  echo "removed every object labelled $LABEL"
}
if [ "$CLEANUP" = 1 ]; then cleanup; exit 0; fi

mkdir -p "$LOGS"; LOG="$LOGS/dind-test-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
echo "bank installer DinD test — $(date '+%F %T') — log $LOG"
T0=$(date +%s)
if ! docker inspect "$NAME" >/dev/null 2>&1; then
  docker volume inspect "$VOL" >/dev/null 2>&1 || docker volume create --label "$LABEL" "$VOL" >/dev/null
  docker create --name "$NAME" --hostname bank-srv --label "$LABEL" --privileged --init --cgroupns private \
    -v "$VOL:/var/lib/docker" "$IMAGE" bash /usr/local/sbin/kit-boot.sh >/dev/null
  docker cp "$(hostpath "$REPO/kits/colleague-test/lib/kit-boot.sh")" "$NAME:/usr/local/sbin/kit-boot.sh"
fi
docker start "$NAME" >/dev/null
echo "container $NAME up ($(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$NAME"))"
# The working tree (tracked + untracked, not ignored) -> /root/src: unpushed changes included, no .git.
docker exec "$NAME" sh -c 'rm -rf /root/src && mkdir -p /root/src'
if [ "$FROM_HEAD" = 1 ]; then
  # Committed HEAD + ONLY the bank installer's own files from the working tree (other unfinished work ignored).
  (cd "$REPO" && git archive HEAD) | docker exec -i "$NAME" tar -C /root/src -xf -
  (cd "$REPO" && tar -cf - installers/bank installers/server/install-patchgate.sh) | docker exec -i "$NAME" tar -C /root/src -xf -
  echo "source: HEAD $(cd "$REPO" && git rev-parse --short HEAD) + working-tree installers/bank, installers/server/install-patchgate.sh"
else
  (cd "$REPO" && git ls-files -co --exclude-standard -z | tar --null --ignore-failed-read -T - -cf - 2>/dev/null) \
    | docker exec -i "$NAME" tar -C /root/src -xf -
fi
echo "working tree copied ($(docker exec "$NAME" du -sh /root/src | cut -f1))"
rc=0
docker exec "$NAME" bash /root/src/installers/bank/install.sh --source-dir /root/src --domain bank.test \
  --bank-name "Test Bank" --auditor-email auditor@bank.test --non-interactive "${EXTRA[@]}" || rc=$?
echo "install.sh exit $rc after $(( ($(date +%s) - T0) / 60 )) min"
docker exec "$NAME" bash /root/src/installers/bank/install.sh --status || true
docker cp "$NAME:/var/log/patchgate-bank-install.log" "$(hostpath "$LOGS")/patchgate-bank-install.log" 2>/dev/null || true
docker cp "$NAME:/var/log/patchgate-install.log" "$(hostpath "$LOGS")/patchgate-install.log" 2>/dev/null || true
docker cp "$NAME:/var/log/patchgate-site-install.log" "$(hostpath "$LOGS")/patchgate-site-install.log" 2>/dev/null || true
[ "$KEEP" = 1 ] || cleanup
exit "$rc"
