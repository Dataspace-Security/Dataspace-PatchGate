#!/usr/bin/env bash
# PatchGate colleague test kit — ONLINE site bundle from a source checkout (TEST KIT ONLY, not product code).
#
#   lib/build-online-bundle.sh --repo <clone> --version <v> --connector-image patchgate-connector:<v> --out <dir>
#
# Same layout as installers/site/build-site-bundle.sh's "-online" variant (install-site.sh, bundle.env, SHA256SUMS,
# images/{IMAGES.lock,IMAGES.txt,local.tar}, tactical/, connector/, endpoint/, pc/, agent/), but without the inputs
# that only exist on the release machine (a ../tacticalrmm checkout, the lab's agent mirror, pulled Tactical images):
#   - Tactical's docker-compose.yml        github.com/amidaware/tacticalrmm tag v1.5.2   (SHA-256 pinned below)
#   - Tactical agent 2.11.0 (amd64, 386)    github.com/amidaware/rmmagent release v2.11.0 (SHA-256 pinned below)
#   - public image digests (IMAGES.lock)    pinned below = the digests of the reviewed 1.0.0-rc3 site bundle;
#                                           the site pulls exactly these from Docker Hub (--online)
#   - the connector image                   built from the checkout (patchgate-connector/), saved as local.tar
# Output: <out>/patchgate-site-<v>-online.tar.gz, <out>/SHA256SUMS (archive + install-site.sh), <out>/install-site.sh
set -euo pipefail

TACTICAL_VERSION="1.5.2"
TACTICAL_COMPOSE_URL="https://raw.githubusercontent.com/amidaware/tacticalrmm/v1.5.2/docker/docker-compose.yml"
TACTICAL_COMPOSE_SHA256="aa5be68186d155091e9ff7728d4f1b2bb89a31526e779c779f45c360b327846b"
AGENT_VERSION="2.11.0"
AGENT_URL="https://github.com/amidaware/rmmagent/releases/download/v2.11.0"
# shellcheck disable=SC2034 # read indirectly (${!v})
AGENT_SHA256_amd64="c685032015152dd6f91b5ec2036e2da240a190911b87b1f7fdeba1440070c37d"
# shellcheck disable=SC2034
AGENT_SHA256_386="cf154a0437653666bb0a7460f83fc502bea55f695274ec768e8f0fedcd5b075c"
LOCK_PINS=(
  "tacticalrmm/tactical:1.5.2 tacticalrmm/tactical@sha256:2abb72ae5799416082fcb6d7cb5edda0ac7f87a71fa8eabbab36ef004d603ee7"
  "tacticalrmm/tactical-nginx:1.5.2 tacticalrmm/tactical-nginx@sha256:65679e4ae7d92550277b98130857c0cf85bc4b2ab7fbfde5262f10c330ca96aa"
  "tacticalrmm/tactical-frontend:1.5.2 tacticalrmm/tactical-frontend@sha256:2d4253c5fd6d287f6f3e75587949ff1e322c91c9abea37e609277e48042ab59b"
  "tacticalrmm/tactical-nats:1.5.2 tacticalrmm/tactical-nats@sha256:4e7ebe47ca1159af55ac1c55cac7efa1c3f1d9ae2a953823a13e194a1a45c1ab"
  "tacticalrmm/tactical-meshcentral:1.5.2 tacticalrmm/tactical-meshcentral@sha256:41caa1c737472aa570bad50da12eff0fd5b71ab38d85a1665eed325df49a1d58"
  "mongo:4.4 mongo@sha256:4be76f674fc4b27859816811b8baa3c51830eb1dbf4ca81a51e26b79edd662ef"
  "postgres:13-alpine postgres@sha256:fb9065b6e3e213bdc07edd372a5b2a26245840b7fb65d1fd8b6700106d51805c"
  "redis:6.0-alpine redis@sha256:2b35fc7d2908e25aa6aa197f97882c8a67829d3b106ad5ea5c8028f816f26aa8"
)
SOCAT_PIN="alpine/socat@sha256:fb3862c949af7c79996d0e514ee96128644d840835ed5368eeecb14a869de361"

die() { printf 'ERROR %s\n' "$*" >&2; exit 1; }
REPO=""; VERSION=""; CONNECTOR_IMAGE=""; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --connector-image) CONNECTOR_IMAGE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[ -d "$REPO/installers/site" ] || die "--repo must be a PatchGate checkout"
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,40}$ ]] || die "invalid --version"
docker image inspect "$CONNECTOR_IMAGE" >/dev/null 2>&1 || die "connector image $CONNECTOR_IMAGE not built"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
NAME="patchgate-site-$VERSION"; STAGE="$OUT/$NAME"
rm -rf "$STAGE"; mkdir -p "$STAGE"/{images,tactical,connector,endpoint,pc,agent}
CACHE="$OUT/.cache"; mkdir -p "$CACHE"

fetch_pinned() { # url sha256 dest
  if [ ! -s "$3" ] || [ "$(sha256sum "$3" | cut -d' ' -f1)" != "$2" ]; then
    curl -fsSL --proto '=https' --retry 3 -o "$3.part" "$1" || die "download failed: $1"
    mv -f "$3.part" "$3"
  fi
  [ "$(sha256sum "$3" | cut -d' ' -f1)" = "$2" ] || { rm -f "$3"; die "SHA-256 mismatch for $1 (refusing it)"; }
}

echo "    Tactical compose v$TACTICAL_VERSION + agent $AGENT_VERSION (GitHub, SHA-256 pinned)"
fetch_pinned "$TACTICAL_COMPOSE_URL" "$TACTICAL_COMPOSE_SHA256" "$CACHE/docker-compose-$TACTICAL_VERSION.yml"
for arch in amd64 386; do
  f="tacticalagent-v$AGENT_VERSION-windows-$arch.exe"; v="AGENT_SHA256_$arch"
  fetch_pinned "$AGENT_URL/$f" "${!v}" "$CACHE/$f"
  cp "$CACHE/$f" "$STAGE/agent/$f"
done
(cd "$STAGE/agent" && sha256sum tacticalagent-v*.exe | sed 's/ \*/  /' > AGENT-SHA256SUMS)
cat > "$STAGE/agent/SOURCE.txt" <<TXT
Tactical RMM agent $AGENT_VERSION for Windows (amd64 + 386), TEST KIT bundle.
Source: github.com/amidaware/rmmagent release v$AGENT_VERSION, SHA-256 pinned in the test kit (same values as
PatchGate's verified mirror used for the 1.0.0-rc3 release bundle). Bundle $VERSION built $(date -u +%FT%TZ).
TXT

echo "    images: IMAGES.lock (pinned digests) + local.tar ($CONNECTOR_IMAGE, built from source)"
SOCAT_IMAGE="patchgate-site/socat:$VERSION"
{ printf '%s\n' "${LOCK_PINS[@]}"; printf '%s %s\n' "$SOCAT_IMAGE" "$SOCAT_PIN"; } > "$STAGE/images/IMAGES.lock"
{ for p in "${LOCK_PINS[@]}"; do t="${p%% *}"; case "$t" in tacticalrmm/tactical-meshcentral:*) ;; *) echo "$t" ;; esac; done
  echo "patchgate-site/tactical-meshcentral-offline:$TACTICAL_VERSION"; echo "$SOCAT_IMAGE"; echo "$CONNECTOR_IMAGE"; } > "$STAGE/images/IMAGES.txt"
docker save -o "$STAGE/images/local.tar" "$CONNECTOR_IMAGE"

H="$REPO/installers/site"
cp "$H/install-site.sh" "$STAGE/install-site.sh"
cp "$CACHE/docker-compose-$TACTICAL_VERSION.yml" "$STAGE/tactical/docker-compose.yml"
cp "$H/tactical/docker-compose.site.yml" "$H/tactical/provision-site.py" "$H/tactical/break-glass.py" "$H/tactical/tactical-watchdog.sh" "$STAGE/tactical/"
cp -r "$H/tactical/meshcentral-offline" "$STAGE/tactical/meshcentral-offline"
cp "$H/connector/write-config.mjs" "$STAGE/connector/"
for s in Install-PatchGatePackage.ps1 Invoke-PatchGateWuScan.ps1 Install-PatchGateWinUpdate.ps1; do
  cp "$REPO/patchgate-web/scripts/endpoint/$s" "$STAGE/endpoint/$s"
done
cp "$REPO/installers/pc/Install-PatchGateAgent.ps1" "$REPO/installers/pc/Install-PatchGateAgent.cmd" "$STAGE/pc/"
cat > "$STAGE/bundle.env" <<ENV
BUNDLE_VERSION=$VERSION
TACTICAL_VERSION=$TACTICAL_VERSION
CONNECTOR_IMAGE=$CONNECTOR_IMAGE
SOCAT_IMAGE=$SOCAT_IMAGE
AGENT_VERSION=$AGENT_VERSION
DOCKER_STATIC_VERSION=none
BUILT_AT=$(date -u +%FT%TZ)
ENV
find "$STAGE" -type f \( -name '*.sh' -o -name '*.yml' -o -name '*.py' -o -name '*.mjs' -o -name '*.env' -o -name Dockerfile \) -exec sed -i 's/\r$//' {} +
chmod 0755 "$STAGE/install-site.sh"
(cd "$STAGE" && find . -type f ! -name 'SHA256SUMS*' | sed 's#^\./##' | LC_ALL=C sort | xargs -d '\n' sha256sum | sed 's/ \*/  /' > SHA256SUMS)
tar -C "$OUT" -czf "$OUT/$NAME-online.tar.gz" "$NAME"
cp "$STAGE/install-site.sh" "$OUT/install-site.sh"
(cd "$OUT" && sha256sum "$NAME-online.tar.gz" install-site.sh | sed 's/ \*/  /' > SHA256SUMS)
rm -rf "$STAGE"
echo "    $NAME-online.tar.gz ($(du -h "$OUT/$NAME-online.tar.gz" | cut -f1))"
