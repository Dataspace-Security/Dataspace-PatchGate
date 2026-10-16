#!/usr/bin/env bash
# Build the OFFLINE bank-site bundle (run by US, on a machine with Docker + internet):
#
#   installers/site/build-site-bundle.sh --version 1.0.0 \
#       --agent-dir <dir with tacticalagent-v<ver>-windows-{amd64,386}.exe> --agent-version 2.11.0 \
#       [--agent-sha256 <file "sha256  name" from PatchGate's verified mirror>] [--sign-key bundle-signing.pem]
#
# Output (in --out, default ./dist):
#   patchgate-site-<ver>.tar.gz    everything a bank site needs, no internet required:
#       install-site.sh, bundle.env, SHA256SUMS (every file inside)
#       images/images.tar + IMAGES.txt   `docker save` of Tactical (incl. the OFFLINE MeshCentral image),
#                                        mongo/redis/postgres, socat (ingress/egress)
#       images/local.tar                 the PatchGate Connector image (ours, not on a public registry)
#       images/IMAGES.lock               "<tag> <image@sha256:digest>" of every public image (for --online)
#       docker/                          static Docker Engine + Compose plugin (used only if Docker is missing)
#       tactical/                        Tactical's official docker-compose.yml + our site override + provisioning
#                                        + meshcentral-offline/Dockerfile (built on site in --online mode)
#       connector/write-config.mjs       connector.json generator (runs inside the connector image)
#       endpoint/*.ps1                   the 3 PatchGate PowerShell scripts registered in Tactical
#       pc/Install-PatchGateAgent.ps1    bank PC installer (step 3) (+ Install-PatchGateAgent.cmd double-click wrapper)
#       agent/                           Tactical agent installers + AGENT-SHA256SUMS + SOURCE.txt
#   patchgate-site-<ver>-online.tar.gz   same without images.tar and docker/ (for `install-site.sh --online`:
#                                        public images are pulled by digest, Docker from the official apt repo)
#   install-site.sh                a loose copy for USB use: sudo ./install-site.sh --bundle patchgate-site-<ver>.tar.gz
#   SHA256SUMS (+ SHA256SUMS.sig)  checksums (and Ed25519 signature) of both archives + install-site.sh
#
# Agent source: PatchGate's VERIFIED Tactical agent mirror. The fetcher downloads releases from
# github.com/amidaware/rmmagent, verifies them and stores them under REPO_DIR/tactical/agent/<ver>/ (rows in
# "MirroredRelease", component TACTICAL_AGENT, verification VERIFIED). Export from production with:
#   docker compose -f docker-compose.prod.yml --env-file .env.production exec -T web-1 \
#     tar -C /data/repo -cf - tactical/agent/<ver> | tar -xf - -C /tmp/agent-export
#   + the expected hashes:  SELECT sha256||'  '||"assetName" FROM "MirroredRelease"
#                           WHERE component='TACTICAL_AGENT' AND verification='VERIFIED' AND version='<ver>';
# and pass --agent-dir /tmp/agent-export/tactical/agent/<ver> --agent-sha256 <that output>.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VERSION=""
OUT="./dist"
TACTICAL_VERSION="1.5.2"
TACTICAL_SRC_TAG="latest"
TACTICAL_COMPOSE="$REPO/../tacticalrmm/docker/docker-compose.yml"
MESH_IMAGE=""
CONNECTOR_IMAGE="patchgate-connector:1.0.0"
SOCAT_SRC="alpine/socat:latest"
AGENT_VERSION="2.11.0"
AGENT_DIR=""
AGENT_SHA_FILE=""
DOCKER_VERSION="28.5.2"
COMPOSE_VERSION="2.40.3"
NO_DOCKER_STATIC=0
SIGN_KEY=""
PULL=0
KEEP=0

die() { printf 'ERROR %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; cat <<'TXT'

More options: --out DIR  --tactical-version 1.5.2  --tactical-src-tag latest  --tactical-compose FILE
  --mesh-image IMG (default: build lab/tactical/meshcentral-offline)  --connector-image patchgate-connector:1.0.0
  --socat-image alpine/socat:latest  --docker-version 28.5.2  --compose-version 2.40.3  --no-docker-static
  --pull (pull missing upstream images)  --keep-staging
TXT
}
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tactical-version) TACTICAL_VERSION="$2"; shift 2 ;;
    --tactical-src-tag) TACTICAL_SRC_TAG="$2"; shift 2 ;;
    --tactical-compose) TACTICAL_COMPOSE="$2"; shift 2 ;;
    --mesh-image) MESH_IMAGE="$2"; shift 2 ;;
    --connector-image) CONNECTOR_IMAGE="$2"; shift 2 ;;
    --socat-image) SOCAT_SRC="$2"; shift 2 ;;
    --agent-version) AGENT_VERSION="$2"; shift 2 ;;
    --agent-dir) AGENT_DIR="$2"; shift 2 ;;
    --agent-sha256) AGENT_SHA_FILE="$2"; shift 2 ;;
    --docker-version) DOCKER_VERSION="$2"; shift 2 ;;
    --compose-version) COMPOSE_VERSION="$2"; shift 2 ;;
    --no-docker-static) NO_DOCKER_STATIC=1; shift ;;
    --sign-key) SIGN_KEY="$2"; shift 2 ;;
    --pull) PULL=1; shift ;;
    --keep-staging) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[ -n "$VERSION" ] || VERSION="$(date -u +%Y.%m.%d)"
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,40}$ ]] || die "invalid --version"
[[ "$AGENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid --agent-version"
[ -n "$AGENT_DIR" ] || AGENT_DIR="$REPO/lab/patchgate/repo-data/tactical/agent/$AGENT_VERSION"
for t in docker tar gzip sha256sum curl awk; do command -v "$t" >/dev/null || die "$t is required"; done
docker info >/dev/null 2>&1 || die "Docker daemon not reachable"
[ -f "$TACTICAL_COMPOSE" ] || die "Tactical compose file not found: $TACTICAL_COMPOSE (--tactical-compose)"

NAME="patchgate-site-$VERSION"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
STAGE="$OUT/$NAME"
rm -rf "$STAGE"; mkdir -p "$STAGE"/{images,docker,tactical,connector,endpoint,pc,agent}

have() { docker image inspect "$1" >/dev/null 2>&1; }
need_image() { have "$1" && return 0; [ "$PULL" = 1 ] || die "image $1 not present (docker pull it, or --pull)"; docker pull -q "$1" >/dev/null; }

# ------------------------------------------------------------------ images
step "Images"
IMAGES=()
for c in tactical tactical-nginx tactical-frontend tactical-nats; do
  need_image "tacticalrmm/$c:$TACTICAL_SRC_TAG"
  [ "$TACTICAL_SRC_TAG" = "$TACTICAL_VERSION" ] || docker tag "tacticalrmm/$c:$TACTICAL_SRC_TAG" "tacticalrmm/$c:$TACTICAL_VERSION"
  IMAGES+=("tacticalrmm/$c:$TACTICAL_VERSION")
done
found="$(docker run --rm --network none --entrypoint sh "tacticalrmm/tactical:$TACTICAL_VERSION" -c \
  'sed -n "s/^TRMM_VERSION = \"\(.*\)\"/\1/p" /tmp/tactical/api/tacticalrmm/settings.py' 2>/dev/null || true)"
[ "$found" = "$TACTICAL_VERSION" ] || die "tacticalrmm/tactical:$TACTICAL_SRC_TAG is Tactical '$found', not $TACTICAL_VERSION"
info "Tactical $found verified inside the image"
# IMAGES.lock: "<local tag> <registry ref@sha256 digest>" for every public image, so `install-site.sh --online`
# pulls exactly the bits packed here (same digests), never a moving tag.
LOCK="$STAGE/images/IMAGES.lock"; : > "$LOCK"
lock() { # local-tag source-image
  local d; d="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$2" | grep -m1 '@sha256:' || true)"
  [ -n "$d" ] || die "$2 has no registry digest (pull it from its registry first)"
  printf '%s %s\n' "$1" "$d" >> "$LOCK"
}
for c in tactical tactical-nginx tactical-frontend tactical-nats tactical-meshcentral; do
  need_image "tacticalrmm/$c:$TACTICAL_SRC_TAG"; lock "tacticalrmm/$c:$TACTICAL_VERSION" "tacticalrmm/$c:$TACTICAL_SRC_TAG"
done
MESH_TAG="patchgate-site/tactical-meshcentral-offline:$TACTICAL_VERSION"
if [ -n "$MESH_IMAGE" ]; then
  need_image "$MESH_IMAGE"; docker tag "$MESH_IMAGE" "$MESH_TAG"
else
  info "building the offline MeshCentral image (installers/site/tactical/meshcentral-offline)"
  docker build -q -t "$MESH_TAG" --build-arg "MESH_BASE=tacticalrmm/tactical-meshcentral:$TACTICAL_SRC_TAG" \
    "$HERE/tactical/meshcentral-offline" >/dev/null
fi
IMAGES+=("$MESH_TAG")
# Third-party images exactly as referenced by Tactical's compose file.
while read -r img; do
  [ -n "$img" ] || continue
  need_image "$img"; IMAGES+=("$img"); lock "$img" "$img"
done < <(sed -nE 's/^\s*image:\s*([^$ ]+)\s*$/\1/p' "$TACTICAL_COMPOSE" | tr -d '\r' | sort -u)
need_image "$SOCAT_SRC"
SOCAT_IMAGE="patchgate-site/socat:$VERSION"; docker tag "$SOCAT_SRC" "$SOCAT_IMAGE"; IMAGES+=("$SOCAT_IMAGE"); lock "$SOCAT_IMAGE" "$SOCAT_SRC"
if ! have "$CONNECTOR_IMAGE"; then
  info "building $CONNECTOR_IMAGE from patchgate-connector/"
  docker build -q -t "$CONNECTOR_IMAGE" "$REPO/patchgate-connector" >/dev/null
fi
printf '%s\n' "${IMAGES[@]}" "$CONNECTOR_IMAGE" > "$STAGE/images/IMAGES.txt"
info "docker save ${#IMAGES[@]} public/Tactical images (shared layers stored once)"
docker save -o "$STAGE/images/images.tar" "${IMAGES[@]}"
info "images.tar: $(du -h "$STAGE/images/images.tar" | cut -f1)"
# Our own image (not on any public registry): in BOTH variants.
docker save -o "$STAGE/images/local.tar" "$CONNECTOR_IMAGE"
info "local.tar ($CONNECTOR_IMAGE): $(du -h "$STAGE/images/local.tar" | cut -f1)"
cp -r "$HERE/tactical/meshcentral-offline" "$STAGE/tactical/meshcentral-offline"

# ------------------------------------------------------------------ static Docker (only used where Docker is missing)
if [ "$NO_DOCKER_STATIC" = 0 ]; then
  step "Static Docker $DOCKER_VERSION + Compose $COMPOSE_VERSION"
  CACHE="$OUT/.cache"; mkdir -p "$CACHE"
  dtgz="docker-$DOCKER_VERSION.tgz"
  [ -s "$CACHE/$dtgz" ] || curl -fsSL --proto =https -o "$CACHE/$dtgz" "https://download.docker.com/linux/static/stable/x86_64/$dtgz"
  tar -tzf "$CACHE/$dtgz" docker/dockerd >/dev/null || die "$dtgz is not a Docker static archive"
  cbin="docker-compose-linux-x86_64"
  if [ ! -s "$CACHE/compose-$COMPOSE_VERSION" ]; then
    curl -fsSL --proto =https -o "$CACHE/compose-$COMPOSE_VERSION" "https://github.com/docker/compose/releases/download/v$COMPOSE_VERSION/$cbin"
    want="$(curl -fsSL --proto =https "https://github.com/docker/compose/releases/download/v$COMPOSE_VERSION/$cbin.sha256" | awk '{print $1}')"
    got="$(sha256sum "$CACHE/compose-$COMPOSE_VERSION" | awk '{print $1}')"
    [ "$want" = "$got" ] || { rm -f "$CACHE/compose-$COMPOSE_VERSION"; die "compose checksum mismatch"; }
  fi
  cp "$CACHE/$dtgz" "$STAGE/docker/$dtgz"
  cp "$CACHE/compose-$COMPOSE_VERSION" "$STAGE/docker/docker-compose"
  info "docker/$dtgz (download.docker.com, https) + docker-compose (GitHub release, published SHA-256 verified)"
fi

# ------------------------------------------------------------------ files
step "Files"
cp "$HERE/install-site.sh" "$STAGE/install-site.sh"
cp "$TACTICAL_COMPOSE" "$STAGE/tactical/docker-compose.yml"
cp "$HERE/tactical/docker-compose.site.yml" "$HERE/tactical/provision-site.py" "$HERE/tactical/break-glass.py" "$STAGE/tactical/"
cp "$HERE/connector/write-config.mjs" "$STAGE/connector/"
for s in Install-PatchGatePackage.ps1 Invoke-PatchGateWuScan.ps1 Install-PatchGateWinUpdate.ps1; do
  cp "$REPO/patchgate-web/scripts/endpoint/$s" "$STAGE/endpoint/$s"
done
cp "$REPO/installers/pc/Install-PatchGateAgent.ps1" "$REPO/installers/pc/Install-PatchGateAgent.cmd" "$STAGE/pc/"
# LF for everything the Linux side executes.
find "$STAGE" -maxdepth 2 -type f \( -name '*.sh' -o -name '*.yml' -o -name '*.py' -o -name '*.mjs' \) -exec sed -i 's/\r$//' {} +
chmod 0755 "$STAGE/install-site.sh"

step "Tactical agent $AGENT_VERSION (from $AGENT_DIR)"
n=0
for arch in amd64 386; do
  f="tacticalagent-v$AGENT_VERSION-windows-$arch.exe"
  [ -f "$AGENT_DIR/$f" ] || { [ "$arch" = amd64 ] && die "missing $AGENT_DIR/$f"; continue; }
  cp "$AGENT_DIR/$f" "$STAGE/agent/$f"; n=$((n + 1))
done
(cd "$STAGE/agent" && sha256sum tacticalagent-v*.exe > AGENT-SHA256SUMS)
if [ -n "$AGENT_SHA_FILE" ]; then
  while read -r sum file; do
    file="${file#\*}"   # sha256sum binary-mode marker (e.g. Git Bash)
    want="$(awk -v f="$file" '$2==f || $2=="*"f {print $1}' "$AGENT_SHA_FILE" | head -1 || true)"
    [ -n "$want" ] || die "no expected hash for $file in $AGENT_SHA_FILE"
    [ "$want" = "$sum" ] || die "$file does not match PatchGate's verified mirror hash"
  done < "$STAGE/agent/AGENT-SHA256SUMS"
  info "agent hashes match PatchGate's verified mirror ($AGENT_SHA_FILE)"
else
  echo "    WARNING: --agent-sha256 not given: agent hashes NOT cross-checked against PatchGate's mirror" >&2
fi
cat > "$STAGE/agent/SOURCE.txt" <<TXT
Tactical RMM agent $AGENT_VERSION for Windows ($n file(s)).
Source: PatchGate's verified Tactical agent mirror (fetched from github.com/amidaware/rmmagent releases,
digest-verified by the PatchGate fetcher; "MirroredRelease" rows with verification=VERIFIED), exported from
REPO_DIR/tactical/agent/$AGENT_VERSION/. SHA-256 values: AGENT-SHA256SUMS. Unsigned by the vendor: the PC script
installs ONLY a file whose SHA-256 matches. Banks can pin these hashes in connector.json trust.agentSha256.
Bundle $VERSION built $(date -u +%FT%TZ).
TXT

cat > "$STAGE/bundle.env" <<ENV
BUNDLE_VERSION=$VERSION
TACTICAL_VERSION=$TACTICAL_VERSION
CONNECTOR_IMAGE=$CONNECTOR_IMAGE
SOCAT_IMAGE=$SOCAT_IMAGE
AGENT_VERSION=$AGENT_VERSION
DOCKER_STATIC_VERSION=$([ "$NO_DOCKER_STATIC" = 0 ] && echo "$DOCKER_VERSION" || echo none)
BUILT_AT=$(date -u +%FT%TZ)
ENV

step "Checksums + archives"
# Full (offline) variant: everything. Online variant: no images.tar / static Docker (pulled/installed online).
(cd "$STAGE" && find . -type f ! -name 'SHA256SUMS*' -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum > SHA256SUMS)
(cd "$STAGE" && grep -vE ' [ *](images/images\.tar|docker/.*)$' SHA256SUMS > SHA256SUMS.online)
info "SHA256SUMS: $(wc -l < "$STAGE/SHA256SUMS") files (online variant: $(wc -l < "$STAGE/SHA256SUMS.online"))"
gz=(gzip -6); command -v pigz >/dev/null && gz=(pigz -6)
tar -C "$OUT" --exclude="$NAME/SHA256SUMS.online" -cf - "$NAME" | "${gz[@]}" > "$OUT/$NAME.tar.gz"
tar -C "$OUT" --exclude="$NAME/SHA256SUMS" --exclude="$NAME/images/images.tar" --exclude="$NAME/docker" \
    --transform="s#^$NAME/SHA256SUMS\.online\$#$NAME/SHA256SUMS#" -cf - "$NAME" | "${gz[@]}" > "$OUT/$NAME-online.tar.gz"
# A loose copy of the installer next to the archives: `sudo ./install-site.sh --bundle <archive>` from a USB stick
# (it checks the archive against SHA256SUMS before extracting, then runs the bundle's own copy).
cp "$STAGE/install-site.sh" "$OUT/install-site.sh"; chmod 0755 "$OUT/install-site.sh"
(cd "$OUT" && sha256sum "$NAME.tar.gz" "$NAME-online.tar.gz" install-site.sh > SHA256SUMS)
if [ -n "$SIGN_KEY" ]; then
  openssl pkeyutl -sign -inkey "$SIGN_KEY" -rawin -in "$OUT/SHA256SUMS" -out "$OUT/SHA256SUMS.sig"
  openssl pkey -in "$SIGN_KEY" -pubout -out "$OUT/bundle-signing.pub.pem"
  # One-line form for PATCHGATE_SITE_BUNDLE_PUBKEY / install-site.sh --bundle-key (raw key = last 32 DER bytes).
  printf 'ed25519:%s\n' "$(openssl pkey -in "$SIGN_KEY" -pubout -outform DER | tail -c 32 | base64 -w0)" > "$OUT/bundle-signing.pub.txt"
  info "signed: SHA256SUMS.sig — server: PATCHGATE_SITE_BUNDLE_PUBKEY=$(cat "$OUT/bundle-signing.pub.txt"); USB installs: --bundle-key <same>"
fi
[ "$KEEP" = 1 ] || rm -rf "$STAGE"
step "Done"
info "$OUT/$NAME.tar.gz         offline/USB  ($(du -h "$OUT/$NAME.tar.gz" | cut -f1))"
info "$OUT/$NAME-online.tar.gz  --online     ($(du -h "$OUT/$NAME-online.tar.gz" | cut -f1))"
info "$OUT/SHA256SUMS"
