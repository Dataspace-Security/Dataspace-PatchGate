#!/usr/bin/env bash
# Build the PatchGate colleague test kit from a finished release:
#   kits/colleague-test/build-kit.sh 1.0.0-rc3     ->  kits/colleague-test/out/PatchGate-1.0.0-rc3-test-kit/ (+ .zip if zip/7z exist)
# Inputs (read only): release/out/<version>/{SHA256SUMS,images/*.tar.gz,bundles/patchgate-site-<v>-online.tar.gz,
# bundles/site-SHA256SUMS,bundles/site-install-site.sh}, installers/, deploy/ (secrets/generated files excluded).
set -euo pipefail
V="${1:?usage: build-kit.sh <version>   e.g. 1.0.0-rc3}"
[[ "$V" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "invalid version: $V"; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REL="$ROOT/release/out/$V"
NAME="PatchGate-$V-test-kit"
OUT="$HERE/out/$NAME"

say() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR %s\n' "$*" >&2; exit 1; }

[ -f "$REL/SHA256SUMS" ] || die "$REL/SHA256SUMS not found: build the release first (release/build-release.sh)"
ONL="patchgate-site-$V-online.tar.gz"
for f in "bundles/$ONL" bundles/site-SHA256SUMS bundles/site-install-site.sh; do [ -f "$REL/$f" ] || die "missing $REL/$f"; done
n_img="$(ls "$REL"/images/patchgate-*-"$V".tar.gz 2>/dev/null | wc -l)"
[ "$n_img" = 6 ] || die "expected 6 image archives in $REL/images (found $n_img)"

say "verifying the release inputs against $REL/SHA256SUMS"
(cd "$REL" && for f in images/*.tar.gz "bundles/$ONL" bundles/site-SHA256SUMS bundles/site-install-site.sh; do
   line="$(grep -E " [* ]?(\./)?$f\$" SHA256SUMS || true)"
   [ -n "$line" ] || { echo "  not listed in SHA256SUMS: $f"; exit 1; }
   printf '%s\n' "$line" | sha256sum --strict -c --quiet - || exit 1
   echo "  OK $f"
 done) || die "release checksum verification failed"
# The site installer copy must be the one the site bundle's SHA256SUMS lists.
want="$(awk '$2 ~ /^\*?install-site\.sh$/ {print $1}' "$REL/bundles/site-SHA256SUMS")"
have="$(sha256sum "$REL/bundles/site-install-site.sh" | cut -d' ' -f1)"
[ -n "$want" ] && [ "$want" = "$have" ] || die "bundles/site-install-site.sh does not match install-site.sh in site-SHA256SUMS"
want="$(awk -v f="$ONL" '$2 == f || $2 == "*"f {print $1}' "$REL/bundles/site-SHA256SUMS")"
have="$(sha256sum "$REL/bundles/$ONL" | cut -d' ' -f1)"
[ "$want" = "$have" ] || die "$ONL does not match site-SHA256SUMS"

say "assembling $OUT"
# A rebuild keeps what a test run in this folder wrote (logs, logins, test CA, choices): the kit may be running.
KEEP="$HERE/out/.keep-$NAME"; rm -rf "$KEEP"; mkdir -p "$KEEP"
for f in logs logins.txt patchgate-test-ca.pem; do [ -e "$OUT/$f" ] && mv "$OUT/$f" "$KEEP/"; done
rm -rf "$OUT" "$HERE/out/$NAME.zip"
mkdir -p "$OUT/images" "$OUT/site-bundle" "$OUT/product" "$OUT/lib"
for f in logs logins.txt patchgate-test-ca.pem; do [ -e "$KEEP/$f" ] && mv "$KEEP/$f" "$OUT/"; done
rmdir "$KEEP"; mkdir -p "$OUT/logs"
cp "$REL"/images/patchgate-*-"$V".tar.gz "$OUT/images/"
cp "$REL/bundles/$ONL" "$REL/bundles/site-SHA256SUMS" "$OUT/site-bundle/"
cp "$REL/bundles/site-install-site.sh" "$OUT/site-bundle/install-site.sh"
# Product files the server installer needs (installers/ + deploy/). Never local state: secrets, .env files,
# certificates/keys, backups, per-bank allow-lists, logs, caches.
tar -C "$ROOT" \
  --exclude='deploy/secrets' --exclude='deploy/backups' --exclude='deploy/.env.production' --exclude='*.env' \
  --exclude='deploy/tls/*.pem' --exclude='deploy/tls/*.key' --exclude='deploy/tls/*.srl' --exclude='deploy/ca/*.pem' \
  --exclude='deploy/nginx/allowlists/connectors.d/*.conf' --exclude='*.agekey' --exclude='*.log' \
  --exclude='node_modules' --exclude='*.bak' --exclude='*.orig' --exclude='*~' \
  -cf - installers deploy | tar -C "$OUT/product" -xf -
# Belt and braces: nothing key-like may ride along.
bad="$(cd "$OUT/product" && find . -type f \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' -o -name '.env.production' -o -path '*/secrets/*' -o -name '*.agekey' \) | grep -v 'patchgate-connector/test/fixtures' || true)"
[ -z "$bad" ] || die "secret-looking files in product/: $bad"
cp "$HERE/test-on-my-pc.sh" "$HERE/START-HERE.md" "$OUT/"
cp "$HERE"/lib/* "$OUT/lib/"
printf '%s\n' "$V" > "$OUT/VERSION"
# LF line endings for everything a shell or node reads (a Windows checkout may carry CRLF).
find "$OUT" -maxdepth 2 -type f \( -name '*.sh' -o -name '*.mjs' -o -name '*.md' -o -name VERSION \) -exec sed -i 's/\r$//' {} +
find "$OUT/product" -type f \( -name '*.sh' -o -name '*.conf' -o -name '*.yml' -o -name '*.template' -o -name '*.mjs' -o -name '*.example' \) -exec sed -i 's/\r$//' {} +
chmod 0755 "$OUT/test-on-my-pc.sh" "$OUT"/lib/*.sh
printf 'Run ./test-on-my-pc.sh from the kit folder; each run writes a log file here.\n' > "$OUT/logs/README.txt"

say "kit SHA256SUMS"
(cd "$OUT" && find . -type f ! -name SHA256SUMS ! -path './logs/*' ! -name logins.txt ! -name patchgate-test-ca.pem ! -name '.logins.*' | sed 's#^\./##' | LC_ALL=C sort | xargs -d '\n' sha256sum > SHA256SUMS)
(cd "$OUT" && sha256sum --strict -c --quiet SHA256SUMS) || die "kit checksum self-check failed"
echo "  $(wc -l < "$OUT/SHA256SUMS") files"

if command -v zip >/dev/null 2>&1; then
  say "zip"; (cd "$HERE/out" && zip -qr -1 "$NAME.zip" "$NAME")
elif command -v 7z >/dev/null 2>&1; then
  say "zip (7z)"; (cd "$HERE/out" && 7z a -tzip -mx=1 "$NAME.zip" "$NAME" >/dev/null)
else
  echo "  (no zip/7z found: share the folder, or zip it with Explorer: right-click -> Send to -> Compressed folder)"
fi

say "done"
du -sh "$OUT" | sed 's/^/  /'
[ -f "$HERE/out/$NAME.zip" ] && du -sh "$HERE/out/$NAME.zip" | sed 's/^/  /'
du -sh "$OUT"/images "$OUT"/site-bundle "$OUT"/product | sed 's/^/  /'
