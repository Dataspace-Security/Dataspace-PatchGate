#!/usr/bin/env bash
# Lab PKI: a private root CA (like a bank's internal CA) + one wildcard server certificate for all
# lab hosts. Used by Tactical nginx, PatchGate (HTTPS), the SIEM receiver, and trusted in the sandbox.
# Usage: lab/certs/make-certs.sh <lab-domain>     e.g. 192-168-1-33.nip.io
set -euo pipefail

DOMAIN="${1:?lab domain required, e.g. 192-168-1-33.nip.io}"
DIR="$(cd "$(dirname "$0")" && pwd)/out"
mkdir -p "$DIR"
cd "$DIR"

if [ ! -f ca.key ]; then
  openssl genrsa -out ca.key 4096 2>/dev/null
  MSYS_NO_PATHCONV=1 openssl req -x509 -new -key ca.key -sha256 -days 825 \
    -subj "/C=IN/O=PatchGate Lab/CN=PatchGate Lab Root CA" -out ca.crt
fi

openssl genrsa -out server.key 2048 2>/dev/null
cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:*.${DOMAIN},DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1
EOF
MSYS_NO_PATHCONV=1 openssl req -new -key server.key -subj "/C=IN/O=PatchGate Lab/CN=*.${DOMAIN}" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 397 -sha256 \
  -extfile server.ext -out server.crt 2>/dev/null
cat server.crt ca.crt > fullchain.crt
rm -f server.csr server.ext

echo "CA:        $DIR/ca.crt"
echo "Server:    $DIR/server.crt (SAN *.${DOMAIN})"
echo "Fullchain: $DIR/fullchain.crt"
