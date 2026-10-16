# syntax=docker/dockerfile:1.7
#
# PatchGate production image.
#
#   docker build -t patchgate-web:<version> --build-arg PATCHGATE_BUILD_ID=<version> .          # web/fetcher (default target)
#   docker build -t patchgate-tools:<version> --target tools --build-arg PATCHGATE_BUILD_ID=<version> .   # migrate + admin CLI
#
# Targets
#   runner (default) - Next.js standalone server (node server.js), non-root, read-only-rootfs friendly.
#   tools            - full node_modules + prisma CLI + sources for ONE-SHOT jobs only:
#                      `prisma migrate deploy` (never run on web start) and admin scripts.
#
# Secrets are never baked in. At runtime the entrypoint turns VAR_FILE=/run/secrets/x into VAR, and
# builds DATABASE_URL from DB_HOST/DB_PORT/DB_NAME/DB_USER + DB_PASSWORD_FILE (see deploy/).

# Debian 13 (trixie): current OS packages; release/release.sh fails the build on CRITICAL findings.
ARG NODE_IMAGE=node:24-trixie-slim

# ---------------------------------------------------------------- osslsigncode: built from a pinned release
# Debian ships 2.9 (CVE-2025-70888, fixed upstream after 2.10). Built without cURL: PatchGate only VERIFIES
# Authenticode signatures (no timestamping requests), so the runtime needs just libssl + zlib.
# docker/osslsigncode/*.patch: accept Microsoft's critical "Application Policies" extension (OID
# 1.3.6.1.4.1.311.21.10, unknown to OpenSSL). Without it every Microsoft Store/Marketplace-signed file
# (e.g. the winget source.msix) fails with "unhandled critical extension". Any OTHER unknown critical
# extension still fails. Re-check the patch applies (--fuzz=0) when bumping OSSLSIGNCODE_VERSION.
FROM ${NODE_IMAGE} AS osslsigncode
ARG OSSLSIGNCODE_VERSION=2.14
ARG OSSLSIGNCODE_SHA256=0f033fd6069387d2e489fbd2187e62f624764eb8c2758ee94e3e793e5150b5c5
COPY docker/osslsigncode/ /tmp/patches/
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl build-essential cmake libssl-dev zlib1g-dev patch \
 && curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/src.tar.gz "https://github.com/mtrojnar/osslsigncode/archive/refs/tags/${OSSLSIGNCODE_VERSION}.tar.gz" \
 && echo "${OSSLSIGNCODE_SHA256}  /tmp/src.tar.gz" | sha256sum -c - \
 && mkdir /src && tar -C /src --strip-components=1 -xzf /tmp/src.tar.gz \
 && for p in /tmp/patches/*.patch; do patch -p1 --forward --fuzz=0 -d /src < "$p" || exit 1; done \
 && cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release -DCMAKE_DISABLE_FIND_PACKAGE_CURL=ON \
 && cmake --build /build -j"$(nproc)" \
 && install -m 0755 /build/osslsigncode /usr/local/bin/osslsigncode \
 && /usr/local/bin/osslsigncode --version

# ---------------------------------------------------------------- os: shared runtime packages
FROM ${NODE_IMAGE} AS os
# tini: PID 1 (signal forwarding, zombie reaping) · osslsigncode: Authenticode verification on Linux
# (src/lib/fetch/signature.ts, with CODESIGN_CA_FILE; built above) · ca-certificates: CA bundle for TLS +
# CODESIGN_CA_FILE · openssl: Prisma engine detection + libssl3 for osslsigncode.
COPY --from=osslsigncode /usr/local/bin/osslsigncode /usr/local/bin/osslsigncode
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends tini ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* \
 && osslsigncode --version >/dev/null \
 && groupadd --gid 10001 patchgate \
 && useradd --uid 10001 --gid patchgate --no-create-home --home-dir /app --shell /usr/sbin/nologin patchgate
ENV NEXT_TELEMETRY_DISABLED=1 \
    CHECKPOINT_DISABLE=1 \
    PRISMA_HIDE_UPDATE_MESSAGE=1

# Secrets-as-files + DATABASE_URL assembly, then exec the command (under tini).
COPY --chmod=0755 <<'EOF' /usr/local/bin/patchgate-entrypoint
#!/bin/sh
set -eu
fail() { printf '{"ts":"%s","level":"error","msg":"entrypoint.%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >&2; exit 1; }
# VAR_FILE=/run/secrets/name  ->  VAR=<file contents, trailing newline stripped>
for var in AUDIT_HMAC_KEY WORKER_TOKEN WSUS_TOKEN AUTH_ENC_KEY AUTH_ENC_KEY_PREVIOUS TACTICAL_API_KEY OIDC_CLIENT_SECRET GITHUB_TOKEN METRICS_TOKEN SMTP_URL DATABASE_URL; do
  eval "file=\${${var}_FILE:-}"
  [ -n "$file" ] || continue
  eval "current=\${${var}:-}"
  [ -z "$current" ] || fail "secret_conflict.${var}"
  [ -r "$file" ] || fail "secret_unreadable.${var}"
  value="$(cat "$file")"
  export "$var=$value"
  unset "${var}_FILE"
done
# Least privilege: a container that must pass config validation but never USES a secret (e.g. the fetcher
# never decrypts TOTP seeds or calls Tactical) gets a random per-start value instead of the real one:
#   PATCHGATE_EPHEMERAL_SECRETS="AUTH_ENC_KEY TACTICAL_API_KEY"
# Never allowed for AUDIT_HMAC_KEY / DATABASE_URL (they must be the real values when present).
for var in ${PATCHGATE_EPHEMERAL_SECRETS:-}; do
  case "$var" in AUTH_ENC_KEY|TACTICAL_API_KEY|WSUS_TOKEN|WORKER_TOKEN) ;; *) fail "ephemeral_not_allowed.${var}" ;; esac
  eval "current=\${${var}:-}"
  [ -z "$current" ] || fail "secret_conflict.${var}"
  value="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
  [ "${#value}" -eq 64 ] || fail "ephemeral_failed.${var}"
  export "$var=$value"
done
unset PATCHGATE_EPHEMERAL_SECRETS value current file
if [ -z "${DATABASE_URL:-}" ] && [ -n "${DB_PASSWORD_FILE:-}" ]; then
  [ -r "$DB_PASSWORD_FILE" ] || fail "secret_unreadable.DB_PASSWORD"
  # Password must be URL-safe (deploy/scripts/generate-secrets.sh emits hex).
  pw="$(cat "$DB_PASSWORD_FILE")"
  DATABASE_URL="postgresql://${DB_USER:?DB_USER required}:${pw}@${DB_HOST:-db}:${DB_PORT:-5432}/${DB_NAME:-patchgate}?schema=public"
  [ -z "${DB_URL_PARAMS:-}" ] || DATABASE_URL="${DATABASE_URL}&${DB_URL_PARAMS}"
  export DATABASE_URL
  unset DB_PASSWORD_FILE pw
fi
exec "$@"
EOF

# ---------------------------------------------------------------- deps: full install (dev deps needed to build)
FROM os AS deps
WORKDIR /src
COPY package.json package-lock.json ./
# postinstall runs `prisma generate`, which needs the schema.
COPY prisma ./prisma
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund

# ---------------------------------------------------------------- build: next build (output: standalone)
FROM deps AS build
COPY . .
ARG PATCHGATE_BUILD_ID=dev
ENV NODE_ENV=production \
    PATCHGATE_BUILD_ID=${PATCHGATE_BUILD_ID}
RUN npx prisma generate && npm run build \
 && test -f .next/standalone/server.js

# ---------------------------------------------------------------- tools: one-shot jobs (migrate, admin CLI)
FROM os AS tools
WORKDIR /app
ENV NODE_ENV=production HOME=/tmp
COPY --from=deps /src/node_modules ./node_modules
COPY package.json package-lock.json tsconfig.json ./
COPY prisma ./prisma
COPY scripts ./scripts
COPY src ./src
USER 10001:10001
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/patchgate-entrypoint"]
CMD ["node", "node_modules/prisma/build/index.js", "migrate", "deploy"]

# ---------------------------------------------------------------- runner: production web / fetcher
FROM os AS runner
WORKDIR /app
ARG PATCHGATE_BUILD_ID=dev
LABEL org.opencontainers.image.title="patchgate-web" \
      org.opencontainers.image.version="${PATCHGATE_BUILD_ID}" \
      org.opencontainers.image.vendor="Dataspace"
# HOSTNAME must be 0.0.0.0: Docker sets HOSTNAME to the container id and server.js binds to it.
ENV NODE_ENV=production \
    HOSTNAME=0.0.0.0 \
    PORT=3000 \
    HOME=/tmp \
    REPO_DIR=/data/repo \
    PATCHGATE_BUILD_ID=${PATCHGATE_BUILD_ID}
# App files are owned by root and read-only for the runtime user.
COPY --from=build /src/.next/standalone ./
COPY --from=build /src/.next/static ./.next/static
COPY --from=build /src/public ./public
# Writable paths (mount tmpfs / volumes here when the root filesystem is read-only):
#   /app/.next/cache (Next.js cache)   /data/repo (shared package store, REPO_DIR)   /tmp
RUN mkdir -p /app/.next/cache /data/repo \
 && chown 10001:10001 /app/.next/cache /data/repo
USER 10001:10001
EXPOSE 3000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/patchgate-entrypoint"]
CMD ["node", "server.js"]
