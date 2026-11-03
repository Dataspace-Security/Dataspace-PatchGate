# PatchGate Connector — single bundled file on node:24-alpine, non-root, read-only root filesystem.
# Build:  docker build -t patchgate-connector:1.0.0 .
# Run:    see docker-compose.example.yml (read_only: true; only /var/lib/patchgate-connector is writable)

FROM node:25-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY scripts ./scripts
COPY src ./src
RUN node scripts/build.mjs

FROM node:25-alpine
# The image contains nothing but node and the bundle (zod is inlined; no node_modules at runtime).
RUN apk add --no-cache tini \
 && mkdir -p /opt/patchgate-connector /var/lib/patchgate-connector /etc/patchgate-connector \
 && chown node:node /var/lib/patchgate-connector \
 && chmod 0700 /var/lib/patchgate-connector
COPY --from=build --chown=root:root --chmod=0555 /src/dist/patchgate-connector.mjs /opt/patchgate-connector/patchgate-connector.mjs

ENV NODE_ENV=production \
    PATCHGATE_CONNECTOR_CONFIG=/etc/patchgate-connector/connector.json
USER node:node
VOLUME ["/var/lib/patchgate-connector"]
EXPOSE 8443
STOPSIGNAL SIGTERM

# Liveness of the local cache server only (no outbound calls). `check` is the full probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "require('https').get({host:'127.0.0.1',port:process.env.PGC_HEALTH_PORT||8443,path:'/healthz',rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

ENTRYPOINT ["/sbin/tini", "--", "node", "/opt/patchgate-connector/patchgate-connector.mjs"]
CMD ["run"]
