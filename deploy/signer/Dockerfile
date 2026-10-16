# PatchGate job signer: holds the job-signing private keys (per bank) and nothing else.
# No npm dependencies, no shell tools needed at runtime, no network access except the internal
# "signer" Docker network (docker-compose.prod.yml).
#
#   docker build -t patchgate-signer:local deploy/signer                 # runtime image
#   docker build --target test deploy/signer                             # runs the unit tests
ARG NODE_IMAGE=node:24-alpine

FROM ${NODE_IMAGE} AS base
WORKDIR /opt/signer
COPY server.mjs ./

FROM base AS test
COPY server.test.mjs ./
RUN node --test server.test.mjs

FROM base AS runtime
# Audit trail directory (named volume signer-audit inherits this ownership on first use).
RUN mkdir -p /var/log/signer && chown 10002:10001 /var/log/signer && chmod 0750 /var/log/signer
# uid 10002 (keys are 0600 owned by 10002); gid 10001 lets it read the shared job_signer_token (0640, group 10001).
USER 10002:10001
ENV NODE_ENV=production SIGNER_PORT=8080 SIGNER_KEY_DIR=/run/job-keys SIGNER_TOKEN_FILE=/run/secrets/job_signer_token
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.SIGNER_PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["node", "/opt/signer/server.mjs"]
