# Offline MeshCentral for an air-gapped Tactical RMM site (same recipe as lab/tactical/meshcentral-offline).
# The stock image npm-installs extra modules AT RUNTIME (needs internet); this build bakes them in, so the
# container runs with no internet at all (Tactical's networks are internal-only).
#   offline bundle: built by build-site-bundle.sh and shipped in images.tar
#   online mode:    built on the site VM by install-site.sh --online from the digest-pinned stock image
ARG MESH_BASE=tacticalrmm/tactical-meshcentral:latest
FROM ${MESH_BASE}

USER root
WORKDIR /home/node/app
RUN npm install --no-audit --no-fund --omit=optional \
      mongodb@4.17.2 @mongodb-js/saslprep@1.3.1 nodemailer@6.10.1 \
 && chown -R node:node /home/node
USER node
