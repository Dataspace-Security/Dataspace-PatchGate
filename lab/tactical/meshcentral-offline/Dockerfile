# Offline MeshCentral for an air-gapped Tactical RMM.
# The stock image installs extra npm modules AT RUNTIME (needs internet). This build bakes them in, so
# the resulting image runs with no internet at all. Build it in the PatchGate (internet) zone and ship
# it to the offline Tactical server as part of the Tactical offline bundle (ARCHITECTURE §6B).
FROM tacticalrmm/tactical-meshcentral:latest

USER root
WORKDIR /home/node/app
RUN npm install --no-audit --no-fund --omit=optional \
      mongodb@4.17.2 @mongodb-js/saslprep@1.3.1 nodemailer@6.10.1 \
 && chown -R node:node /home/node
USER node
