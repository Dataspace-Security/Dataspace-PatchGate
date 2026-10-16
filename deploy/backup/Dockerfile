# Backup sidecar: pg_dump/psql of the SAME PostgreSQL major as the server + age for encryption.
# Minimal on purpose (the release scan fails on CRITICAL findings): Debian slim + ONLY the PGDG client
# package (no server, no gosu, no libxml2) + age built from source with a current Go toolchain.
ARG GO_IMAGE=golang:1.27-trixie
ARG DEBIAN_IMAGE=debian:trixie-slim

FROM ${GO_IMAGE} AS age
ARG AGE_VERSION=v1.3.2
# Module download is verified against the Go checksum database (sum.golang.org).
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath -ldflags="-s -w" "filippo.io/age/cmd/...@${AGE_VERSION}" \
 && /out/age --version

FROM ${DEBIAN_IMAGE}
ARG PG_MAJOR=16
# PostgreSQL Global Development Group apt signing key (www.postgresql.org/download/linux/debian). Pinned.
ARG PGDG_KEY_FPR=B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/pgdg.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc \
 && fpr="$(gpg --show-keys --with-colons /tmp/pgdg.asc | awk -F: '$1=="fpr"{print $10; exit}')" \
 && [ "$fpr" = "$PGDG_KEY_FPR" ] || { echo "PGDG key fingerprint mismatch: $fpr" >&2; exit 1; } \
 && gpg --dearmor -o /usr/share/keyrings/pgdg.gpg < /tmp/pgdg.asc && rm -f /tmp/pgdg.asc \
 && . /etc/os-release \
 && echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "postgresql-client-${PG_MAJOR}" \
 && apt-get purge -y --auto-remove curl gnupg \
 && rm -rf /var/lib/apt/lists/* /root/.gnupg
COPY --from=age /out/age /out/age-keygen /usr/local/bin/
ENV PATH=/usr/lib/postgresql/${PG_MAJOR}/bin:$PATH
COPY --chmod=0755 backup.sh /usr/local/bin/patchgate-backup
ENTRYPOINT ["/usr/local/bin/patchgate-backup"]
CMD ["schedule"]
