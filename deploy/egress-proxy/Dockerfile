# Forward proxy for the fetcher: HTTPS CONNECT only, to an explicit vendor host allow-list. No caching,
# no TLS interception (PatchGate verifies SHA-256 + Authenticode itself).
FROM alpine:3.22
RUN apk add --no-cache squid \
 && install -d -o squid -g squid /var/cache/squid /var/run/squid /var/log/squid
# Run unprivileged from the start (also lets squid write its logs to the container stdout).
USER squid
EXPOSE 3128
ENTRYPOINT ["squid", "-N", "-f", "/etc/squid/squid.conf"]
