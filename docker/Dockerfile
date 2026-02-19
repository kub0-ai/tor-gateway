FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.source="https://github.com/kub0-ai/tor-gateway"
LABEL org.opencontainers.image.description="Tor transparent-proxy sidecar with iptables killswitch"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update -y \
  && apt-get install -y --no-install-recommends \
       tor \
       iptables \
       iproute2 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY torrc /etc/tor/torrc
COPY setup-iptables.sh /usr/local/bin/setup-iptables.sh
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/setup-iptables.sh /entrypoint.sh

# 9050 — SOCKS5 proxy (application-level)
# 9051 — control port
# 9040 — TransPort (transparent TCP proxy target for iptables REDIRECT)
# 5353 — DNSPort (DNS resolver over Tor)
EXPOSE 9050 9051 9040

VOLUME ["/var/lib/tor"]

ENTRYPOINT ["/entrypoint.sh"]
