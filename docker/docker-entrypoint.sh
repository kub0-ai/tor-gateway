#!/bin/bash
# docker-entrypoint.sh — Tor gateway sidecar runtime
#
# Assumes iptables killswitch was already applied by the tor-killswitch
# init container (setup-iptables.sh).  This container just runs Tor.
# Tor itself drops privileges to debian-tor via the User directive in torrc.

set -euo pipefail

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: tor-gateway must start as root so Tor can bind to ports < 1024" >&2
  echo "       (Tor will drop to debian-tor internally via torrc User directive)" >&2
  exit 1
fi

# Ensure Tor's data directory is owned by debian-tor
install -d -o debian-tor -g debian-tor -m 700 /var/lib/tor

echo "[tor-gateway] Starting Tor..."
exec tor -f /etc/tor/torrc "$@"
