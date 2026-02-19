#!/bin/bash
# setup-iptables.sh — Tor transparent proxy + hard killswitch
#
# Called by an init container (runAsUser: 0, NET_ADMIN capability).
# Applies rules to the pod's shared network namespace; they persist for the
# pod's entire lifetime even after the init container exits.
#
# Packet flow for outbound TCP from a blockchain container:
#   1. nat OUTPUT: REDIRECT → 127.0.0.1:9040 (Tor TransPort)
#   2. Tor receives it, resolves via .onion / SOCKS, and creates an outbound
#      connection using the debian-tor UID (allowed by the uid-owner rule).
#   3. filter OUTPUT: allows loopback (the redirected packets), Tor's own
#      outbound, and ESTABLISHED responses. Drops everything else.

set -euo pipefail

TOR_UID=$(id -u debian-tor 2>/dev/null)
if [ -z "${TOR_UID}" ]; then
  echo "ERROR: cannot resolve debian-tor UID — is tor installed?" >&2
  exit 1
fi

TOR_TRANS_PORT=9040
TOR_DNS_PORT=5353

echo "[tor-killswitch] debian-tor UID=${TOR_UID}"

# Flush any pre-existing OUTPUT rules (idempotent)
iptables -t nat -F OUTPUT 2>/dev/null || true
iptables        -F OUTPUT 2>/dev/null || true

# ── NAT table: transparent proxy redirect ────────────────────────────────────

# Let Tor's own traffic escape without redirect (otherwise Tor loops)
iptables -t nat -A OUTPUT -m owner --uid-owner "${TOR_UID}" -j RETURN

# Loopback is local — don't redirect
iptables -t nat -A OUTPUT -o lo -j RETURN

# Redirect DNS (UDP 53) to Tor's DNSPort
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "${TOR_DNS_PORT}"

# Redirect all other TCP SYNs to Tor's TransPort
iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports "${TOR_TRANS_PORT}"

# ── FILTER table: killswitch ─────────────────────────────────────────────────

# Loopback always allowed (includes the REDIRECT-modified packets going to 127.0.0.1:9040)
iptables -A OUTPUT -o lo -j ACCEPT

# Tor process may make real outbound connections
iptables -A OUTPUT -m owner --uid-owner "${TOR_UID}" -j ACCEPT

# Responses to inbound connections (e.g. RPC service hitting the pod) are fine
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# KILLSWITCH: drop all other outbound (UDP non-DNS, any leaked TCP, etc.)
iptables -A OUTPUT -j DROP

echo "[tor-killswitch] Rules applied — all non-Tor outbound traffic is now blocked."
