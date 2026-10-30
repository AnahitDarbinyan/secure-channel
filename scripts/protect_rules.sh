#!/bin/bash
# Select which traffic is protected: TCP PC1 -> PC2 to destination port $1.
# Usage: sudo ./scripts/protect_rules.sh [port]      (default 5001)
#        sudo ./scripts/protect_rules.sh clear
# Anything that does not match (return traffic, handshake, other ports)
# is forwarded normally. If a device is not running, matching packets are
# dropped (fail closed), never sent in clear.
set -e
[ "$EUID" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

PORT="${1:-5001}"

clear_rules() {
    for ns in d1 d2; do
        ip netns exec "$ns" iptables -F FORWARD 2>/dev/null || true
    done
}

clear_rules
[ "$PORT" = "clear" ] && { echo "Protection rules removed."; exit 0; }

# Device1 encrypts (queue 2), Device2 decrypts (queue 3)
ip netns exec d1 iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.3.0/24 \
    -p tcp --dport "$PORT" -j NFQUEUE --queue-num 2
ip netns exec d2 iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.3.0/24 \
    -p tcp --dport "$PORT" -j NFQUEUE --queue-num 3

echo "Protecting TCP 10.0.1.0/24 -> 10.0.3.0/24, destination port $PORT"
