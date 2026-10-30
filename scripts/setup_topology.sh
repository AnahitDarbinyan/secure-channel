#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root (sudo)." >&2
    exit 1
fi

# Remove leftovers from a previous run
for ns in pc1 d1 d2 pc2; do
    ip netns del "$ns" 2>/dev/null || true
done

# Namespaces
for ns in pc1 d1 d2 pc2; do
    ip netns add "$ns"
done

# veth pairs
ip link add veth-pc1 type veth peer name veth-d1-in
ip link add veth-d1-out type veth peer name veth-d2-in
ip link add veth-d2-out type veth peer name veth-pc2

ip link set veth-pc1    netns pc1
ip link set veth-d1-in  netns d1
ip link set veth-d1-out netns d1
ip link set veth-d2-in  netns d2
ip link set veth-d2-out netns d2
ip link set veth-pc2    netns pc2

# Addresses
ip netns exec pc1 ip addr add 10.0.1.2/24 dev veth-pc1
ip netns exec d1  ip addr add 10.0.1.1/24 dev veth-d1-in
ip netns exec d1  ip addr add 10.0.2.1/24 dev veth-d1-out
ip netns exec d2  ip addr add 10.0.2.2/24 dev veth-d2-in
ip netns exec d2  ip addr add 10.0.3.1/24 dev veth-d2-out
ip netns exec pc2 ip addr add 10.0.3.2/24 dev veth-pc2

# MTU: leave room for the 24-byte protection overhead
ip netns exec pc1 ip link set veth-pc1 mtu 1476
ip netns exec pc2 ip link set veth-pc2 mtu 1476

# Bring everything up
ip netns exec pc1 ip link set veth-pc1 up
ip netns exec d1  ip link set veth-d1-in up
ip netns exec d1  ip link set veth-d1-out up
ip netns exec d2  ip link set veth-d2-in up
ip netns exec d2  ip link set veth-d2-out up
ip netns exec pc2 ip link set veth-pc2 up
for ns in pc1 d1 d2 pc2; do ip netns exec "$ns" ip link set lo up; done

# Forwarding on the devices
ip netns exec d1 sysctl -qw net.ipv4.ip_forward=1
ip netns exec d2 sysctl -qw net.ipv4.ip_forward=1

# Routes
ip netns exec pc1 ip route add default via 10.0.1.1
ip netns exec pc2 ip route add default via 10.0.3.1
ip netns exec d1  ip route add 10.0.3.0/24 via 10.0.2.2
ip netns exec d2  ip route add 10.0.1.0/24 via 10.0.2.1

# Disable offloads so NFQUEUE sees real packets with real checksums
off() { ip netns exec "$1" ethtool -K "$2" tx off rx off gso off gro off tso off >/dev/null 2>&1 || true; }
off pc1 veth-pc1
off d1  veth-d1-in
off d1  veth-d1-out
off d2  veth-d2-in
off d2  veth-d2-out
off pc2 veth-pc2

# Connectivity check (before any protection is enabled)
if ip netns exec pc1 ping -c 1 -W 2 10.0.3.2 >/dev/null; then
    echo "Topology set up: pc1 can reach pc2."
else
    echo "Topology created, but pc1 cannot reach pc2. Check routes." >&2
    exit 1
fi