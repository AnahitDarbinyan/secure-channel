#!/bin/bash
# End-to-end test:  PC1 -> Device1 -> Device2 -> PC2  (network namespaces)
set -u
cd "$(dirname "$0")/.."
[ "$EUID" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
[ -x build/device ] || { echo "Build first: make" >&2; exit 1; }

PORT=5001
OUT=build/e2e
mkdir -p "$OUT"; rm -f "$OUT"/*
PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

cleanup() {
    kill $D1_PID $D2_PID $TCPDUMP_WIRE $TCPDUMP_PC2 2>/dev/null
    wait 2>/dev/null
    for ns in pc1 d1 d2 pc2; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
D1_PID=; D2_PID=; TCPDUMP_WIRE=; TCPDUMP_PC2=

echo "== 1. Topology"
./scripts/setup_topology.sh || exit 1

echo "== 2. Start devices and run the handshake"
ip netns exec d2 ./build/device --mode decrypt > "$OUT/d2.log" 2>&1 & D2_PID=$!
for i in $(seq 50); do grep -q "Waiting for Device1" "$OUT/d2.log" && break; sleep 0.1; done
ip netns exec d1 ./build/device --mode encrypt > "$OUT/d1.log" 2>&1 & D1_PID=$!
for i in $(seq 50); do
    grep -q "Session established" "$OUT/d1.log" && grep -q "Session established" "$OUT/d2.log" && break
    sleep 0.1
done
check "handshake completed on both devices" \
  'grep -q "Session established" $OUT/d1.log && grep -q "Session established" $OUT/d2.log'

echo "== 3. Enable protection and capture"
./scripts/protect_rules.sh $PORT
ip netns exec d1 tcpdump -i veth-d1-out -U -w "$OUT/wire_d1_d2.pcap" tcp port $PORT >/dev/null 2>&1 & TCPDUMP_WIRE=$!
ip netns exec pc2 tcpdump -i veth-pc2   -U -w "$OUT/pc2.pcap"        tcp port $PORT >/dev/null 2>&1 & TCPDUMP_PC2=$!
sleep 1

echo "== 4. Send data PC1 -> PC2"
MARKER="TOP-SECRET-PLAINTEXT-MARKER-12345"
python3 - <<PY
import os
open("$OUT/send.bin","wb").write((b"$MARKER\n")*50 + os.urandom(3*1024*1024))
PY
ip netns exec pc2 python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('10.0.3.2',$PORT)); s.listen(1); s.settimeout(30)
c,_=s.accept(); out=open('$OUT/recv.bin','wb')
while True:
    d=c.recv(65536)
    if not d: break
    out.write(d)
" & RECV=$!
sleep 1
ip netns exec pc1 python3 -c "
import socket
s=socket.create_connection(('10.0.3.2',$PORT),timeout=20)
s.sendall(open('$OUT/send.bin','rb').read()); s.close()
"
wait $RECV
sleep 1
kill $TCPDUMP_WIRE $TCPDUMP_PC2 2>/dev/null; wait $TCPDUMP_WIRE $TCPDUMP_PC2 2>/dev/null

echo "== 5. Verify"
check "PC2 received exactly what PC1 sent (sha256 match)" \
  '[ "$(sha256sum < $OUT/send.bin)" = "$(sha256sum < $OUT/recv.bin)" ]'
check "plaintext NOT visible on the Device1->Device2 link" \
  '! grep -aq "$MARKER" $OUT/wire_d1_d2.pcap'
check "plaintext IS visible at PC2 (restored)" \
  'grep -aq "$MARKER" $OUT/pc2.pcap'
check "Device1 encrypted packets" 'grep -q "^\[ENCRYPT\]" $OUT/d1.log'
check "Device2 verified tags and decrypted packets" 'grep -q "^\[DECRYPT\] tag OK" $OUT/d2.log'
check "no packet was dropped during the normal transfer" '! grep -q "^\[DROP\]" $OUT/d2.log && ! grep -q "^\[DROP\]" $OUT/d1.log'
check "every nonce counter is unique (strictly increasing, no repeats)" \
  '[ "$(grep -o "counter=[0-9]*" $OUT/d1.log | sort | uniq -d | wc -l)" = 0 ]'
MAXWIRE=$(tcpdump -nr $OUT/wire_d1_d2.pcap 2>/dev/null | grep -o "length [0-9]*" | awk '{print $2}' | sort -n | tail -1)
MAXPC2=$(tcpdump -nr $OUT/pc2.pcap 2>/dev/null | grep -o "length [0-9]*" | awk '{print $2}' | sort -n | tail -1)
check "largest TCP payload: ${MAXPC2} bytes at PC2 vs ${MAXWIRE} on the device link (+24 = counter 8 + GCM tag 16)" \
  '[ -n "$MAXWIRE" ] && [ -n "$MAXPC2" ] && [ $((MAXWIRE - MAXPC2)) -eq 24 ]'

echo "== 6. Forged packet injection (plaintext payload straight onto the device link)"
ip netns exec pc2 tcpdump -i veth-pc2 -U -w "$OUT/pc2_forged.pcap" tcp port $PORT >/dev/null 2>&1 & TCPDUMP_PC2=$!
sleep 1
ip netns exec d1 python3 - <<'PY'
import socket, struct
def csum(b):
    if len(b)%2: b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while s>>16: s=(s&0xffff)+(s>>16)
    return (~s)&0xffff
src=socket.inet_aton('10.0.1.2'); dst=socket.inet_aton('10.0.3.2')
payload=b'FORGED-INJECTED-DATA-' + b'x'*40
tcp=struct.pack('!HHIIBBHHH',40000,5001,1,1,5<<4,0x18,1000,0,0)+payload
ph=src+dst+struct.pack('!BBH',0,6,len(tcp))
tcp=tcp[:16]+struct.pack('!H',csum(ph+tcp))+tcp[18:]
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),99,0x4000,64,6,0,src,dst)
ip=ip[:10]+struct.pack('!H',csum(ip))+ip[12:]
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.sendto(ip+tcp,('10.0.2.2',0))
PY
sleep 1
kill $TCPDUMP_PC2 2>/dev/null; wait $TCPDUMP_PC2 2>/dev/null
check "Device2 rejected the forged packet (authentication failed)" \
  'grep -q "AUTHENTICATION FAILED" $OUT/d2.log'
check "forged data never reached PC2" '! grep -aq "FORGED-INJECTED" $OUT/pc2_forged.pcap'

echo
echo "Device1 log (last lines):"; tail -3 "$OUT/d1.log"
echo "Device2 log (last lines):"; tail -3 "$OUT/d2.log"
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "Evidence saved in $OUT/ (wire_d1_d2.pcap = encrypted link, pc2.pcap = restored)"
[ "$FAIL" -eq 0 ]
