# Secure Inline Communication Channel

Linux prototype of a secure inline channel:

    PC1 --> Device1 --> Device2 --> PC2
           (encrypt)    (decrypt)

Selected TCP/IPv4 packets from PC1 to PC2 are protected between Device1 and
Device2. Only the **TCP payload** is encrypted (AES-256-GCM); the IP and TCP
headers stay as they are. There is no UDP encapsulation and no custom
protocol header.

## How it works

1. **Handshake** (`src/handshake.c`, TCP port 5006, before any data flows):
   Device1 and Device2 run an ephemeral **X25519 Diffie-Hellman** exchange,
   authenticate each other with an HMAC proof over the handshake transcript
   (pre-shared key), and derive the session key with **HKDF-SHA256**
   (fresh random salt each session).
2. **Packet interception**: an `iptables ... -j NFQUEUE` rule selects the
   traffic (TCP, PC1 -> PC2, chosen destination port). `src/device.c` reads
   those packets from the queue.
3. **Device1 (encrypt)** - `pp_encrypt_packet()` in `src/packet_processor.c`:

       before: IP | TCP | payload
       after : IP | TCP | counter(8) | AES-GCM ciphertext | tag(16)

   `tot_len` grows by 24 and the IP and TCP checksums are recalculated.
4. **Device2 (decrypt)** - `pp_decrypt_packet()`: verifies the GCM tag
   (headers are authenticated as AAD), checks the anti-replay window,
   decrypts, restores the original payload and length, recalculates the IP
   and TCP checksums, and forwards the packet to PC2. The restored packet is
   bit-identical to what PC1 sent.

### Unique nonce per packet
The 96-bit GCM nonce is `prefix(4) || counter(8)`. Device1 keeps a 64-bit
counter that starts at 0 for every session and is incremented **before each
use** (even a TCP retransmission gets a new counter). The counter travels in
the packet so Device2 can rebuild the nonce. Because the key is new for every
session (fresh X25519 keys + random salt), a (key, nonce) pair is never
repeated. If the counter would reach 2^64-1 encryption is refused.

### Authenticated headers (AAD)
Source/destination IP, protocol, ports, TCP sequence number, ACK number and
TCP flags are authenticated. TTL and checksums are intentionally excluded
because routers change them (verified by a unit test that decrements TTL).

### Fail closed
If a selected packet cannot be processed (bad tag, replay, malformed,
fragmented, counter exhausted) it is **dropped**, never forwarded in clear.
If a device is down, the NFQUEUE rule drops matching packets.
Packets with an empty TCP payload (SYN, ACK, FIN) carry no data and pass
unchanged, so normal TCP connection handling works.

## Build

    sudo apt install build-essential libssl-dev libnetfilter-queue-dev \
                     iptables iproute2 ethtool tcpdump python3
    make            # builds build/device
    make test       # unit tests (no root needed)
    make e2e        # full end-to-end test in network namespaces (root)

## Run the demo manually

    sudo ./scripts/setup_topology.sh              # namespaces pc1 d1 d2 pc2
    sudo ip netns exec d2 ./build/device --mode decrypt      # terminal 1
    sudo ip netns exec d1 ./build/device --mode encrypt      # terminal 2
    sudo ./scripts/protect_rules.sh 5001                     # protect port 5001
    # terminal 3:  sudo ip netns exec pc2 nc -l 10.0.3.2 5001
    # terminal 4:  echo hello | sudo ip netns exec pc1 nc 10.0.3.2 5001
    sudo ip netns exec d1 tcpdump -A -i veth-d1-out tcp port 5001   # ciphertext

Stop with Ctrl+C. `sudo ./scripts/protect_rules.sh clear` removes the rules.

## Test results

`make test` - unit tests:
* AES-256-GCM against the NIST known-answer vector; every single-bit change
  of counter/ciphertext/tag/AAD/key is rejected
* full packet round trip is bit-identical, IP/TCP checksums validated by an
  independent implementation, headers preserved, no plaintext in the output
* 5000 identical packets -> 5000 distinct, strictly increasing nonces
* replay rejected, reordering tolerated, forged packets never move the window
* fail-closed cases (exhausted counter, fragments, truncated packets,
  plaintext injected on the decrypt side)

`make e2e` - real traffic PC1 -> PC2 through both devices (3 MB, ~2670
protected packets): SHA-256 identical at PC2, plaintext absent on the
Device1-Device2 link, 24 bytes added per packet, forged plaintext packet
rejected by Device2. Output and short captures are in `docs/evidence/`.

## Limitations (prototype)
* Only the PC1 -> PC2 direction is protected (as in the task); return traffic
  (ACKs, replies) is forwarded normally.
* The authentication PSK is hard-coded in `include/session_auth.h`
  (demonstration only - provision it securely in a real deployment).
* One session key per run, no re-keying; IPv4 only; IP fragments are dropped.
* PC1/PC2 interface MTU is set to 1476 so the +24 bytes still fit in 1500.
* `legacy/` holds earlier development stages and is not part of the build.

## Layout
    src/        device.c, handshake.c, packet_processor.c, packet_crypto.c, packet_utils.c
    include/    headers (replay_window.h = anti-replay window)
    tests/unit/ unit tests          scripts/  topology, rules, end-to-end test
    docs/       evidence/           legacy/   earlier development stages
