# ARC — Adaptive Relay Connectivity

ARC is a multipath, carrier-agnostic overlay VPN. A TUN interface gives applications an ordinary IP network. Underneath, one encrypted session runs over any permitted mix of carriers (UDP, TLS/TCP, and experimentally DNS and ICMP) to a relay that forwards traffic to the Internet.

**Status:** pre-alpha. The wire format is provisional (spec 0.2).

## Layout

| Path | Contents |
|---|---|
| `spec/` | Protocol spec, wire registry, fixtures, and their generator |
| `internal/wire` | Packet, frame, and cell codec |
| `internal/crypto` | Noise IK handshake, packet protection, rekeying, replay windows, cookies, reset tokens |
| `internal/reassembly` | Bounded IP datagram reassembly |
| `internal/session` | Client and relay session state machines (sans-IO) |
| `internal/carrier/udp` | UDP carrier with batched I/O |
| `internal/tun` | TUN device and Linux address/route setup |
| `internal/gateway` | Relay address pool, token authorization, routing to sessions |
| `internal/engine` | Event loops that run sessions on real sockets and TUN devices |
| `cmd/arc-client`, `cmd/arc-relay` | The client and relay commands |
| `test/netns` | End-to-end tunnel test in network namespaces |

## Development

```sh
go test -race ./...
go test -run='^$' -fuzz='^FuzzPacket$' -fuzztime=1m ./internal/wire   # also FuzzFrames
go test -run='^$' -bench=. ./internal/...                           # benchmarks

# Regenerate the wire fixtures after a spec change
python3 -m venv .venv && .venv/bin/pip install -r spec/requirements.txt
.venv/bin/python spec/generate_arc_fixtures.py
```

## Running a tunnel (Linux)

```sh
go build -o bin/ ./cmd/...

# Relay host
bin/arc-relay genkey > relay.key
bin/arc-relay pubkey < relay.key          # give this to clients
echo "some-token" > tokens
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE
sudo bin/arc-relay run -listen 0.0.0.0:4433 -network 10.77.0.1/16

# Client host
echo "some-token" > token
sudo bin/arc-client run -relay RELAY_IP:4433 -relay-key RELAY_PUBLIC_KEY -full-tunnel

# Several links at once (e.g. Wi-Fi and cellular): one carrier per interface,
# with flows spread across them, failover, and traffic moved off a link that
# turns lossy (-status 5s logs each path's state)
sudo bin/arc-client run -relay RELAY_IP:4433 -relay-key RELAY_PUBLIC_KEY -full-tunnel -bind wlan0 -bind wwan0

# Where UDP may be blocked, also carry the session over TLS/TCP (used only
# while no UDP path works); the relay runs with -tls-listen 0.0.0.0:443, and
# `arc-relay gencert -hosts ...` makes a certificate for -tls-ca if needed
sudo bin/arc-client run ... -tls RELAY_HOST:443

# Forward error correction is on by default (-fec auto): while a link loses
# 0.5% or more, repair packets let the far end rebuild losses without TCP
# retransmitting; -fec off disables it, -fec always keeps it on

# When every link is lossy, send each packet on two links while the best one
# loses over 1% (doubles traffic while on; "always" duplicates everything)
sudo bin/arc-client run ... -bind wlan0 -bind wwan0 -redundancy auto
```

The end-to-end test builds this setup in three network namespaces:

```sh
sudo test/netns/e2e.sh bin                                   # Linux
docker build -f test/netns/Dockerfile -t arc-e2e . && docker run --rm --privileged arc-e2e   # macOS
```

`test/netns/degraded.sh` runs plain routing, ARC, and WireGuard under netem loss, delay, jitter, and
bandwidth limits, and measures ARC's failover across two links, whether it moves traffic off a lossy
link, and what redundancy does when both links are lossy (`docker run --rm --privileged arc-e2e degraded`).
`test/netns/fec.sh` compares FEC off, auto, and always under uniform and bursty loss, as medians of
repeated runs (`docker run --rm --privileged arc-e2e fec [SECONDS] [REPS]`).
`test/netns/bench.sh` compares ARC's throughput with kernel WireGuard over the same topology
(`docker run --rm --privileged arc-e2e bench` on macOS). Treat its numbers as relative: both ends
share one machine.
