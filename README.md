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
```

The end-to-end test builds this setup in three network namespaces:

```sh
sudo test/netns/e2e.sh bin                                   # Linux
docker build -f test/netns/Dockerfile -t arc-e2e . && docker run --rm --privileged arc-e2e   # macOS
```

`test/netns/bench.sh` compares ARC's throughput with kernel WireGuard over the same topology
(`docker run --rm --privileged arc-e2e bench` on macOS). Treat its numbers as relative: both ends
share one machine.
