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

Use Go 1.26.9 or a newer supported patched release. CI checks reachable
vulnerabilities with govulncheck as well as running the tests.

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
sudo bin/arc-client run -relay RELAY_IP:4433 -relay-key RELAY_PUBLIC_KEY -full-tunnel -dns 1.1.1.1

# Several links at once (e.g. Wi-Fi and cellular): one carrier per interface,
# with flows spread across them, failover, and traffic moved off a link that
# turns lossy (-status 5s logs each path's state)
sudo bin/arc-client run -relay RELAY_IP:4433 -relay-key RELAY_PUBLIC_KEY -full-tunnel -dns 1.1.1.1 -bind wlan0 -bind wwan0

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

Full-tunnel mode requires either an explicit trusted `-dns ADDRESS` or a
resolver supplied by the authenticated relay (`arc-relay run -dns ADDRESS`).
By default the client configures systemd-resolved with `resolvectl` and
restores the interface's DNS settings on exit. It fails if that setup is
unavailable. On hosts with another resolver manager, configure that manager
to use the chosen resolver, then pass `-dns-mode manual -dns ADDRESS`.
The namespace tests use manual mode because they do not run a resolver
service or make DNS queries.

Full-tunnel policy includes LAN destinations, so a LAN resolver cannot
bypass the tunnel via a more-specific main-table route. Only marked
carrier sockets bypass it. Local-network access is available in split
tunnel mode with explicit `-route` prefixes. Existing custom routing rules
with higher priority remain the administrator's responsibility.

The relay caps pending and active sessions together (`-max-sessions 1024`),
global Noise handshake work (`-handshakes-per-second 256`), per-source UDP-IP
handshake work (`-handshakes-per-source 8`), and pending plus established
TLS connections (`-max-tls-conns 4096`). Handshake limits use token buckets
with a burst equal to the rate; tune the per-source rate for clients sharing
a NAT. TLS carriers use distinct synthetic source addresses and share the
global work limit. Failed handshakes consume the same budget as successful attempts.
FEC decoders cap repair bytes and block metadata independently of source
storage. A session reconnects after 4096 allocated path IDs so that retired
nonce spaces are never reused and their history stays bounded.

These bounds do not replace operator firewall policy. Static bearer tokens
still require operator rotation/restart for revocation; this pre-alpha does
not provide expiring credentials or tenant destination isolation.

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

