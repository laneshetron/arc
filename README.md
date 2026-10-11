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

## Development

```sh
go test -race ./...
go test -run='^$' -fuzz='^FuzzPacket$' -fuzztime=1m ./internal/wire   # also FuzzFrames
go test -run='^$' -bench=. ./internal/...                           # benchmarks

# Regenerate the wire fixtures after a spec change
python3 -m venv .venv && .venv/bin/pip install -r spec/requirements.txt
.venv/bin/python spec/generate_arc_fixtures.py
```
