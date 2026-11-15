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
| `internal/tun` | TUN device, and address, route and DNS setup on Linux and macOS |
| `internal/gateway` | Relay address pool, token authorization, routing to sessions |
| `internal/engine` | Event loops that run sessions on real sockets and TUN devices |
| `cmd/arc-client`, `cmd/arc-relay` | The client and relay commands |
| `test/netns` | End-to-end tunnel test in network namespaces |

## Development

Use Go 1.26.11 or a newer supported patched release. CI checks reachable
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
echo "lane some-token relay" > tokens      # NAME TOKEN [relay]: see Accounts below
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

# Where the network watches TLS, pose the TLS carrier as a host the network
# permits: -tls-cover presents that name instead of the relay's own, and
# -tls-fingerprint chrome shapes the ClientHello like a browser's (with
# -tls-fragment N, the ClientHello is sent in small TCP segments). With
# -tls-cover, no -tls-ca is needed: ARC's own session authenticates the relay
# underneath. Without it, the relay's certificate is verified as usual. The relay
# runs -tls-camouflage to accept browser-alike carrier connections, and its
# certificate should list the cover name: arc-relay gencert -hosts COVER_HOST
sudo bin/arc-client run ... -tls RELAY_HOST:443 -tls-cover COVER_HOST -tls-fingerprint chrome

# The relay can also present itself as an ordinary HTTPS site: with
# -front-listen 0.0.0.0:443 (instead of -tls-listen), every visitor gets
# cover content (from -front-site, or a minimal page), while the client's
# carrier rides an authenticated HTTP upgrade through it, so an active
# prober sees only a website. The certificate should be publicly valid for
# the domain clients dial; the admission token is the client's ordinary
# -token-file token.
sudo bin/arc-client run ... -front cdn.example.com:443 -tls-fingerprint chrome

# Forward error correction is on by default (-fec auto): while a link loses
# 0.5% or more, repair packets let the far end rebuild losses without TCP
# retransmitting; -fec off disables it, -fec always keeps it on

# On links losing tens of percent, TCP over any tunnel stalls. Split TCP ends
# TCP connections at the client and carries their bytes reliably to the
# relay, which opens the real connection ("auto" splits new connections
# while the link loses 10% or more; the relay declines with -no-split-tcp)
sudo bin/arc-client run ... -split-tcp auto

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

The relay caps authenticated sessions (`-max-sessions 1024`) independently
of pending Noise handshakes (`-max-pending 4096`),
global Noise handshake work (`-handshakes-per-second 256`), per-source UDP-IP
handshake work (`-handshakes-per-source 8`), and pending plus established
TLS connections (`-max-tls-conns 4096`). TLS handshakes have a smaller
separate budget (`-max-tls-handshakes 128`), a ten-second timeout
(`-tls-handshake-timeout`; lossy networks, where TLS is the fallback, need
several seconds), and
at most four pending handshakes per actual TCP peer IP. Total TLS
connections per peer IP are capped by `-max-tls-conns-per-source 64`.
Handshake limits use token buckets
with a burst equal to the rate; tune the per-source rate for clients sharing
a NAT. TLS carriers use distinct synthetic source addresses and share the
global work limit. Failed handshakes consume the same budget as successful attempts.
Refilled source buckets are discarded. At source-table saturation, a new
source must prove reachability with a cookie before replacing the oldest
bucket. A cookie-validated, valid Noise handshake may replace the oldest
unauthenticated session when the pending budget is full; active sessions
are never displaced. Authentication rechecks active capacity before leasing
an address.
FEC decoders cap repair bytes and block metadata independently of source
storage. Path IDs only increase, so a retired path's nonce space is never
reused, and no history of retired paths is kept; a session ends only if
its 32-bit path ID space runs out.

The client resolves a TLS relay hostname once before installing tunnel
routes, then rotates through the cached IP endpoints on reconnect while
still verifying the original TLS hostname. This lets fallback recover when
tunnel DNS is unavailable. If that first lookup fails (DNS not up yet),
the client starts anyway and the TLS carrier retries the lookup with each
connection attempt until one succeeds. Restart the client to refresh endpoints after
the operator changes the relay's DNS records. Managed DNS reconnects with
the same resolver are no-ops; resolver changes update the link in place
and restore the previous resolver on failure. `-dns` and `-dns-mode` are
rejected in split-tunnel mode; configure that mode's DNS externally.

These bounds do not replace operator firewall policy. Static bearer tokens
still require operator rotation/restart for revocation; this pre-alpha does
not provide expiring credentials.

### Accounts

Each line of the relay's `-tokens-file` is a credential of an account:

```
lane    3f9c…   relay
lane    81d2…   relay
friend  c47a…
```

A name may repeat, giving its account several tokens. The relay reads
the file only at startup, so changing it means restarting the relay, which
interrupts every session.

#### Changing accounts while the relay runs

With `-accounts-store`, the relay keeps its accounts in a store instead,
and changes them without restarting
([spec/self-service-accounts.md](spec/self-service-accounts.md)). An empty
store is seeded from `-tokens-file` (each token becomes a device named
`legacy-N`), and the store keeps only hashes of tokens. The store is one
object, replaced whole by conditional writes:

- `s3://BUCKET/KEY`: an S3 object, so accounts outlive the relay's host.
  Credentials and the region (`AWS_REGION`) come from the environment or
  the instance role, which needs `s3:GetObject` and `s3:PutObject` on the
  object and `s3:ListBucket` on the bucket (without it, S3 answers a
  missing object with 403, and the relay will not seed an empty store).
  Turn on versioning, which keeps every generation as history.
- `file:PATH`: a local file, for a relay whose accounts need not survive
  its host.

```sh
arc-relay accounts list
arc-relay accounts add alexei                 # -relay, -max-devices N
arc-relay accounts add-token alexei laptop    # prints the new token once
arc-relay accounts revoke alexei/laptop       # closes its session at once
arc-relay accounts remove alexei
```

The commands talk to the running relay through its control socket
(`-accounts-control`, default `/run/arc-relay`, root only). With the relay
stopped, pass `-store` (the relay's `-accounts-store`) and they change the
store themselves. Either way, a command succeeds only once the store has
the change. If the store does not confirm a write and cannot be read back,
the command says the outcome is unknown (and `add-token` still prints the
token, in case the device was added): run `list` to see.

The store also holds a **writer lease**: the relay authenticates clients
only while it holds it, renewing it every minute (`-accounts-lease`,
default 15 minutes). A relay that cannot renew it, because the store is
unreachable or another relay took it, stops after the lease runs out and
closes its sessions; its clients are told the relay is full and keep
retrying. A clean shutdown releases the lease. After a crash, the relay
restarted with the same `-accounts-control` directory retakes it at once,
proven its own by the lease token it keeps there; any other relay, even one
with the same `-accounts-holder` name, waits for it to expire, or for
`arc-relay accounts takeover`, which you run only when the old relay is
gone: on the waiting relay's host, that relay takes the lease at once
(with no relay running, pass `-store`). `-front-listen` still needs `-tokens-file`.

Clients of one account can reach each other's tunnel addresses; clients of
different accounts never can. (Split TCP never connects a stream to another
client, even within an account.) Only accounts marked `relay` reach the
relay host, where the operator may run services: its tunnel address, and
the addresses of its interfaces (read at startup), whether by IP
forwarding or by split TCP. A bare `TOKEN` line is an account of its own,
named by its line number (`line3`), without relay access; since inserting
a line above it renames it, prefer named accounts. The relay logs each
session's account. All accounts share the relay's exit address.

No account reaches loopback, link-local (cloud metadata services among
them), multicast or broadcast destinations. `-deny PREFIX` (repeatable)
closes networks private to the operator, such as the relay's VPC, to every
account, by IP forwarding and split TCP alike. Split TCP connects from the
relay host itself, so host firewall rules on forwarded traffic do not
cover it; `-deny` does. The relay host's own addresses stay reachable for
`relay` accounts even inside a denied network.

An address that reaches the host without being on one of its interfaces,
such as a cloud provider's public IP mapped by NAT, is not a host address;
if the host serves anything private on it, list it with `-deny`. Where no
account needs the host's other addresses, a host firewall rule such as
`iptables -A INPUT -i arc0 ! -d 10.77.0.1 -j DROP` adds a second line of
defense for IP forwarding (not for split TCP, which only the relay's own
checks cover).

### Diagnostics

When someone else runs a client on a network that interferes with ARC,
the relay's operator can receive that client's diagnostics without asking
for them. The relay accepts uploads with `-diagnostics-dir DIR`; the
client opts in with `-share-diagnostics`:

```sh
sudo bin/arc-relay run ... -diagnostics-dir /var/lib/arc/diagnostics
sudo bin/arc-client run ... -share-diagnostics
```

The client keeps a journal, `journal.jsonl` by default (`-journal FILE`):
its log at debug level, including each carrier's failures (a TLS
handshake reset, a timeout), path quality every ten minutes, and the
version, platform and carriers it runs with. The journal persists across
runs, up to 4 MiB, so a run that never connected is uploaded by the next
one that does. It belongs to the relay whose key the client pins: a client
pointed at a different relay discards what the journal held rather than
send it to another operator. Uploads go over the session 5 s after it
comes up and every ten minutes after; what the relay confirms it stored
leaves the journal. The journal holds addresses (the relay's, and those of
the client's own links as the relay sees them). ARC does not log traffic
or credentials, but the journal is the client's whole debug log: read it
before sharing it anywhere else.

The relay stores each upload as `DIR/ACCOUNT/TIME-ADDRESS.jsonl` and logs
`diagnostics received` with the account. Uploads are client-chosen data
on the relay's disk, so they are bounded: at most 8 MiB per upload, and
64 MiB and 256 uploads per account: each new upload, once stored, deletes
the account's oldest as needed to stay within them (an upload that fails
deletes nothing). One upload runs at a time per client and four per
account, an upload that stalls for two minutes or runs past thirty is
abandoned, and empty uploads are refused. Other files you put in an
account's directory count toward its 64 MiB but are never deleted.
`-journal` without `-share-diagnostics` keeps the journal locally only.

A client that never gets a session up never uploads, so the relay logs
what it sees of attempts, with each client's address:

- `handshake not completed`: a handshake arrived and the relay answered,
  but the client never authenticated. `init_resends` counts how often the
  client resent its first message; it does so only until it hears the
  answer, so resends mean the relay's replies were not reaching it.
  None means nothing after the first message arrived.
- `handshake rejected: unknown token`; `handshake rejected: relay at
  capacity`; `handshake rejected: authorization failed` for a valid token
  refused for another `reason`, such as an exhausted address pool; and
  `handshake failed`, for a client pinning another relay key (or a
  corrupted packet).
- `tls connection failed`, with the `stage` it stopped at: `tcp` (nothing
  arrived), `client_hello` (a ClientHello started but did not finish, or
  did not parse), `after_client_hello` (the relay parsed it but sent
  nothing back), `after_server_hello` (the relay answered and the
  handshake then failed), or `alpn`; with its SNI and ALPN (cut short if
  long), bytes each way and duration. A carrier that ends logs `tls
  carrier closed` likewise.
- `session established` names the TLS carrier's TCP peer, not its
  internal address, and adds `handshake_seconds` and `init_resends`.
- `connections refused by admission limits`, at most once a minute and
  only if any were: handshakes dropped because the relay was full
  (`udp_relay_full`) or over its handshake rate (`udp_rate_limited`), and
  TCP connections closed before TLS because a limit was reached, by
  which limit, with how many sources and the one refused most
  (`tls_top_source`).

These lines are unauthenticated, so they are limited to 60 a minute; the
next line logged counts those dropped as `suppressed`.

The end-to-end test builds this setup in three network namespaces:

```sh
sudo test/netns/e2e.sh bin                                   # Linux
docker build -f test/netns/Dockerfile -t arc-e2e . && docker run --rm --privileged arc-e2e   # macOS
```

`test/netns/accounts.sh` checks account isolation, the relay host's addresses and `-deny` with
two clients and split TCP (`docker run --rm --privileged arc-e2e accounts`).
`test/netns/degraded.sh` runs plain routing, ARC, and WireGuard under netem loss, delay, jitter, and
bandwidth limits, and measures ARC's failover across two links, whether it moves traffic off a lossy
link, and what redundancy does when both links are lossy (`docker run --rm --privileged arc-e2e degraded`).
`test/netns/fec.sh` compares FEC off, auto, and always under uniform and bursty loss, as medians of
repeated runs (`docker run --rm --privileged arc-e2e fec [SECONDS] [REPS]`).
`test/netns/split.sh` compares TCP through ARC with split TCP off and on, from a clean link to 90%
loss (`docker run --rm --privileged arc-e2e split [SECONDS] [REPS]`).
`test/netns/stall.sh` compares TCP downloads through plain routing and ARC while the client's link
stalls periodically, as Wi-Fi does when AWDL takes the radio off-channel, with the access point
holding only a few frames meanwhile (`docker run --rm --privileged arc-e2e stall [SECONDS] [REPS]`).
`test/netns/bench.sh` compares ARC's throughput with kernel WireGuard over the same topology
(`docker run --rm --privileged arc-e2e bench` on macOS). Treat its numbers as relative: both ends
share one machine.

## The client on macOS

The relay runs on Linux; the client also runs on macOS, with the same flags:

```sh
go build -o bin/ ./cmd/arc-client
sudo bin/arc-client run -relay RELAY_IP:4433 -relay-key RELAY_PUBLIC_KEY -full-tunnel -dns 1.1.1.1
```

The interface is the next free `utunN` (`-tun utunN` picks one). macOS has
no socket marks or policy routing, so a full tunnel works differently:

- **Carriers are bound to their interface** (`IP_BOUND_IF`), which routes
  them by that interface's own routes rather than the tunnel's. With no
  `-bind`, the client binds to the default route's interface at startup and
  stays there: if the Mac moves from Wi-Fi to Ethernet, restart it, or pass
  `-bind en0 -bind en7` to use both.
- **Routes** `0.0.0.0/1` and `128.0.0.0/1` go through the tunnel, and IPv6
  is rejected. Directly connected networks keep their more specific
  routes, so unlike on Linux the local network stays reachable outside the
  tunnel. DNS still goes through the tunnel's resolver.
- **DNS** is published to configd's dynamic store as a service that
  overrides the primary one (`-dns-mode scutil`, the default), as VPN
  clients do, and removed on exit. Nothing persistent changes. If the
  client is killed before it can clean up, the next run replaces the
  entry, or remove it with
  `printf 'remove State:/Network/Service/arc/IPv4\nremove State:/Network/Service/arc/DNS\n' | sudo scutil`.

`test/macos/e2e.sh` checks split and full tunnels against a relay in
Docker Desktop.

## License

Copyright (C) 2026 Lane Shetron.

ARC is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License, version 3, as published by
the Free Software Foundation. See [LICENSE](LICENSE) for the full text.

If you run a modified version as a network service, the AGPL requires you to
offer its users the corresponding source code. For other licensing terms,
contact the copyright holder.
