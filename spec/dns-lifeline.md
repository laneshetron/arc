# ARC — The DNS lifeline

**Status:** draft design. Extends the carrier contract (§16.5, §12 of the
handoff), `network-profiling.md` §6.2 (the `allowlist` and `shutdown`
rows) and §10 (rendezvous), and `freeze-and-udp-ban.md` §4 (what a
posture does with UDP). Nothing here is implemented yet.

## 1. What the lifeline is

Every other ARC carrier needs the client to reach *the relay's address*
with *the relay's packet shape*. The regimes that kill a session outright
are the ones that remove that premise: an allowlist that passes only
approved destinations (a mobile operator's white list, an airline portal
after payment), or a shutdown where everything but the resolver is gone.
Both leave one thing working, because the network cannot function without
it: **DNS resolution through the resolver the network hands out.**

The lifeline has two parts, with different jobs and different failure
modes:

- **The beacon** (§3). One ordinary TXT query to a zone the operator
  publishes, answered by a signed record that says where the relay is
  now: addresses, ports, and cover names. It needs no ARC session, no
  prior contact with the relay, and nothing but a working resolver, and
  it is verified locally against a key the device already holds. Its job
  is rendezvous: relay rotation, address changes, cover-name rotation, and
  the first address a device learns after its enrolled one dies.
- **The carrier** (§4). An ARC path whose packets travel as cells inside
  DNS queries and answers (§16.5). It establishes a real session — Noise
  handshake, AUTH, paths, everything — and then carries control frames
  and, at a rate of a few hundred bytes per second, IP traffic.

Neither is a general-purpose channel. Both are the last rung of the
ladder, and both are shaped so that the cost of using them is paid in
observability rather than in someone else's infrastructure.

### 1.1 Why this is not the DNS tunnel everyone assumes

A DNS tunnel is bulk traffic in label bytes: it is the loudest thing an
entropy detector can see, and it gets a zone blocked for every user of
that zone at once. This design accepts that shape only under two
conditions, and neither is optional:

- The zone belongs to the operator, is delegated to infrastructure the
  operator controls, and is used by ARC users only.
- The volume is bounded by policy (§5.3) at a rate that keeps the zone
  uninteresting: a session that establishes, stays alive, and moves a few
  kilobytes a minute, not a session that streams.

Under those conditions the lifeline is worth its risk. A tunnel that
moves a video is not, and the posture that enables this path never
pretends otherwise.

## 2. Sizing

All numbers below are for a 13-character nonce label (8 random bytes),
`_arc.` before the zone, payload labels of at most 50 characters, and a
255-byte name limit. A cell (§12.1) is 18 bytes of header plus chunk.

### 2.1 Uplink: one cell per query

The question name carries one cell. The room left for the cell depends on
the zone suffix:

| zone | suffix bytes | payload chars | labels | cell | chunk |
|---|---|---|---|---|---|
| `_arc.x.io` | 11 | 225 | 5 | 140 | 122 |
| `_arc.ex.net` | 13 | 223 | 5 | 139 | 121 |
| `_arc.example.net` | 18 | 218 | 5 | 136 | 118 |
| `_arc.relay.example.com` | 24 | 212 | 5 | 132 | 114 |
| `_arc.lifeline.example.org` | 27 | 209 | 5 | 130 | 112 |

A zone suffix of about 20 bytes therefore carries 118-byte chunks: a PING
(37 B), a `PATH_JOIN` (45 B), an `AUTH_RESULT` (65 B), an `AUTH` with a
43-byte token (80 B) and a `HANDSHAKE_RESP` (81 B) each fit in one cell;
`HANDSHAKE_INIT` (122 B) takes 2; a full 1280-byte IP packet (1317 B)
takes 12.

### 2.2 Downlink: one cell per answer

An answer is 12 bytes of header, the question, 12 bytes of answer header,
and a TXT record whose content is `A1:` plus base64url of one cell,
chunked into 255-byte character-strings. Base64 costs 4/3, so the answer
is about 1.4× the cell it carries, and the cell that fits depends on how
long the question name was — which the client chooses, because the same
query bytes can be spent on payload or on padding.

It is also capped independently of the resolver's buffer. The relay's
anti-amplification limit (§14.4: at most 3× the bytes received) is
enforced here **per answer** — an answer may not exceed 3× the query that
asked for it. That is stricter than the per-association rule, needs no
state at the relay, and costs nothing, because a resolver answers one
question at a time. It is also the reason the downlink does not simply
grow with the question.

For zone `_arc.example.net`, uplink cell → question → largest downlink
cell (the answer's size in bytes is in parentheses):

| uplink cell | question name | query | answer ≤ 512 B | EDNS(0) 1232 |
|---|---|---|---|---|
| 26 B | 75 B | 91 B | 124 B | 141 B |
| 37 B (PING) | 94 B | 110 B | 153 B | 169 B |
| **37 B, name padded to 155 B** | **155 B** | **171 B** | **243 B** (512) | 255 B |
| 55 B | 122 B | 138 B | 194 B | 210 B |
| 65 B | 139 B | 155 B | 219 B | 236 B |
| 81 B | 165 B | 181 B | 235 B (512) | 275 B |
| 99 B | 195 B | 211 B | 213 B (512) | 320 B |
| 122 B | 232 B | 248 B | 186 B (512) | 375 B |
| 136 B (full name) | 255 B | 271 B | 168 B (511) | 409 B (846) |

Two different regimes, and the adapter has to know which it is in:

- **With EDNS(0),** the 3× rule binds and the downlink grows
  monotonically with the question: fill the name and get 409 B back.
  Padding cannot do better than filling the name, since both cost the same
  query bytes.
- **Without EDNS(0)** — the common case behind a hotel, airline or ISP
  resolver — the 512-byte answer cap binds for long questions and the 3×
  rule binds for short ones. There is a **maximum in the middle**: a
  37-byte cell in a name padded out to 155 bytes (a 171-byte query) buys
  243 B down, and no question of any length, padded or not, buys more.

So a client draining a downlink backlog sizes its polls to the regime:
full-name queries when the resolver showed it honors EDNS(0), and
mid-sized ones when it did not. A client with uplink to send sizes the
query to the cell it is carrying, since that cell has to fit anyway — and
under the 512-byte regime it pads a short name out to 155 bytes to get the
best answer, which is why the PING row above shows both forms.

That padding is also the reason the non-monotonic table is not a trap: the
adapter computes the best (cell, pad) pair for its zone suffix once at
startup, for each answer budget, and uses it whenever it has nothing
particular to send.

Without EDNS(0), a full-name poll is a 271-byte query and a 511-byte
answer carrying 136 B up and 168 B down. With EDNS(0) 1232, it is a
282-byte query and an 846-byte answer carrying 409 B down.

### 2.3 Rates

A poll is one query and one answer, and a poll is the *only* way anything
moves downlink. Zone `_arc.example.net`, full-name questions, EDNS(0):

| polls/min | interval | up | down | on the wire | |
|---|---|---|---|---|---|
| 6 | 10 s | 13.6 B/s | 40.9 B/s | 0.90 kbit/s | **steady: exactly the keepalive** |
| 12 | 5 s | 27.2 B/s | 81.8 B/s | 1.80 kbit/s | an active small transfer |
| 30 | 2 s | 68.0 B/s | 204.5 B/s | 4.51 kbit/s | **ceiling** |

The steady rate is not a preference, it is the floor: `DefaultKeepalive`
is 10 s, a path silent longer than `keepalive + max(3·PTO, keepalive/2)`
— about 15 s at any realistic RTT (`conn.idleLimit`) — goes `SUSPECT`, and
`DefaultPathTimeout` makes it `DEAD` at 30 s of silence. A DNS path that
is the only path therefore **must** poll at least six times a minute or
kill the session it exists to keep alive. Six is a 10-second interval
against a 15-second threshold, so the margin is 5 s: any poll whose answer
takes longer than that eats into it, which is why a late answer counts as
a pacing failure (§4.3) and not merely as latency.

Six polls a minute is where "steady" comes from, and it costs the uplink
budget accordingly: 136 B every 10 s is about 48 KiB an hour of cell
payload, all of it control when the user is idle (§5.3).

Without EDNS(0), the same questions move 168 B down per poll instead of
409 B, and a mid-sized question does better than a full one (§2.2):
at 6 polls/min, 16.8 B/s down; at 30, 84 B/s.

### 2.4 Establishment

Path 0 carries the handshake, and the session is active once `AUTH_RESULT`
arrives (§14.2), so establishment is the handshake and nothing else:

| step | bytes | cells | direction |
|---|---|---|---|
| `HANDSHAKE_INIT` | 122 | 2 | up |
| `HANDSHAKE_RESP` | 81 | 1 | down |
| `AUTH` (43-byte token) | 80 | 1 | up |
| `AUTH_RESULT` | 65 | 1 | down |

A poll carries one uplink cell and returns one downlink cell, so
establishment is **three polls**: two for the INIT (the relay cannot
answer until both cells reassemble), then one for the AUTH, whose answer
carries `AUTH_RESULT`. No `PATH_CHALLENGE` is needed — `AUTH_RESULT` is
what validates path 0 on the client side.

The time budget is the real constraint. `HandshakeTimeout` is 10 s and
applies to **each phase separately**: the client restarts the whole
handshake if `HANDSHAKE_RESP` has not arrived 10 s after the INIT phase
started, and if `AUTH_RESULT` has not arrived 10 s after that
(`Client.Tick`). So the two INIT cells must both reach the nameserver and
the response must come back within 10 s, on a path whose every step is a
recursive lookup.

That makes the establishment poll rate a requirement, not a knob: at 30
polls/min (2 s apart) the two INIT cells cost 2 s of the 10, leaving 8 s
of resolver latency — enough for a slow ISP resolver, not enough for a
congested one. The adapter therefore polls at the ceiling from the first
INIT, and if establishment fails three times in a row it reports this
path unusable on this network rather than retrying forever inside a
10-second window it cannot meet.

### 2.5 What an IP packet costs

A full-name poll moves 136 B up and 409 B down with EDNS(0), on 1128
bytes of query and answer. Inner IP traffic pays base32, cell headers,
IP-framing and query overhead together, and needs one poll per cell in
each direction. The asymmetry is large and worth knowing:

| inner IP packet | ARC packet | cells | polls up | wire up | overhead up | polls down | wire down | overhead down |
|---|---|---|---|---|---|---|---|---|
| 40 B | 77 B | 1 | 1 | 1128 | 14.6× | 1 | 1128 | 14.6× |
| 100 B | 137 B | 2 | 2 | 2256 | 16.5× | 1 | 1128 | 8.2× |
| 300 B | 337 B | 3 | 3 | 3384 | 10.0× | 1 | 1128 | 3.3× |
| 600 B | 637 B | 6 | 6 | 6768 | 10.6× | 2 | 2256 | 3.5× |
| 1200 B | 1237 B | 11 | 11 | 12408 | 10.0× | 4 | 4512 | 3.6× |

The ratio is per *poll*, not per byte: on the wire both directions carry
about 0.48 bytes of cell per byte of DNS message (0.482 up on base32,
0.483 down on base64 — base64 is cheaper per byte, but the answer's 12-byte
header, question echo and TXT-string framing eat the difference). What
differs by 3× is how much one poll carries: an uplink cell is capped by
the 255-byte name it must fit inside, while a downlink cell is capped by
3× the query. **Uplink is therefore the scarce direction** — not because
base32 is worse, but because a DNS question is 255 bytes and an answer is
not.

So a name lookup — a 100-byte query up and a 300-byte answer down — is
three polls: two up for the query, one down for the answer. At the
6-poll steady rate that is 30 s; at the 30-poll ceiling, but only if
nothing else is competing, 6 s. Messaging, an API call, a status update:
reachable. A web page: not. That is the honest ceiling, and §6.2 of the
profiling design's promise to the user ("full tunnel unavailable") is what
it should say.

## 3. The beacon

### 3.1 Name and record

```
<nonce>._arcb.<beacon-zone>   TXT   "B1:" + base64url(body ‖ signature)
```

`<nonce>` is 13 lowercase no-padding base32 characters over 8 random
bytes, fresh for every query, so no answer is ever served from a cache
and no response can be correlated with another. Any recursive resolver
may relay it; the operator's authoritative server answers it.

`<beacon-zone>` is a zone of its own, not a carrier zone (§3.4); the
sizing examples below use `_arcb.example.net` for brevity, standing for
`_arcb.` plus whatever zone the deployment delegates.

`body`, in field order:

```text
Field                  Size        Notes
version                1           1
flags                  1           bit 0: DNS carrier available
published              4           Unix seconds; the operator's publish time
not_after              4           Unix seconds; when the operator stops vouching
n_relays               1           1..16
relays                 40 × n      each: ipv4:u32, port:u16, udp_port:u16
                                    (0: no UDP carrier), static key[32]
n_names                1           0..16
cover names            1 + len     each: len:u8, then lowercase ASCII, no
                                    trailing dot
n_zones                1           1..2
carrier zones          1 + len     each: len:u8, then the zone a DNS
                                    carrier may use
signature              64          Ed25519 over every preceding byte
```

The signature is domain-separated: it covers the beacon's own query
suffix as a prefix, `"ARC/1 beacon" ‖ u8(len) ‖ suffix ‖ body`, so a
record signed for one beacon name or zone verifies under no other. Without
that, an operator's record could be replayed under a name the censor finds
easier to block, or a second deployment's record could be served for this
one.

`key` is the relay's static public key, so a device that has never
enrolled can pin it from a beacon instead of an invite, and a device that
has enrolled can check that the address it is being moved to belongs to
the relay it trusts.

The signature is over the body, by an Ed25519 **beacon key** whose public
half the client knows out of band: in the profile at enrollment, or
`-lifeline-key`. One beacon key covers a deployment's relays, which is
what makes rotation work — a beacon that could only speak for one relay
could not move a client off a dead one.

Sizes, zone `example.net`, one relay and one cover name and one carrier
zone: body 150 B, TXT content 204 characters in one character-string, and
an unpadded answer of 266 B. With the padding of §3.2 the query is 109 B
and the answer 326 B.

### 3.2 The 3× rule applies here too

An authoritative nameserver that answers a 54-byte question with a
326-byte answer is an amplifier, and one day it will be used as one. The
client **pads its beacon question** so that the answer is at most three
times the query: one extra label (`p` followed by base32 junk) sized to
reach ⌈answer/3⌉ bytes, which for the record above is 59 bytes, taking the
query to 109 B for a 326 B answer — a ratio of 2.99.

The nameserver refuses (`REFUSED`) any beacon answer that would exceed 3×
the query, so the property survives a client that forgets, and the padding
is cheap in exactly the way it matters: it costs the client bytes it would
have spent on nothing, and it costs a reflector nothing to reject.

A beacon therefore fits a 512-byte answer with no EDNS(0):

| deployment | body | query | answer |
|---|---|---|---|
| 1 relay, 1 cover name, 1 zone | 150 B | 109 B | 326 B |
| 2 relays, 1 cover name, 1 zone | 190 B | 136 B | 408 B |
| 2 relays, 2 cover names, 1 zone | 208 B | 148 B | 444 B |
| 2 relays, 2 cover names, 2 zones | 226 B | 160 B | 480 B |
| 3 relays, 1 cover name, 1 zone | 230 B | 163 B | 488 B |

The ceiling is a 242-byte body in a 512-byte answer (query 171 B): three
relays and one cover name, or two relays and two cover names in two
carrier zones. Past that, deployments publish several beacon names
(`b1._arcb`, `b2._arcb`, …) and the client queries them in order until one
verifies; each is signed independently over its own name (§3.1), and a
client that verifies two of them keeps the newer `published`. With EDNS(0)
1232 the ceiling rises to a 600-byte body in a 1230-byte answer (query
410 B), still under the 3× cap — 12 relays and a cover name in one record,
or 4 relays and 16 cover names.

### 3.3 What the client does with it

- **When.** At startup, when a session cannot be established, and hourly.
  Every failed establishment attempt backs off (1, 2, 4, … minutes,
  capped at 30, with jitter) and re-queries. Never per poll, never as a
  heartbeat: the beacon is read-only data and its query rate is not a
  message rate.
- **Verification.** Signature first, then the time window: `not_after`
  must be in the future, and a beacon older than one already accepted (by
  `published`) is discarded, which is what stops a replay of a previous
  rotation from steering the client back. A beacon that fails either check
  is discarded and logged as a warning; there is no trust-on-first-use,
  because a forged beacon is exactly how a client would be steered to an
  adversary's relay, and the client's own Noise handshake would not
  notice — it authenticates whatever key it was told to expect.
- **Precedence.** The device's enrolled relay address is tried first,
  then the beacon's relays in the order listed. A beacon cannot displace
  a working enrolled endpoint; it exists to replace one that is gone.
- **Staleness.** A client keeps the newest beacon it has accepted until
  its `not_after`. Past that, it keeps *using* what it has (nothing has
  changed for the worse in the data) but says so, and re-queries with
  backoff. A beacon with no `not_after` in the future at acceptance is
  refused.
- **Failure.** NXDOMAIN, SERVFAIL, an unsigned answer, a truncated TXT, a
  sinkhole (a wildcard record where a TXT was asked), or three timeouts:
  no beacon this round. The client widens its uncertainty and says so;
  per `network-profiling.md` §8, an update failure never counts as
  confirmation that nothing changed.
- **Rotation.** `names` replaces the cover-name set a `-tls-cover` or
  `-front` carrier presents. It does not replace `-tls-ca` verification:
  the names come from a signed beacon, so they are as trustworthy as the
  configuration, and a certificate that does not cover one is still a
  failure.

### 3.4 Zones must be independent

The beacon zone MUST NOT be the carrier zone, and SHOULD be delegated to
different infrastructure (ideally a different provider). The beacon is
queried through resolvers that reach the operator's nameserver by
recursion, so it survives the relay's addresses being blocked; if the
beacon zone shared infrastructure with the carrier zone, one block would
take away both rendezvous and the path, and the operator would lose the
ability to tell users where to go.

## 4. The carrier

### 4.1 The adapter

The DNS adapter is §16.5 with the cell rules of §12.1 and the numbers of
§2. Against the carrier contract (§16):

```text
Bidirectional:              true  (only while the client polls)
RequestResponseOnly:        true
RequiresCells:              true
MaxPacketSize:              16384 (cells reassemble any packet)
MaxCellSize:                from the zone suffix and the query name limit
SupportsUnsolicitedDownlink: false
HasNativeCongestionControl: false
```

Two consequences of `true` in that block that are easy to get wrong:

- **No MTU probe** (§14.4). The probe pads a PING to 1317 bytes, which
  over 118-byte cells is twelve polls to prove what the cell layer
  already guarantees. (ICMP is different: one echo carries that size, so
  probing it is worth one packet.) A DNS path sets its maximum packet size
  from the cell budget at validation and never probes.
- **No FEC and no redundancy on it** (§11.1, §11.2). A repair symbol is
  another cell; duplicating onto a path that carries 409 bytes per round
  trip spends the whole budget to save a retransmission it would not have
  made. The client keeps constrained paths out of both.

Two things the adapter needs that the current contract does not model,
and both are code changes:

- **A way to say a path is constrained.** `Carrier` is a datagram
  connection plus a `Fallback` flag in the engine (`engine.Carrier`), with
  no `Capabilities` value, and `conn.probe` probes every validated path
  with `c.probeSizes`. Until the session learns that a path is
  constrained, a DNS path spends twelve polls on a probe nobody needs.
- **A poll of its own.** The engine is a push model: `WriteBatch` is
  called only when there are datagrams to send (`flushTransmits`), and a
  session with nothing to say sends nothing —
  but a request/response carrier must *ask* to learn anything, and the case
  that matters most here is an idle session whose relay has a cell queued.
  So the adapter runs its own poll timer goroutine, where the rate limiter,
  the downlink backlog and the establishment ramp live, and the
  engine-facing `ReadBatch`/`WriteBatch` are thin: `WriteBatch` hands the
  poll loop cells to send, and `ReadBatch` returns whatever the last
  answered poll yielded.

### 4.2 Association and address validation

`assoc_id` is chosen when the carrier opens, and is carried on every cell
(§12.1). The relay binds it to a session the first time a fully
reassembled packet carrying it authenticates. Until then its answers
carry `A1:-` and no content for anyone, and its per-resolver budget is
enforced against the unbound-association limits (4 packets, 16 KiB).

A recursive resolver may send one client's queries from many egress
addresses, so nothing is keyed by source address — this is why `assoc_id`
exists, and §12.1's rule against keying reassembly on the source is load
bearing here.

The relay's downlink queue for a bound association is drained one cell
per answer, FIFO, and any answer may carry the next cell even while the
query's own packet is still incomplete. An empty queue answers `A1:-`.

### 4.3 Polling

The client's poll loop is the path's entire clock, and with one exception
it is the adapter's, not the engine's. Rules:

- **Anything to send** (uplink cells queued by `WriteBatch`): one cell per
  query, back to back, up to the rate cap.
- **Downlink backlogged** (the last answer carried a full-size cell):
  poll again as soon as the cap allows.
- **The exception, and the reason the loop is the adapter's:** with
  uplink cells queued the next poll is due at once, but with nothing
  queued the next poll is still due at the keepalive (§2.3). An idle
  session therefore polls by timer, carrying an encrypted `DATA`/`PING`
  cell, never an empty unauthenticated one (§16.5), so the relay can tell
  a live client from a curious resolver — and so a cell the relay queued
  unprompted actually gets collected.
- **Pacing.** A token bucket of `-dns-lifeline-rate` polls per minute
  (default 6 steady, 30 ceiling) and a separate per-resolver bucket, so a
  client cannot spend a shared resolver's patience. On `SERVFAIL`,
  `REFUSED`, `FORMERR`, or an answer later than the interval, the bucket
  drains and the interval stretches — but **never past the keepalive
  floor of §2.3**: the floor is what keeps the session alive, so backing
  off below it is not caution, it is a slower way to close the session.
  What backs off instead is what the poll carries: after three failures in
  a row the poll holds only a PING, and application cells wait.
- **Giving up is explicit.** A path that cannot meet the floor at all —
  answers arriving after the 15 s suspect threshold, five failures in a
  row, or establishment failing three times (§2.4) — is reported unusable
  and closed, rather than kept at a rate that makes the session flap.
- **One answer, one cell.** An answer that carries a cell which does not
  authenticate (a stale cache entry for a repeated name, a rewriting
  middlebox, an off-path injector) is discarded and the poll repeated
  with a fresh nonce. A rejected answer proves nothing about the path;
  only an absence of authenticated progress for the stall timeout does.

### 4.4 Answers are not liveness

`A1:-` is unsigned. It says the query reached the operator's nameserver
and came back, which is a fact about the *path*, not about the *session*.
The session's own PING/ACK exchange is what proves the relay is there;
the client MUST NOT treat an empty answer as session progress, and the
relay MUST NOT count an empty answer as a received packet for path
validation (a `PATH_CHALLENGE` still has to arrive and be answered).

Conversely, a resolver that answers from cache can keep a dead zone
looking alive for the record's TTL. TTL 0 is requested for carrier zones
(§16.5) and the client keeps no state that depends on it being honored.

### 4.5 The path in the session

- **Class.** The DNS path is a *fallback* path in the sense of §16.3: it
  carries flows only while no other healthy path exists, and the primary
  prefers any other path. It is never the primary for control frames
  while something faster is healthy. A resolver round trip costs 50–200 ms
  on a healthy ISP resolver, which a keepalive tolerates, but every
  retransmission and rekey wait multiplies it by the poll interval, so
  nothing latency-sensitive is scheduled onto it while anything else is
  up.
- **Health.** Keepalive, suspect and death follow §14.6 unchanged. The
  idle interval is the keepalive, so a path that is being polled stays
  healthy and one that is not, does not. Shared-outage rules apply: if
  every path is silent, the DNS path is kept too.
- **Rate.** The scheduler's per-path rate cap (§15.2 item 1) is the poll
  budget expressed in bytes: 136 B per poll up, 409 B down at the
  ceiling, so the path's measurable capacity is under 100 B/s each way.
  A "path that measures" 68 B/s must not receive a flow that will only
  stall in it, which is what §15.2 item 6 (slow-path policy) already
  says — and here it is not a preference but the only honest reading of
  the numbers.
- **Streams.** No split TCP over a constrained carrier, and `-split-tcp`
  is refused when the DNS path is the only carrier: a stream terminated at
  the client only to be carried at under 100 B/s is worse for the user
  than the connection failing, and split TCP under a censorship posture is
  refused on TLS-borne carriers anyway (`network-profiling.md` §6.2).

## 5. Policy

### 5.1 When the client opens it

Never by default. Two ways in:

- `-dns-lifeline ZONE` — operator or user explicitly enables the carrier
  for `ZONE`; combined with `-lifeline-beacon ZONE` (or a profile that
  carries both) it also enables rendezvous.
- **Posture-driven.** Under `network-profiling.md` §6.2, `regime =
  allowlist` or `shutdown` selects it automatically, but only when the
  posture was itself opted into (`-allowlist`, `-censorship`), matching
  the rule for every camouflage behaviour.

The reverse is a harder rule: the client closes the carrier and stops
polling when (a) any other validated path exists and the profile is not
`allowlist`/`shutdown`, or (b) the user turns it off. A lifeline that
keeps running when it is not needed is a beacon announcing "this device
is here, right now" to every resolver on the path.

### 5.2 Which resolver

The client uses the resolver the network gave it — captured from the
system configuration *before* the tunnel is installed, and pinned, like
every other carrier socket, outside the TUN routing loop
(`network-profiling.md` §3.2). That is deliberate: under an allowlist,
the permitted resolver is the permitted infrastructure, and using it is
the least conspicuous choice available. `-dns-lifeline-resolver ADDR`
overrides it. The path never resolves its own names through the tunnel
(§17.3).

### 5.3 Budgets

Three independent caps, all mandatory:

- **Client to resolver:** `-dns-lifeline-rate` polls/min (6 steady, 30
  ceiling), and no more than `-dns-lifeline-bytes` (default 256 KiB) of
  cell payload per hour, after which the path carries control only:
  keepalives and ACKs continue at the 6/min floor, and every other frame
  waits for the window to roll over or the path to be closed. Control
  cannot be throttled further without killing the session (§2.3). The
  two caps are close to each other by design — 6/min is 48 KiB/h and the
  30/min ceiling is 239 KiB/h, so the byte budget binds only for a client
  running near its ceiling for an hour.
- **Relay, per client:** the same, enforced at the authoritative server
  against the bound association, answering `A1:-` to anything over.
- **Relay, per resolver and per zone:** a query budget per source
  address, so a resolver being used by many clients is not driven into
  throttling everyone. Over budget, the nameserver answers `REFUSED` for
  a cooldown and the client backs off; it is never worth hammering a
  shared resolver, and §16.5 already forbids pretending otherwise.

### 5.4 What may ride it

- **Control, always.** Handshake, AUTH, path validation, keepalives,
  ACKs, `CLOSE`, `PATH_ABANDON`.
- **IP traffic, yes, under budget.** There is no protocol reason to
  exclude it and one good reason to include it: the first thing a user
  needs on a captive or allowlisted network is a name resolved to an
  address, and if ARC will not carry that query, the tunnel is up and
  useless. Application DNS therefore gets a reserved slice of the budget
  (the first 4 KiB/hour of downlink, say) ahead of any other flow.
- **Everything else, subject to §15.2 item 6.** A flow is placed here
  only when nothing else is validated. A `TCP_MSS`-shaped request to a
  plain-HTTP endpoint is the largest thing that plausibly completes: it
  costs 10× its bytes and a few seconds per round trip.
- **The user is told.** `regime = allowlist` and `shutdown` both surface
  a status line ("lifeline only: full tunnel unavailable") and the
  journal records the regime, the poll rate and the budget remaining.
  Silently degrading to a few hundred bytes a second would read as a
  broken client.

## 6. Testing

`test/netns/dns.sh` (Linux, like its neighbours) builds an authoritative
responder and a censor inline, and asserts behavior end to end. The
responder is a small Go binary in `test/`; it implements the zone of §4
and the beacon of §3, and it *refuses* any answer above 3× its query, so
the amplification rule is tested rather than trusted.

| Scenario | Assertion |
|---|---|
| Everything but DNS blocked (`iptables` default drop, resolver allowed) | A session establishes over the DNS path alone inside one handshake attempt (10 s per phase), and a ping through the tunnel gets its reply within two polls |
| Beacon queried cold, no session possible | The client learns endpoints and cover names from a signed record and logs the regime |
| Beacon forged (signature flipped), replayed past `not_after`, sinkholed by a wildcard | Each is rejected and logged; the client falls back to its enrolled relay |
| Beacon answer above 3× the query | The nameserver refuses it; a client that stops padding gets no beacon and says so |
| Full-length uplink cells against a 512-byte answer budget | The downlink cell is 168 B, not the 243 B a padded short query gets — a client that fills the name loses downlink — and no answer exceeds 3× its query |
| Resolver rewriting TXT content / truncating / caching stale cells | Cells that do not authenticate are discarded; the path is not declared dead until the stall timeout |
| Resolver returning `SERVFAIL` at 20 polls/min | The path keeps the 6/min floor with PING-only polls, sheds application cells, and either recovers or is reported unusable — it never backs off below the floor |
| A faster path available | The DNS path stops polling within one idle interval and carries no flows |
| Budget exhausted (256 KiB) | The path drops to control only at the 6/min keepalive floor, keeps the session alive, and reports it |
| 300-byte application DNS answer through the tunnel | Completes in three polls (two up, one down); the journal records the wire cost |

The responder's own assertions replace what a lab DNS zone would
otherwise take days to schedule: `test/netns/dns.sh` needs no registrar,
no delegation, and no internet.

## 7. Staging

1. **Beacon only.** Responder plus client verification, no carrier. This
   delivers rendezvous, which `network-profiling.md` §10 defers, and is
   useful on its own: a device whose enrolled relay address died can
   learn the new one with one ordinary query.
2. **Uplink carrier.** Cells up, `A1:-` answers, poll loop and pacing.
   Exit: a session establishes over DNS alone and holds for 10 minutes
   with its path never going `SUSPECT`.
3. **Downlink carrier.** One cell per answer, backlog polling, and
   application DNS as the first IP flow. Exit: a name lookup through the
   tunnel completes in three polls.
4. **Postures and budgets.** `allowlist`/`shutdown` regime selection,
   byte budgets, the status line, and `dns.sh` in CI.

No wire changes at any stage: the lifeline uses `CELL` (§12.1) and
`TXT` unchanged. It needs no new frame type, no new feature bit, and no
relay-side protocol negotiation — only a responder, a client adapter,
and the policy above.

## 8. Deferred

- **An A/AAAA-only beacon.** Some allowlists pass only address queries.
  A beacon could be encoded across four A records (4 bytes each per
  query, one relay per name, round-robin by index) without TXT at all.
  Deferred until a field report shows TXT is filtered where A is not.
- **Several cells per answer.** EDNS(0) 4096 fits roughly 2.8 KB of cell
  in one answer, which would cut the poll count for a downlink burst by
  6×. It also makes the answer an amplifier worth abusing and a shape
  worth blocking, and it depends on a resolver honoring the client's
  buffer size. Revisit if any deployment's resolver forwards 4096-byte
  answers intact.
- **DoT/DoH as the transport.** Encrypting the query hides the label
  entropy from the resolver's path but not from the endpoints; it also
  turns the carrier into HTTPS, which the front carrier (§16.4) already
  does better. Deferred, and probably never.
- **Beacon over other out-of-band channels.** A signed record of the same
  body could ride an app-store listing, a static HTTPS page, an
  email auto-responder, or a package registry. The body and the
  verification rule of §3.3 are channel-independent; only the reader
  changes. This is the "application-layer lifeline" adapter of
  `network-profiling.md` §10, and the beacon format is deliberately
  shaped to be its smallest instance.
- **Rendezvous privacy.** Today anyone who knows a beacon name can read
  the record, which means a censor can too, and can therefore enumerate
  the operator's address pool. Encrypting the body to the deployment's
  enrolled devices (`-lifeline-key` becomes a shared secret, the beacon
  key the AEAD's recipient) would remove that; it also means one leak
  compromises every device's view, and it makes bootstrap harder.
  Deferred with the tradeoff stated.
- **ICMP beside it.** §16.6 is the sibling carrier with the same shape
  and a better MTU. When the lifeline exists, ICMP becomes a second
  adapter over the same poll loop and budget machinery; the client's
  choice between them belongs to the profiler's regime, not to the
  adapter.
