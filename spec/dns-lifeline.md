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
  kilobytes a minute (§2.3: 2.4 KiB/min down at the steady rate, 12 at
  the ceiling), not a session that streams.

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
43-byte token (80 B) and a `HANDSHAKE_RESP` (81 B) each fit in one cell,
and `HANDSHAKE_INIT` (122 B) takes 2. A full 1280-byte IP packet would
take 12 cells, which is why it is never sent as one packet on this path:
§2.4 caps the packet size so that every packet completes inside the
reassembly window.

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

#### 2.2.1 The question grammar, and how padding stays decodable

§16.5 says the labels between the nonce and the suffix are the base32 of
exactly one cell, and a cell's chunk length is inferred from the bytes
left over — so a padded name is ambiguous unless the padding is marked.
It is, by the alphabet: base32 (RFC 4648) has no `0` or `1`, so a label
beginning with `0` **cannot** be cell data. That is the grammar:

```text
<nonce>.<b32 cell labels>.[0<padding>...]._arc.<zone>
```

- `<nonce>`: 13 lowercase base32 characters (8 random bytes).
- cell labels: lowercase base32 of exactly one cell, each at most 50
  characters, as §16.5 already specifies.
- zero or more padding labels: `0` followed by 1–62 base32 characters.
  A decoder MUST skip every label whose first character is `0`, and MUST
  reject a `0` label of length 1 or above 63. The nameserver emits them;
  the relay ignores them.
- Because a cell's chunk length is `cell_len − 18` and `cell_len` is
  `⌊5·chars/8⌋`, the decoder recovers the chunk boundary exactly, with no
  padding involved: 60 chars → 37 B, 189 → 118 B, 218 → 136 B. Padding
  rides entirely outside the cell, so a padded name decodes to one cell by
  the same rule an unpadded one does.

The upstream direction therefore has a small vocabulary of names rather
than one, and a golden fixture must round-trip a *fragmented* cell with
padding present: two cells of one `HANDSHAKE_INIT`, the first padded to
155 bytes of name and the second not.

#### 2.2.2 The table

For zone `_arc.example.net`, cell size → question → largest downlink cell
(the answer's size in bytes is in parentheses). A packet of *n* bytes is
carried in a cell of *n*+18:

| cell | packet it carries | question name | query | answer ≤ 512 B | EDNS(0) 1232 |
|---|---|---|---|---|---|
| 26 B | 8 B | 75 B | 91 B | 124 B | 141 B |
| 37 B | 19 B | 94 B | 110 B | 153 B | 169 B |
| **55 B (+32 B pad)** | **37 B (a PING)** | **155 B** | **171 B** | **243 B** (512) | 260 B |
| 55 B | 37 B | 122 B | 138 B | 194 B | 210 B |
| 65 B | 47 B | 139 B | 155 B | 219 B | 236 B |
| 81 B | 63 B | 165 B | 181 B | 235 B | 275 B |
| 99 B | 81 B | 195 B | 211 B | 213 B | 320 B |
| 122 B | 104 B | 232 B | 248 B | 186 B | 375 B |
| 136 B | 118 B (full name) | 255 B | 271 B | 168 B (511) | 409 B (846) |

Two different regimes, and the adapter has to know which it is in:

- **With EDNS(0),** the 3× rule binds and the downlink grows
  monotonically with the question: fill the name and get 409 B back.
  Padding cannot do better than filling the name, since both cost the same
  query bytes.
- **Without EDNS(0)** — the common case behind a hotel, airline or ISP
  resolver — the 512-byte answer cap binds for long questions and the 3×
  rule binds for short ones. There is a **maximum in the middle**: a
  37-byte PING in a name padded to 155 bytes (a 171-byte query) buys 243 B
  down, and no question of any length, padded or not, buys more.

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
moves downlink. Zone `_arc.example.net`, full-cell questions, EDNS(0):

| polls/min | interval | up | down | on the wire | |
|---|---|---|---|---|---|
| 6 | 10 s | 11.8 B/s | 40.9 B/s | 0.90 kbit/s | **steady: exactly the keepalive** |
| 12 | 5 s | 23.6 B/s | 81.8 B/s | 1.80 kbit/s | an active small transfer |
| 30 | 2 s | 59.0 B/s | 204.5 B/s | 4.51 kbit/s | **ceiling** |

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
409 B, and a mid-sized question does better than a full one (§2.2.2):
at 6 polls/min, 16.8 B/s down; at 30, 84 B/s.

### 2.4 A packet must finish inside the reassembly window

Cell reassembly expires incomplete packets on a timer (§12.1: 10 s for a
bound association), and this path delivers **one cell per poll**. Those
two facts collide, and the collision decides how large a packet this path
may carry:

| cells | packet | IP payload | spans, at 30/min | at 6/min |
|---|---|---|---|---|
| 2 | 236 B | 199 B | 2 s | 10 s |
| 3 | 354 B | 317 B | 4 s | 20 s |
| 6 | 708 B | 671 B | 10 s | 50 s |
| 12 | 1416 B | 1379 B | 22 s | 110 s |

Under the existing 10-second expiry a sustained 6/min session could never
send a packet of more than **two cells**, and even at the ceiling it would
be capped at six. A full 1317-byte `DATA` packet (12 cells) takes 22 s at
the ceiling and 110 s at steady state: it can never be reassembled. The
path would establish — the handshake's largest packet is
`HANDSHAKE_INIT` at 122 B, two cells — and then fail to carry anything
larger than 317 bytes.

**Rule.** The DNS adapter sets its own reassembly expiry, and the session
respects a path-specific maximum packet size:

- **Expiry 60 s** for DNS associations, replacing the 10 s of §12.1 for
  this carrier only. It is stated per-carrier because it is a property of
  the pacing, not of cells in general: an ICMP adapter carrying a cell per
  echo needs no such allowance.
- **`max_packet` 472 B** (4 cells, spanning 30 s at the steady rate) when
  the path first validates, raised to **708 B** (6 cells, 50 s) once a
  session has held the steady rate for a minute without a stall. Both stay
  under the 60 s expiry with margin; a 7-cell packet would span exactly
  60 s and is deliberately out of reach. `session.path.maxPacket` already
  exists and the scheduler fragments above it (`conn.sendOn` →
  `IP_FRAGMENT`), so a 1280-byte IP packet becomes four fragments of
  438 B at first (four cells each), then two of 674 and 636 bytes.
- The relay reassembles with the same expiry for a bound association, and
  **must not** raise it further: 60 s is already six poll intervals of
  slack at the ceiling, and a longer window is a longer time to hold
  attacker-chosen bytes.

The margin is the point. A path whose pacing degrades past the steady rate
— a resolver that starts answering in 3 s instead of 10 — pushes a pending
packet past the expiry and loses it, which is correct: the cell layer is
telling the session that the path is no longer fast enough to carry
objects of that size. Recovery is the ordinary stall recovery of §14.6,
not a reassembly special case.

This is the one place the lifeline changes a §12.1 constant rather than
just its own pacing, and it needs a test that fails on the 10 s value:
establish, then send a 472-byte packet at 6/min and assert it reassembles.

### 2.5 Establishment

Path 0 carries the handshake, and the session is active once `AUTH_RESULT`
arrives (§14.2), so establishment is the handshake and nothing else:

| step | bytes | cells | direction |
|---|---|---|---|
| `HANDSHAKE_INIT` | 122 | 2 | up |
| `HANDSHAKE_RESP` | 81 | 1 | down |
| `AUTH` (43-byte token) | 80 | 1 | up |
| `AUTH_RESULT` | 65 | 1 | down |

A poll carries one uplink cell and returns one downlink cell, so
establishment is **three polls** when the relay accepts the first INIT,
and **five** when cookies are required (§4.2.2) — the case that matters,
since a DNS listener should set `AlwaysRequireCookie`. No
`PATH_CHALLENGE` is needed either way: `AUTH_RESULT` is what validates
path 0 on the client side.

The time budget is the real constraint. `HandshakeTimeout` is 10 s and
applies to **each phase separately**: the client restarts the whole
handshake if `HANDSHAKE_RESP` has not arrived 10 s after the INIT phase
started, and if `AUTH_RESULT` has not arrived 10 s after that
(`Client.Tick`). So with cookies the four INIT-phase polls must fit in
10 s, on a path whose every step is a recursive lookup.

That makes the establishment poll rate a requirement, not a knob: at 30
polls/min (2 s apart) the four INIT polls cost 6 s of the 10, leaving 4 s
of resolver latency for each of four recursions — enough for a slow ISP
resolver, not enough for a congested one. The adapter therefore polls at
the ceiling from the first INIT, and if establishment fails three times
in a row it reports this path unusable on this network rather than
retrying forever inside a 10-second window it cannot meet.

### 2.6 What an IP packet costs

A full-name poll moves 136 B up and 409 B down with EDNS(0), on 1128
bytes of query and answer. Inner IP traffic pays base32, cell headers,
IP-framing and query overhead together, and needs one poll per cell in
each direction. The asymmetry is large and worth knowing:

| inner IP packet | ARC packet | cells up | polls up | wire up | × | polls down | wire down | × |
|---|---|---|---|---|---|---|---|---|
| 40 B | 77 B | 1 | 1 | 1128 | 28.2× | 1 | 1128 | 28.2× |
| 100 B | 137 B | 2 | 2 | 2256 | 22.6× | 1 | 1128 | 11.3× |
| 300 B | 337 B | 3 | 3 | 3384 | 11.3× | 1 | 1128 | 3.8× |
| 600 B | 637 B | 6 | 6 | 6768 | 11.3× | 2 | 2256 | 3.8× |
| 1200 B | 1237 B | 11 | 11 | 12408 | 10.3× | 4 | 4512 | 3.8× |

The small-packet rows are the worst and the ones a user will meet first: a
40-byte packet costs a whole 1128-byte poll in either direction. That is
why §5.4 says this path carries application DNS and little else — a
lookup's *answer* is the payload, and it is the only common flow whose
size is worth the envelope.

Cells are counted after §2.4's fragmentation, at `max_packet` 708 (the
value after the first minute). At the initial 472 a 600-byte packet takes
two fragments rather than one, a 1200-byte one three rather than two, and
a 1280-byte one four (13 cells rather than 12): each fragment pays 15
bytes of `IP_FRAGMENT` header. Fragmentation costs a few percent, not
multiples, which is why §2.4 accepts it rather than lowering the TUN MTU
for this path.

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

`<beacon-zone>` is a zone of its own, not a carrier zone (§3.6); the
sizing examples below use `_arcb.example.net` for brevity, standing for
`_arcb.` plus whatever zone the deployment delegates.

`body`, in field order. This grammar is frozen: §3.2's limits are derived
from it, so a field added here invalidates them.

```text
Field                  Size        Notes
version                1           1
flags                  1           bit 0: DNS carrier available
published              4           Unix seconds; the operator's publish time
not_after              4           Unix seconds; when the operator stops vouching
n_relays               1           1..4
relays                 38 + eps × n
  ipv4                 4
  key                  32          the relay's static public key
  n_endpoints          1           1..3
  endpoints            3 + n      each: kind:u8 (0 udp, 1 tls, 2 front),
                                    port:u16, then for front only
                                    len:u8 + domain (1..253, lowercase)
n_names                1           0..4
cover names            1 + len     each: len:u8, then lowercase ASCII, no
                                    trailing dot
n_zones                1           1..2
carrier zones          1 + len     each: len:u8, then the zone a DNS
                                    carrier may use
signature              64          Ed25519 over every preceding byte
```

`kind` is what §3.5 requires and my earlier table lacked: two readers
could not otherwise tell which transport to dial from the same bytes. A
`front` endpoint carries its domain because the client must present it as
the cover name, and it is not derivable from the beacon's own name.

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

Sizes, zone `example.net`, one relay with one `tls` and one `udp`
endpoint, one cover name and one carrier zone: body 153 B, TXT content
208 characters in one character-string, and an answer of 492 B against a
query of 271 B. That is the only shape that fits a 512-byte answer without
EDNS(0) (§3.2).

### 3.2 The cold-start query is fixed, and the 3× rule binds it

Two constraints meet on the first query, and one of them makes the other
binding:

- **A name is at most 255 bytes**, so a query is at most 271 bytes
  without EDNS(0) (12 header + 255 name + 4 type/class) and 282 with a
  bare OPT record. A 410-byte query does not exist; RFC 1035 §2.3.4 caps
  the name, and nothing the client sends can exceed it.
- **The answer is at most 3× the query**, so the largest possible beacon
  answer is 813 B without EDNS(0) and 846 B with it.

A cold client also cannot size its query to a record it has not fetched,
and a rotation can grow the record. So the beacon has exactly **two
query profiles**, and the client tries them in order:

| profile | name | query | answer cap | max body |
|---|---|---|---|---|
| bootstrap | padded to 255 bytes | 271 B | 512 B (≤ 3×) | **168 B** |
| bootstrap + EDNS(0) | padded to 255 bytes | 282 B | 845 B (≤ 3×) | **408 B** |

Padding is by the §2.2.1 grammar, with `0`-labelled labels: the beacon
zone leaves 222 bytes of room under `_arcb.example.net`, so it is three
labels of at most 63. The client always sends the *bootstrap* profile
first with its longest name, because that maximizes the answer under any
resolver's buffer; if the answer is truncated or the authority signals a
larger record, it retries once with EDNS(0) 1232 and never sizes a query
to the record it expects.

The authority enforces the same bound: it refuses (`REFUSED`) any answer
that would exceed 3× the query it received, measured on the wire. That
survives a client that forgets to pad, and costs a reflector nothing to
reject.

**Publication limits, derived from the frozen grammar of §3.1.** Each
relay entry is `ipv4 + key[32] + n_endpoints + endpoints`, and the 32-byte
key is irreducible: it is what lets a device that has never enrolled pin a
relay. Every row below has exactly one carrier zone, as the grammar
requires — my earlier table listed "0 zones" rows, which are not legal
records, and claimed a 177-byte row fitted a 168-byte limit.

| record | body | 512-byte profile | EDNS(0) |
|---|---|---|---|
| 1 relay, `tls`+`udp`, 1 cover name, 1 zone | 153 B | **yes** | yes |
| 1 relay, `tls`+`udp`+`front`, 1 name, 1 zone | 172 B | no | yes |
| 2 relays, `tls`+`udp`, 1 cover name, 1 zone | 196 B | no | yes |
| 2 relays, `tls`+`udp`, no cover names, 1 zone | 180 B | no | yes |
| 3 relays, `tls`+`udp`, no cover names, 1 zone | 223 B | no | yes |

**So the 512-byte profile carries exactly one relay.** That is the honest
limit and it is a real constraint, since many hotel and airline resolvers
send no EDNS(0). Two relays fit only with EDNS(0) — 408 body bytes are
available there, which is about four relays with one endpoint each.

The consequence for the design is not a footnote: **rotation cannot be
expressed in a one-relay record.** §3.5 therefore says a deployment that
must rotate publishes two beacon names (`b1._arcb`, `b2._arcb`), each
carrying one relay, and the client queries them in order until one
verifies. That is a strict improvement over a single two-relay record: it
works on the resolvers that send no EDNS(0), and it lets the operator
retire one name without rewriting the other. Each name is signed
independently over its own suffix (§3.1), so a record cannot be moved
between them.

A front endpoint costs 1 + 2 + 1 + len(domain) bytes per relay, which is
why `front` usually pushes a record over 168. The front's domain is needed
because the client must present it as the cover name, and it is not
derivable from the beacon's own name.

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
  its `not_after`, and §3.4 governs what that expires: an existing session
  continues, a beacon-only key stops being usable for a *new* connection,
  and an independently enrolled pin is unaffected. Before `not_after` the
  client re-queries with backoff but keeps dialing what it has; past it,
  it stops opening new sessions on beacon-only relays and says so. A
  beacon whose `not_after` is not in the future at acceptance is refused
  outright.
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

### 3.4 What `not_after` does and does not retire

`not_after` is the time the operator stops vouching for the record, and a
client that keeps dialing a retired relay key indefinitely has quietly
turned a rotation into a vulnerability. Three different things must not
be conflated, so this section separates them:

- **An existing session.** It continues. A session is bound to a relay
  key and a Noise state; `not_after` says nothing about whether the peers
  already talking to each other may keep doing so. Closing live sessions
  on a beacon's schedule would make rotation a self-inflicted outage.
- **A relay learned only from the beacon.** These keys **expire** for new
  connections at `not_after`. Past it the client MAY still use what it
  learned to *reach* an existing session, and MUST NOT use it to start a
  new one unless its own enrollment independently pins that relay.
- **An independently enrolled relay.** Its pin comes from the invite, not
  the beacon, so it stays dialable forever regardless of any beacon. That
  is the only reason a beacon outage cannot lock a device out.

**The rollback watermark.** The client persists the newest `published` it
has accepted, with the beacon name it came from, alongside the profile.
A beacon older than that watermark is refused even if it verifies and its
`not_after` is still in the future — otherwise a restart, or a second
device on the same profile directory, would reopen the window in which
the operator's *previous* rotation is still valid. The watermark is
written before the beacon's relays are adopted, so a crash mid-adoption
leaves a client that refuses the old record rather than one that accepts
both.

### 3.5 Whom the beacon can actually point at

A signed address and a pinned key tell the client whom to authenticate;
they do not provision the device there. This is the operational hole in
rotation, and it has two independent halves:

- **The accounts store is the authority.** A relay with `-accounts-store`
  authenticates only while it holds the store's **writer lease**
  (`accounts.Writer.Serving`), so a standby listed in a beacon is
  reachable and trusted yet refuses credentials until the current holder's
  lease expires or it takes over (`arc-relay accounts takeover`). A
  beacon that lists a standby without saying so is a beacon that points
  at a refusing relay.
- **The front is not store-backed.** `-front-listen` requires
  `-tokens-file` and admits by **plaintext token** (the `Authorization:
  Bearer` header), which an `-accounts-store` deployment does not keep —
  `main.go` refuses the combination outright. So a device holding only an
  enrolled token can use a beacon-listed **`-tls`** endpoint and cannot
  use a beacon-listed **front**, unless the operator provisions a matching
  plaintext token for it.

Both are operator prerequisites, not client behaviour, so the spec states
them as such:

- **The record distinguishes endpoint kinds**, per the frozen grammar in
  §3.1: `kind` is `udp`, `tls` or `front` for each endpoint, so two
  readers cannot disagree about which transport to dial. A `front` entry
  also carries its domain, and a client will not try a front for a device
  whose profile has no front token.
- Rotation requires that **every listed relay either serve the same store
  or be the acknowledged holder of its lease**. A deployment rotating
  between two hosts sharing one S3 store satisfies this; one rotating to a
  host with its own `-tokens-file` does not, and the beacon cannot express
  the difference — so the operator must list only relays that are actually
  serving.
- **Rotation uses two beacon names, not two relays in one record.** §3.2
  derives that a 512-byte answer holds exactly one relay with a key, so
  the rotating deployment publishes `b1._arcb` and `b2._arcb`, each with
  one relay, and flips which one is current. Two names is strictly better
  here than a two-relay record that many resolvers cannot even return: it
  works without EDNS(0), and retiring a relay means republishing one name
  while the other keeps a resolvable answer.
- **The staging test rotates for real:** enroll a device, stand up a
  second relay on the same store, publish a beacon naming only the second,
  and assert the device establishes a **new session on the replacement**
  with its existing credential and no operator action. That test is what
  turns "rotation" from a claim into a property.

### 3.6 Zones must be independent

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
reassembled packet carrying it authenticates. A recursive resolver may
send one client's queries from many egress addresses, so nothing is keyed
by source address — this is why `assoc_id` exists, and §12.1's rule
against keying reassembly on the source is load bearing here.

#### 4.2.1 The peer identity: a synthetic address, not the resolver

Cookies are computed over `src_ip ‖ u16 src_port ‖ sender_cid`
(`crypto.ComputeCookie`), and the relay verifies them against the `from`
address each packet arrived from. On UDP that is a client's socket and
stable for a session. **On a DNS path it is the resolver, and the resolver
changes it.** A recursive resolver may send successive lookups from
different source ports (`dig +tries` against a pool), and — since nothing
here is keyed on source — from different egress addresses too. A cookie
issued for poll 2 would fail at poll 3, and with
`AlwaysRequireCookie` the handshake would loop forever: cookie, stale
cookie, cookie.

So the DNS adapter does what the stream carrier already does
(`stream.IsStreamAddr`, `fd61:7263:2f31::/64`): it **presents a synthetic
peer address to the session**, one per association, and that address is
what cookies, path addresses and replies key on.

- **Allocation.** On first open, the client picks `assoc_id`, and the
  relay allocates a synthetic address for that association exactly as it
  does for a stream connection: a unique local IPv6 address under a DNS
  prefix distinct from the stream one, so `IsStreamAddr` and this predicate
  cannot confuse each other. The address is stable for the association's
  life, which is what a cookie needs.
- **Ingress.** `DatagramConn.ReadBatch` reports the synthetic address as
  `from`. The session therefore sees one peer per association, cookies
  verify, `path.addr` is stable, and §14.5's rebinding logic never fires
  for a resolver's port churn.
- **Egress.** `RelayDatagram.Addr` carries the synthetic address back, and
  the relay engine routes it to the adapter (a third branch beside `Conn`
  and `Streams` in `RunRelay`), never to UDP. The adapter maps it to the
  association's current resolver socket.
- **Resolver-facing accounting stays separate.** Per-resolver budgets
  (§5.3) count real source addresses at the adapter, before the synthetic
  mapping, so a shared resolver's load is measured on the resolver and not
  on the tunnel. The journal records the real resolver too.
- **A synthetic address is not authentication.** It is an
  unauthenticated hint exactly as `assoc_id` is: a relay binds it to a
  session only after a fully reassembled packet carrying it authenticates,
  and an address already bound to another session is ignored. A forged
  `assoc_id` gets an address and then fails the handshake.

This is the one place the DNS path needs a new mechanism rather than a
new rule, and it is why the cookie requirement is implementable at all.

#### 4.2.2 The pre-authentication reply path

§12.1 and §16.5 say an unbound association gets `A1:-` and nothing else.
That cannot work here, and it is the reason this section exists: the
client's very first packets are a `HANDSHAKE_INIT`, which the relay
answers with `HANDSHAKE_RESP` (or `COOKIE_REPLY` under load, §9.3) — both
*before* anything has authenticated, and therefore before an `assoc_id`
can be bound. With only `A1:-` available, `HANDSHAKE_RESP` could never
reach the client and no DNS-only session could ever establish.

**Rule.** An association that is not yet bound MAY carry downlink cells,
under all of these limits:

- **Only handshake packets.** `COOKIE_REPLY` (25 B), `HANDSHAKE_RESP`
  (81 B), and `STATELESS_RESET` (25 B) — the three packet types a
  pre-authentication peer can legitimately need. Anything else on an
  unbound association is dropped, and a `DATA` packet that would not
  authenticate is dropped silently as today.
- **One cell per answer, and only in answer to a poll.** The relay sends
  a pre-auth cell on the same query that carried the uplink cell
  provoking it, never unsolicited, so an unbound association cannot be
  used to make the nameserver emit traffic on its own.
- **The same 3× cap per answer** (§2.2), so a pre-auth reply is bounded by
  what the query carried. No padding is needed: `HANDSHAKE_RESP` in one
  99-byte cell costs a 359-byte answer to a 211-byte query, a ratio of
  1.7, and the 25-byte replies are 1.6.
- **A rate limit per source resolver and globally**, as `A1:-` already
  has, since this is now a path that emits a reply to an unauthenticated
  stranger. A cookie makes the relay cheap to defend and is required here
  more than on UDP: `AlwaysRequireCookie` SHOULD be set for a DNS
  listener, so every pre-auth reply except the cookie itself follows a
  validated round trip.
- **A short unbound budget.** The existing limits (4 incomplete packets,
  16 KiB, no expiry) stay, plus: at most 8 pre-auth cells per association
  per minute, after which it gets `A1:-` until it authenticates. That
  bounds a single `assoc_id` guesser without affecting a real client,
  whose entire pre-auth exchange is the cookie, the response, and the
  AUTH.

`HANDSHAKE_INIT` is 122 B, which is two cells, so a cold start with
cookies required is **five polls**:

| poll | carries | answers with |
|---|---|---|
| 1 | INIT, cell 1 | `A1:-` |
| 2 | INIT, cell 2 | `COOKIE_REPLY` |
| 3 | INIT with cookie, cell 1 | `A1:-` |
| 4 | INIT with cookie, cell 2 | `HANDSHAKE_RESP` |
| 5 | `AUTH` | `AUTH_RESULT` |

Three poll intervals elapse inside the INIT phase (6 s of its 10 s), and
the AUTH poll starts the second phase. That is the budget the ceiling rate
buys, and it is why §2.5 says establishment runs at the ceiling rather
than at the steady rate. **The stage 2 exit criterion is exactly this
exchange, with cookies required**, which is why §7 says so explicitly.

This is the one place the lifeline relaxes a §12.1 rule rather than
working within it, and it relaxes it only for the three handshake packet
types, only in answer to a poll, and only under a per-association budget.

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
  row, or establishment failing three times (§2.5) — is reported unusable
  and closed, rather than kept at a rate that makes the session flap.
- **One answer, one cell.** An answer that carries a cell which does not
  authenticate (a stale cache entry for a repeated name, a rewriting
  middlebox, an off-path injector) is discarded and the poll repeated
  with a fresh nonce. A rejected answer proves nothing about the path;
  only an absence of authenticated progress for the stall timeout does.

#### 4.3.1 Who asks the session for a packet

The adapter cannot seal, and it must not try: `WriteBatch` receives
already-encrypted datagrams, and only `session` holds the keys. But the
poll loop needs a *fresh* packet at times the engine will not volunteer
one, so the contract has to say who asks and what comes back.

**The adapter asks; the session decides.** One addition to the session's
public surface, alongside `Probe` (which exists and sends a PING on a
validated path):

```go
// PollPacket returns one fresh datagram for the path. demand means the
// carrier has downlink to collect: the session then mints a PING even if
// the keepalive is not yet due. It reports false only when the path is
// gone.
func (c *Client) PollPacket(now time.Time, id uint32, demand bool) (Datagram, bool)
```

Three things had to change from my first version of this, and the reviewer
found the first two:

- **`demand` is what makes a downlink-only transfer possible.** My first
  signature could return nothing when no keepalive was due — which is
  precisely the state a client is in while it is *only* receiving. A
  backlogged downlink would then wait for the next keepalive, and at 6
  polls/min a 444-byte packet would drain at one cell per 10 s regardless
  of how hard the adapter wanted to poll. With `demand` set, the session
  mints a `DATA`/`PING` now, so the adapter's backlog polls at the ceiling
  actually carry a fresh authenticated packet. The PING is a real
  encrypted packet, so §4.4 holds: an answer to it is session progress,
  not just path progress.
- **The timer goroutine must not call session methods.** `session.Client`
  is a sans-IO state machine owned by the engine's event-loop goroutine;
  every method is documented as being called from it. A poll timer calling
  `PollPacket` directly would be a second writer. So the request goes
  **through the loop**: the adapter sends a `pollRequest{path, demand,
  reply}` on the engine's channel, the engine calls `PollPacket` on its
  own goroutine and returns the datagram on `reply`. The adapter's timer
  owns *when*; the engine owns *the call*.
- **Backpressure.** When the session has more to send than the poll loop
  can carry, the adapter does not buffer it: `PollTransmit` returning
  datagrams faster than polls happen is a sign the path is overloaded, and
  a DNS path that queues for a minute delivers a packet that will expire
  anyway (§2.4). The adapter keeps at most one packet's cells in flight
  and drops the rest with a counter, exactly as the stream carrier drops
  into a full queue rather than blocking the event loop (§16.3).
- **Before validation** the adapter polls with whatever the handshake
  needs, and here the answer is *not* a fresh packet: `HANDSHAKE_INIT`
  and `AUTH` are retransmitted by `Client.Tick` on their own schedule
  (§2.5), at 100 ms early and 1 s once quiet. The adapter drains them from
  `PollTransmit` exactly as a UDP carrier does, one cell per poll, and
  **coalesces**: if `Client.Tick` has queued two INITs for the same
  attempt, only the newest is carried. That matters because the ceiling
  is one poll per 2 s while the session's retransmit interval is 100 ms,
  so without coalescing the adapter would queue twenty obsolete copies of
  the same handshake packet per poll interval.
- **Obsolete attempts are dropped, not queued.** A `Datagram` for a
  handshake attempt whose `HandshakeAttempt()` counter has advanced is
  discarded by the adapter; the session's own restart invalidates it, and
  a DNS path must never spend a poll on an INIT for a session it has
  already abandoned. The same rule covers a path that dies mid-poll: its
  queued cells go, because the path ID will never be reused (§14.3).

So the division is: the session owns *what* to send and *when it is due*;
the adapter owns *how often it can ask*. A PING is due at the keepalive,
a retransmission at a PTO, or — through `demand` — whenever the adapter
has downlink waiting, and each is a question the adapter poses through the
engine's loop rather than on its own goroutine.

#### 4.3.2 Committing a downlink cell: an ARC receipt, not a new query

A new query nonce proves a different query arrived. It does **not** prove
the previous answer was delivered, or that the client accepted it. My
first attempt at this rule treated "poll *n+1* arrived" as a receipt for
poll *n*'s cell, and that is wrong in two ways the reviewer named:

- §4.3 says a cell that fails to authenticate is discarded and the poll
  repeated. That is exactly the case where the answer arrived and was
  rejected — and the rule would have committed it.
- A late recursive retry of an old query looks like a new poll once the
  one-entry cache has moved on, so it would commit a cell the client never
  saw.

**Rule: the relay commits a downlink cell only on evidence from the
*tunnel*, and it keeps the cell until then.**

ARC already has that evidence, for every packet this path sends, with no
new wire elements:

| queued packet | the receipt | why it is proof |
|---|---|---|
| `COOKIE_REPLY` | the next `INIT`, carrying that cookie | only a client that received it can echo it |
| `HANDSHAKE_RESP` | the `AUTH` that follows | it is encrypted under keys from message 2 |
| `AUTH_RESULT` | the client's first `DATA` or `ACK` | the session exists only if it saw the lease |
| `DATA` (downlink) | the `ACK` frame covering that packet number | the client's own acknowledgement, inside its AEAD |
| `STATELESS_RESET` | nothing — it is terminal | no commit; the association is gone |

So the downlink queue holds **whole packets, not pre-split cells**, and a
packet leaves the queue when the tunnel acknowledges it:

- **Refragmentation, which also answers the next finding.** Because the
  queue holds a packet, the relay sizes *each cell* to the arriving poll's
  answer budget: `min(resolver buffer, 3 × query)` (§2.2.2). A packet that
  went out as a 409-byte cell under EDNS and then faces a 168-byte budget
  is simply re-split — the remaining unsent bytes become smaller cells.
  Nothing is stranded: there is no committed cell that no longer fits, no
  head-of-line block, and no need to wait for a larger poll that may never
  come. A cell that was *sent* but not acknowledged is re-sent, in
  whatever size the current poll allows.
- **Re-sends are idempotent at the client.** A cell carries
  `(assoc_id, cell_packet_id, offset)`; the client keeps the accepted
  ranges for the packet in flight and drops a duplicate. A retried
  resolver query gets the same cells again, and the client ignores them.
- **One packet in flight per association.** The path carries a few hundred
  bytes a second; a window deeper than one is queueing for a link that
  cannot absorb it (§2.4). So the relay's downlink state is one packet's
  bytes, one cursor, and one `cell_packet_id`.
- **A lost answer is not a lost cell.** If the authoritative reply never
  reaches the client, nothing is acknowledged, nothing is committed, and
  the next poll re-sends the same bytes. That is the resolver-retry case
  solved by construction rather than by tracking nonces.

The `cell_packet_id` therefore changes only when a packet is committed,
which is what makes the client's duplicate detection sound: a repeat
within one packet is a replay, and a repeat across packets cannot happen.

Tests: a lost authoritative reply followed by a resolver retry must
re-send the same bytes; a sustained loss of EDNS capability mid-transfer
must re-split and complete (the reviewer's second case); and a client that
receives but *rejects* a cell (a middlebox rewrote it) must not have its
packet committed.

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

Never by default, and never on someone else's opt-in. Three gates, all of
which must open:

- **Permission.** `-dns-lifeline ZONE` names the carrier zone the operator
  delegated to this use, and `-lifeline-beacon ZONE` (or a profile key)
  names the beacon zone. §16.5 already requires "explicit authorization to
  use the network's DNS facility in this way"; a posture flag is not that
  authorization, and this section makes the distinction load-bearing.
- **Posture.** Under `network-profiling.md` §6.2, `regime = allowlist` or
  `shutdown` *selects* the lifeline — but only among carriers the
  permission gate already admitted. So the posture can choose this path
  and can never introduce it.
- **Absence of a better one.** The carrier is opened only while no other
  validated path exists, and §5.1's closing rules below take it away again
  when one appears.

The separation matters because `-allowlist` and `-censorship` exist to
shape how *ordinary* carriers behave: which cover names to try, whether to
send UDP to a hosting address. Broadening them to silently authorize a
DNS carrier would change what a user consented to when they passed the
flag, and the DNS carrier is the one with a third party's infrastructure
involved — a resolver, and a zone the operator must have registered. A
flag that meant "be careful with UDP" must not come to mean "tunnel
through your ISP's resolver".

So a client with `-allowlist` and no `-dns-lifeline` behaves exactly as it
does today: approved destinations, cover names, no DNS carrier, and a
status line that says the lifeline is unavailable *because it was not
configured*, not because the network refused it. The two are different
facts and the user should see which one they have.

The reverse is a harder rule: the client closes the carrier and stops
polling when (a) any other validated path exists and the profile is not
`allowlist`/`shutdown`, or (b) the user turns it off. A lifeline that
keeps running when it is not needed is a beacon announcing "this device
is here, right now" to every resolver on the path.

### 5.2 Which resolver

The client uses the resolver the network gave it — but "the resolver the
network gave it" is usually a **local stub**, and a stub is not a
destination this path can use. On a systemd host `/etc/resolv.conf`
names `127.0.0.53`; on macOS it names an address in `127.0.0.1` or
`fe80::1%en0`. Pinning an adapter socket to a stub address does not pin
where its queries go, and once ARC is up the stub is worse than useless:
managed DNS installs `~.` with `default-route yes` on the tunnel link
(`tun.dnsState.configure`), so the stub will forward the lifeline's own
queries back into the tunnel the lifeline exists to rescue.

**Rule: the lifeline never uses a stub, and never uses a resolver it
reaches through the tunnel.**

- **Discover the physical link's real upstream.** Before installing the
  tunnel, the client resolves which link carries the default route and
  asks the platform for *that link's* upstream servers: `resolvectl dns
  <ifindex>` on Linux (which returns the configured upstreams, not the
  stub), `scutil --dns` and the `State:/Network/Service/*/DNS` entries
  filtered to the link's service on macOS. If every answer is loopback,
  link-local, or the stub itself, the lifeline is **unavailable** on this
  host and the client says so — it does not fall back to the stub.
- **Reject ineligible addresses** by the same predicate `tun.ValidateDNS`
  already applies to an installed resolver: IPv4 global unicast, not
  loopback, not link-local, not multicast. A DoH/DoT-only network with no
  plain resolver address exposes none of these, which is a correct
  "unsupported" rather than a silent leak into the tunnel.
- **Pin the socket to the link**, not just to the address: `IP_BOUND_IF` /
  `SO_BINDTODEVICE` on the physical interface, exactly as the carrier
  sockets are, so even a stub's address that happens to be routable is
  reached outside the TUN route.
- **Re-check on link change.** The upstream is a property of the
  attachment, not of the process: a Wi-Fi→Ethernet move or a captive
  portal's post-auth resolver swap must re-run discovery, and a lifeline
  bound to the old link's resolver is closed and reopened.
- **`-dns-lifeline-resolver ADDR` overrides all of it**, for an operator
  who knows the address; it is validated by the same predicate.
- The path never resolves its own names through the tunnel (§17.3), and
  this is the concrete mechanism: the query goes to an address on the
  physical link, from a socket bound to that link, with no dependency on
  the system resolver at all.

The test for this is a full tunnel with managed DNS active: the lifeline
must keep answering while `resolvectl query` on the host returns answers
*through the tunnel*, and the journal must show the physical upstream, not
`127.0.0.53`.

### 5.3 Budgets

Four independent caps. Each names its **direction** and its **metering
point**, because the ceilings differ by a factor of three and a single
"256 KiB" number cannot bound both.

| cap | direction | counts | at 30/min ceiling |
|---|---|---|---|
| `-dns-lifeline-rate` | both | polls/min: 6 steady, 30 ceiling | — |
| `-dns-lifeline-up-bytes` | client→relay | cell payload sent, 128 KiB/h | 207 KiB/h, so it binds |
| `-dns-lifeline-down-bytes` | relay→client | cell payload received, 512 KiB/h | 719 KiB/h, so it binds |
| relay per resolver and per zone | queries | real source address, §5.3.2 | — |

- **The uplink cap must be below the ceiling's own maximum to mean
  anything.** A client at 30 polls/min sends 207 KiB/h of cell payload, so
  a 256 KiB/h uplink budget could never bind — the reviewer's point, and
  it made the earlier single-budget rule untestable on the uplink. 128 KiB/h
  is about 62% of the ceiling: enough for a session that polls at the
  ceiling for 37 minutes an hour, which is a real limit without being an
  arbitrary one.
- **The downlink cap is larger because a downlink cell is larger.** At the
  ceiling a client can receive 719 KiB/h, so 512 KiB/h binds at about 43
  minutes of full-rate polling. Both caps are per hour wall-clock, not
  rolling windows, so exhaustion is a clean boundary a test can hit.
- **Exhaustion carries control only**, at the 6/min floor: keepalives and
  ACKs continue, and every other frame waits for the window to roll over
  or the path to be closed. Control cannot be throttled further without
  killing the session (§2.3).
- **What survives path replacement.** The caps belong to the *device*, not
  the path: a lifeline that dies and reopens, or moves to a second relay,
  keeps counting. Otherwise closing and reopening the path would be a
  trivial way to reset the budget, which is the one thing an operator's
  resolver must not see.
- **The relay enforces its own copy** per bound association at the
  authoritative server, answering `A1:-` to anything over — it cannot see
  the client's counters, and must not trust them.
- **The exhaustion test names its traffic:** application data queued in
  *both* directions, with the assertion that control continues and that
  the dropped packets are counted per direction (§5.3.1).

#### 5.3.1 The budget must be enforced before sealing, not after

The adapter sees opaque datagrams. `session.Datagram` is a path ID, bytes
and an `AckEliciting` bit — no frame types — and one ARC packet may carry
an ACK, a PING and two `IP_PACKET`s together. So an adapter that counts
bytes cannot tell control from application traffic, and "control-only
after the budget" is unimplementable at the adapter layer. The budget
belongs where the frames are still visible.

**Rule.** The session enforces it for a path it knows is constrained:

- `session.path` gains `constrained` and `allowance` (an
  `allowance` = bytes and polls remaining in the current hour). Both are
  set when the path is created, from the carrier, alongside the
  `maxPacket` of §2.4.
- **When assembling a packet for a constrained path, the session admits
  frames by class:** unbound control (PING, ACK, `PATH_*`, `CLOSE`,
  `ERROR`) always; `AUTH` and handshake frames always; `IP_PACKET`,
  `IP_FRAGMENT` and `STREAM*` only while the allowance lasts, and
  **dropped rather than queued** when it does not. The scheduler already
  decides which path a flow goes to, so a flow placed elsewhere loses
  nothing; a flow with nowhere else to go sees the packet drop, which is
  the truthful outcome for a link that is out of budget.
- **Exhaustion is reported, not silent.** The client counts drops per
  class and says so in the journal and the status line; a dropped
  `IP_PACKET` on the only path closes the flow's TCP connection rather
  than letting it hang, matching what a full transmit queue does (§16.3).
- **The reserved application-DNS slice is a session-side flow label,** not
  an adapter heuristic: `flowTable` already keys flows, so the client
  marks the inner resolver's 5-tuple (the relay's pushed `dns_ipv4`, or
  the configured `-dns`) as privileged, and those packets draw on their
  own small allowance ahead of other IP traffic. That is a rule about
  addresses the session knows, which is why it can be a rule at all.

This is the second thing the current contract cannot express (the first
being §4.1's constrained flag), and it is the same fix: the session has to
know a path's budget, because only the session can see what a packet
carries.

#### 5.3.2 The per-resolver budget counts real sources

The relay's per-resolver cap is metered at the adapter, on the **real**
source address of each query, before the synthetic address of §4.2.1
replaces it. The two identities answer different questions and must not be
conflated:

- **The synthetic address** is what cookies, path addresses and replies
  key on — one per association, stable (§4.2.1).
- **The real source** is what a shared resolver's load must be measured
  on: a hotel's resolver serving forty ARC users is one budget, and each
  user's `assoc_id` is not a way to get forty.

So the cap is `(real source address, zone)` at the adapter, and it is
enforced before the packet reaches the session. The journal records the
real resolver alongside the association, so an operator can see which
resolver became the bottleneck without correlating two logs.

### 5.4 What may ride it

- **Control, always.** Handshake, AUTH, path validation, keepalives,
  ACKs, `CLOSE`, `PATH_ABANDON`.
- **IP traffic, yes, under budget.** There is no protocol reason to
  exclude it and one good reason to include it: the first thing a user
  needs on a captive or allowlisted network is a name resolved to an
  address, and if ARC will not carry that query, the tunnel is up and
  useless. Application DNS therefore gets a reserved slice of the budget
  (the first 4 KiB/hour of downlink, say) ahead of any other flow, marked
  as a privileged flow by the session (§5.3.1), not guessed at by the
  adapter.
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
the amplification rule is tested rather than trusted. It can also be told
to require cookies, drop its first reply to force a resolver retry, and
shrink its answer budget mid-transfer.

| Scenario | Assertion |
|---|---|
| Everything but DNS blocked (`iptables` default drop, resolver allowed), **cookies required** | A session establishes over the DNS path alone inside one handshake attempt (10 s per phase) in the five polls of §4.2.2, and a ping through the tunnel gets its reply within two polls |
| Beacon queried cold, no session possible | The client sends the fixed 271-byte bootstrap query, learns endpoints and cover names from a signed record, and logs the regime |
| Beacon forged (signature flipped), replayed past `not_after`, rolled back to an older `published` after a restart, sinkholed by a wildcard | Each is rejected and logged; the client falls back to its enrolled relay and never adopts a retired key for a new connection |
| Beacon answer above 3× the query | The nameserver refuses it; a client that stops padding gets no beacon and says so |
| Beacon too large for the bootstrap profile (3 relays) | No answer in the 512-byte profile; the client retries with EDNS(0) and succeeds there, and logs which profile it used |
| Full-length uplink cells against a 512-byte answer budget | The downlink cell is 168 B, not the 243 B a padded short query gets — a client that fills the name loses downlink — and no answer exceeds 3× its query |
| A padded name carrying a fragmented cell | Two cells of one `HANDSHAKE_INIT`, the first with padding labels; both reassemble to exactly one cell each, and a `0`-led label is never read as cell data |
| A 472-byte packet sent at 6 polls/min | Reassembles inside the 60 s DNS expiry; the same packet fails on the 10 s value, which is why the expiry is carrier-specific |
| Resolver retries after the authority's reply is lost | Nothing is committed, because nothing was acknowledged: the next poll re-sends the same packet bytes, and the client's duplicate detection ignores the repeat |
| Answer budget shrinks mid-transfer (EDNS → no EDNS) | The queued *packet* is re-split to the smaller answer budget and completes; no cell is stranded waiting for a larger poll |
| A client receives but rejects a cell (a middlebox rewrote it) | The packet is not committed; the relay re-sends the same bytes on the next poll |
| Resolver changing source port and egress between the two INITs | Cookies still verify, because they key on the association's synthetic address (§4.2.1), not the resolver's |
| A downlink-only transfer with no uplink work | The client's backlog polls each carry a fresh demand-PING, so the packet drains at the ceiling rather than one cell per keepalive |
| Resolver rewriting TXT content / truncating / caching stale cells | Cells that do not authenticate are discarded; the path is not declared dead until the stall timeout |
| Resolver returning `SERVFAIL` at 20 polls/min | The path keeps the 6/min floor with PING-only polls, sheds application cells, and either recovers or is reported unusable — it never backs off below the floor |
| A faster path available | The DNS path stops polling within one idle interval and carries no flows |
| Budget exhausted (`-dns-lifeline-up-bytes` and `-down-bytes` both) with application data queued in both directions | Control continues at the 6/min floor; application packets are dropped by the session, not queued, and the drops are counted per direction; closing and reopening the path does not reset the counters |
| Full tunnel with managed DNS active (`~.` on the tunnel) | The lifeline keeps answering; the journal shows the physical link's upstream, never `127.0.0.53` or a loopback stub |
| `-allowlist` without `-dns-lifeline` | No DNS carrier is opened; the status line says it was not configured, not that the network refused it |
| 300-byte application DNS answer through the tunnel | Completes in three polls (two up, one down); the journal records the wire cost |

The responder's own assertions replace what a lab DNS zone would
otherwise take days to schedule: `test/netns/dns.sh` needs no registrar,
no delegation, and no internet.

## 7. Staging

1. **Beacon only.** Responder plus client verification, no carrier. This
   delivers rendezvous, which `network-profiling.md` §10 defers, and is
   useful on its own: a device whose enrolled relay address died can
   learn the new one with one ordinary query.
2. **Uplink and authenticated downlink.** Cells both ways, the synthetic
   peer identity of §4.2.1, the pre-auth reply path of §4.2.2, poll loop
   and pacing. Exit: a session establishes over DNS **with cookies
   required** in the five-poll cold start, and then holds 10 minutes with
   its path never going `SUSPECT` — which needs authenticated keepalive
   *replies*, since `A1:-` cannot advance session liveness (§4.4). That is
   why this stage is bidirectional for control; application downlink is
   still stage 3.
3. **Downlink data and receipts.** Whole-packet queueing, per-poll
   refragmentation, ARC receipts (§4.3.2), backlog polling with `demand`,
   and application DNS as the first IP flow. Exit: a name lookup completes
   in three polls, a 472-byte packet reassembles at the steady rate, and a
   downlink-only transfer drains at the ceiling.
4. **Rotation.** A second relay on the same store, a beacon naming only
   it, and an enrolled device establishing a new session there with no
   operator action (§3.5). Exit: that test passes, and a retired key is
   refused for a new connection.
5. **Postures and budgets.** `allowlist`/`shutdown` regime selection
   behind the permission gate of §5.1, session-side budgets (§5.3.1), the
   status line, and `dns.sh` in CI.

**No ARC wire change at any stage.** The carrier uses `CELL` (§12.1) and
`TXT` unchanged, with no new frame type, no new feature bit, and no
relay-side protocol negotiation. The beacon's record *is* a new format
(§3.1), but it is not ARC wire traffic: it is an application-level record
inside a TXT answer, read before any session exists.

What the lifeline does need beyond the adapter is four additions, all
named where they are argued:

- a **constrained** flag and a `max_packet` on the path (§2.4, §4.1);
- a **`PollPacket(now, id, demand)`** query for request/response carriers,
  called from the engine loop rather than the adapter's timer (§4.3.1);
- a **per-path allowance** admitted before sealing (§5.3.1);
- a **synthetic peer address** per association, routed like
  `stream.IsStreamAddr` (§4.2.1).

## 8. Deferred

- **An A/AAAA-only beacon.** Some allowlists pass only address queries.
  A beacon could be encoded across four A records (4 bytes each per
  query, one relay per name, round-robin by index) without TXT at all.
  Deferred until a field report shows TXT is filtered where A is not.
- **Several cells per answer.** A 4096-byte EDNS(0) buffer fits roughly
  2.8 KB of cell in one answer, which would cut the poll count for a
  downlink burst by 6×. It also makes the answer an amplifier worth
  abusing, depends on a resolver honoring the client's buffer size, and
  under the 3× rule would require a query of at least 934 bytes — which a
  255-byte name cannot produce. It becomes possible only with the next
  entry.
- **Tunnelling inside the answer's own extra bytes.** §2.2's 3× rule is
  what caps the downlink; a query *body* larger than a name would lift it,
  and DNS has no such body. This is where a real TCP-length query (or a
  large EDNS(0) option field, which some resolvers echo) would change the
  arithmetic, and it is deferred because it depends on resolver behaviour
  the operator does not control.
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
