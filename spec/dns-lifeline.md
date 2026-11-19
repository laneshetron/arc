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
<nonce>.<b32 cell labels>.[1<seq>...].[0<padding>...]._arc.<zone>
```

- `<nonce>`: 13 lowercase base32 characters (8 random bytes). It makes
  every poll a distinct name, so no answer is served from a cache.
- cell labels: lowercase base32 of exactly one cell, each at most 50
  characters, as §16.5 already specifies.
- zero or one **sequence label**: `1` followed by 2 base32 characters
  (10 bits), carrying the poll's slot number (§4.3.1). It is needed only
  while the window is deeper than 1; a decoder that does not find one
  treats the slot as 0.
- zero or more padding labels: `0` followed by 1–62 base32 characters.
  A decoder MUST skip every label whose first character is `0`, and MUST
  reject a `0` label of length 1 or above 63. The nameserver emits them;
  the relay ignores them.
- Because a cell's chunk length is `cell_len − 18` and `cell_len` is
  `⌊5·chars/8⌋`, the decoder recovers the chunk boundary exactly, with no
  padding involved: 60 chars → 37 B, 189 → 118 B, 218 → 136 B. Padding
  rides entirely outside the cell, so a padded name decodes to one cell by
  the same rule an unpadded one does.

`0` and `1` are both outside the base32 alphabet, which is what makes the
three label kinds unambiguous without a length prefix: `0` is padding,
`1` is a slot, anything else is cell data.

The sequence label costs **4 wire bytes** (a length byte plus `1` and two
characters), which at `_arc.example.net` takes the room for payload from
223 to 219 bytes and the cell from 136 to 133 B, so `max_packet` falls from
118 to 115. That is the price of the window, and it is paid only when the
window is 2.

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
moves downlink. Zone `_arc.example.net`, full-cell questions, EDNS(0).
**The rate is a dial, not a constant**, and what it buys is linear in
polls and in reachable datagram size (§2.4.1):

| polls/min | interval | q/s | down | inner datagram | detectability |
|---|---|---|---|---|---|
| 6 | 10 s | 0.1 | 0.04 KiB/s | 66 B | **floor; indistinguishable from an idle host** |
| 30 | 2 s | 0.5 | 0.20 KiB/s | 198 B | default ceiling; unremarkable |
| 120 | 0.5 s | 2 | 0.80 KiB/s | 660 B | a busy client; still ordinary |
| 300 | 0.2 s | 5 | 2.0 KiB/s | 1.5 KB | **visible to any zone-volume monitor** |
| 1200 | 0.05 s | 20 | 8.0 KiB/s | 6.2 KB | textbook tunnel; expect the zone blocked |

**The default is 30/min and the operator raises it, because the cost is
not ours to pay.** Every poll above the floor is a query to somebody
else's resolver and somebody else's zone, and §1.1 exists because a zone
that looks like a tunnel gets blocked for every user of it, including the
ones using it only for rendezvous. So `-dns-lifeline-rate` is exposed with
the ceiling above and its detectability stated next to it, and the client
does not raise it on its own: a *transfer* may request a higher rate, and
the operator's configured ceiling caps it.

The floor is not a preference either: `DefaultKeepalive` is 10 s, a path
silent longer than `keepalive + max(3·PTO, keepalive/2)` — about 15 s at
any realistic RTT (`conn.idleLimit`) — goes `SUSPECT`, and
`DefaultPathTimeout` makes it `DEAD` at 30 s of silence. A DNS path that
is the only path therefore **must** poll at least six times a minute or
kill the session it exists to keep alive. Six is a 10-second interval
against a 15-second threshold, so the margin is 5 s: any poll whose answer
takes longer than that eats into it, which is why a late answer counts as
a pacing failure (§4.3) and not merely as latency.

At the floor a session costs about 48 KiB an hour of cell payload, all
control when the user is idle (§5.3). At 300/min it is 2.3 MiB an hour,
which is the sort of number a resolver notices.

Without EDNS(0), the same questions move 168 B down per poll instead of
409 B, so every row above drops by 2.4×. That is a bigger swing than any
choice of rate, and it is why §2.2.2 spends so much effort on the EDNS
case.

### 2.3.1 Why not just pipeline harder

A window deeper than 2 buys throughput only when the rate cap is also
raised, and the pair together is what becomes visible. At 409 B per poll,
8 KiB/s needs 1,200 polls a minute — 20 queries a second to one zone.
Dnstt-class throughput needs roughly 250 q/s. That is not a tuning
parameter; it is a different product with a different threat model, and the
operator of a zone would be the one to pay for it.

So the window here is **2**, and its purpose is not throughput: it is so a
client behind a slow resolver can still reach the configured rate at all.
At window 1, throughput is `1/RTT`, and any resolver slower than the poll
interval sets the pace — at 120/min that is 500 ms, which a congested hotel
or mobile core easily exceeds. §4.3.1 states the window and §4.4.1 the
health consequence.

### 2.4 One cell per ARC packet

Cell reassembly expires incomplete packets on a timer (§12.1: 10 s for a
bound association), and this path delivers **one cell per poll**. My
previous revision tried to reconcile that with a raised expiry and a
multi-cell `max_packet`. That cannot work, and the reason is a timer I had
not checked:

**ARC's retransmission timer fires far faster than a poll.** `rtt.pto()`
is `2·initialRTT + maxAckDelay` = **691 ms** before any sample exists
(`initialRTT` 333 ms, `MaxAckDelay` 25 ms), while this carrier's poll
interval is 2 s at the ceiling and 10 s at the steady rate. So a
multi-cell packet is *always* still mid-emission when PTO fires:
`sentLog.onPTO` retires the oldest outstanding control packet and returns
its frames for re-sealing, the emitter abandons the unfinished cells, and
the replacement is preempted 691 ms later in turn. A 4-cell packet can
never be delivered at any rate, lost or not. There is no loss-rate tuning
subtlety here; the timer simply does not permit the design.

| packet | spans at 30/min | at 6/min | PTO at 691 ms |
|---|---|---|---|
| 2 cells | 2 s | 10 s | preempted |
| 4 cells | 6 s | 30 s | preempted |
| 6 cells | 10 s | 50 s | preempted |

**Rule: exactly one cell per ARC packet.** The adapter sets
`max_packet` to the cell budget it can carry in one query, and the session
never emits a packet that needs a second poll to complete.

```text
max_packet  = cell − 18        (cell = the uplink cell for the zone, §2.1)
IP payload  = max_packet − 37  (18 DATA header + 16 tag + 3 frame header)
```

| zone | cell (with slot) | `max_packet` | IP payload up | `HANDSHAKE_INIT` |
|---|---|---|---|---|
| `_arc.io` | 139 B | 121 B | 84 B | 2 cells |
| `_arc.x.io` | 138 B | 120 B | 83 B | 2 cells |
| `_arc.ex.net` | 136 B | 118 B | 81 B | 2 cells |
| `_arc.example.net` | 133 B | 115 B | 78 B | 2 cells |
| `_arc.relay.example.com` | 130 B | 112 B | 75 B | 2 cells |

These are **with the slot label** of §4.3.1, which is 4 wire bytes (a
length byte plus `1` and two characters) and costs 4 B of cell. Without it
— a window of 1, or the handshake, which uses `W = 1` throughout (§2.5) —
each cell is 4 B larger and `_arc.io` and `_arc.x.io` reach a one-cell
`HANDSHAKE_INIT`.

That is the real price of the window, and it is larger than my previous
revision claimed: at 4 wire bytes it costs a poll at *every* zone suffix
in the table, including the shortest, because `_arc.io` drops from 141 to
139 B and 122 bytes no longer fits one cell. The window is worth that —
§2.3.1 explains why it is a correctness fix rather than a throughput
one — but it should be stated as the cost it is.

**What this does to packet sizes.** A 1280-byte IP packet becomes 19
fragments at `_arc.example.net` (`conn.sendOn` splits to
`max_packet − 18 − 16 − 3 − 12 = 69` bytes of payload per `IP_FRAGMENT`),
so it costs 19 polls. That is not a regression against the previous
revision — which specified a `max_packet` no packet could reach — it is
the first honest estimate. A 300-byte payload is 5 polls, a 100-byte query
is 2.

**Reassembly now needs no special expiry.** With one cell per packet,
every packet completes within one poll interval, so the §12.1 10-second
bound is never stressed and the DNS adapter does **not** override it. The
60-second expiry of my previous revision is withdrawn along with the
`max_packet` values it existed to protect. This is a simplification the
review forced and the design is better for it: no wire constant changes.

The only remaining multi-cell packet is `HANDSHAKE_INIT` (§2.5 — with the
slot label it is two cells at every zone suffix), and it is safe for a
reason that does not generalize: `sendInit` appends straight to `c.out`
and never enters `sentLog`, so no PTO can preempt its two-cell emission,
and its own timer (100 ms early, 1 s once quiet) drives the retries.
`AUTH` is also PTO-immune — it is passed as `extra`, so it never lands in
`sentPacket.frames` and `onPTO` cannot return it — but it is only 80 B and
always fits one cell, so it never needs the exemption.

That is an exemption the handshake already has and this carrier merely
uses; it is not a pattern to copy for data. Any *data* packet large enough
to span two polls would be preempted at 691 ms, which is the whole reason
§2.4 exists.

What remains is the *health* interaction, which §4.4 covers, and the
**inner** datagram window of §2.4.1.

#### 2.4.1 One cell per packet caps inner IP at what 5 s admits

One cell per ARC packet fixes the cell layer, and it exposes a second
window underneath it: **IP datagram reassembly**. `reassembly.DefaultConfig`
expires an incomplete datagram after **5 s**, and `conn.sendOn` turns an
IP packet larger than `max_packet` into several `IP_FRAGMENT`s, sent one
per poll. So the inner datagram a path can carry is set by how many
fragments fit before that expiry at the rate it is polling — with a margin
for one round trip, since the clock starts when the first fragment
arrives:

| rate | interval | fragments (5 s − RTT margin) | largest inner IP datagram |
|---|---|---|---|
| 6/min | 10 s | 1 | 66 B |
| 30/min | 2 s | 3 | 198 B |
| 120/min | 0.5 s | 10 | 660 B |
| 300/min | 0.2 s | 24 | 1,584 B |

**The rate dial (§2.3) is therefore also the inner-MTU dial**, and that is
the strongest argument for raising it: at 6/min a 100-byte DNS query (137 B
of ARC packet, three fragments) is *impossible*, not merely slow. Every
step up the rate ladder buys reachable datagram size linearly, which
matters more than the byte rate for real applications.

**Use a deadline below 5 s, not equal to it.** The expiry starts when the
*first* fragment arrives, and the last must be there strictly before it —
so the count is `⌊(5 s − margin) / interval⌋ + 1` with a margin covering
one resolver round trip, not `⌊5 s / interval⌋ + 1`:

| interval | naive `⌊5/iv⌋+1` | with 0.2 s margin | IP payload |
|---|---|---|---|
| 10 s | 1 | 1 | 66 B |
| 2 s | 3 | 3 | 198 B |
| 1 s | 6 | **5** | 330 B |
| 0.5 s | 11 | **10** | 660 B |
| 0.2 s | 26 | **24** | 1,584 B |

The divergence grows with the rate, which is exactly where the dial is
worth having — so the adapter recomputes the bound from its **measured**
RTT after each round trip rather than from a nominal figure, and shrinks
the accepted datagram if the path gets slower.

Fragments of one datagram go out on consecutive polls, so they are
`interval × (n−1)` apart and the last must land inside the window. The
adapter sizes the inner datagram it accepts to the rate it is actually
achieving, and **refuses** one that would not complete rather than sending
fragments that expire: a half-delivered datagram wastes polls and delivers
nothing.

`max_packet` in each direction is that direction's own cell minus 18 —
115 B up (with the slot label), 391 B down with EDNS(0) — because §14.4
probes each direction independently. There is no single symmetric value.

### 2.5 Establishment

Path 0 carries the handshake, and the session is active once `AUTH_RESULT`
arrives (§14.2), so establishment is the handshake and nothing else. The
handshake runs with **`W = 1`** (§4.3.1), so its packets carry a slot
label of 0 and pay the 4-byte cost:

| step | bytes | cells (any zone, with the slot) | direction |
|---|---|---|---|
| `HANDSHAKE_INIT` | 122 | 2 | up |
| `HANDSHAKE_RESP` | 81 | 1 | down |
| `AUTH` (43-byte token) | 80 | 1 | up |
| `AUTH_RESULT` | 65 | 1 | down |

That is simpler than my last two revisions made it: the slot label costs
4 B of cell at every zone suffix in §2.4's table, so `_arc.io` — the one
case that used to fit a one-cell INIT — no longer does, and there is a
single establishment sequence rather than two.

A poll carries one uplink cell and returns one downlink cell. The INIT
needs two cells, so the relay cannot see a complete INIT until the second
poll, and `COOKIE_REPLY` comes back on that answer:

| poll | carries | answers with |
|---|---|---|
| 1 | INIT, cell 0 | `A1:-` |
| 2 | INIT, cell 1 | `COOKIE_REPLY` |
| 3 | INIT with cookie, cell 0 | `A1:-` |
| 4 | INIT with cookie, cell 1 | `HANDSHAKE_RESP` |
| 5 | `AUTH` | `AUTH_RESULT` |

The handshake uses **`W = 1`**, deliberately: it is a short exchange whose
packets are two cells at most, and a window would only complicate the
attempt/cell interleaving rule below. So the two-cell INIT's second cell
goes out on the very next poll, not `W` polls later, and the counts above
are the poll counts.

At 2 s per poll, the INIT phase takes **8 s of its 10**, leaving 2 s for
resolver latency on the response. That fits but with almost no slack: one
3-second resolver response anywhere in those four polls restarts the
attempt. That is why the adapter polls at the dial's rate from the first
INIT and gives up after three attempts rather than retrying inside a
window it cannot meet — and why §2.5's earlier note about transmitting
immediately matters, since the 2 s before poll 1 is otherwise spent
before the first byte reaches the resolver.

Without cookies, subtract two polls: the INIT phase is two polls (4 s),
leaving 6 s.

The two-cell INIT is a constraint on the adapter: `sendInit` retransmits
every 100 ms early and 1 s once quiet, while a poll is 2 s apart at the
ceiling, so the adapter must carry **cell 0 of one attempt, then cell 1 of
the same attempt**, on consecutive polls — the INIT bytes are stable
across retransmissions (`TestInitIsStableAcrossRetransmissionsAndCookies`),
so that works. It must not interleave two attempts' cells.

`HandshakeTimeout` is 10 s and applies to **each phase separately**: the
client restarts the whole handshake if `HANDSHAKE_RESP` has not arrived
10 s after the INIT phase started, and if `AUTH_RESULT` has not arrived
10 s after that (`Client.Tick`). The AUTH phase is one poll either way, so
it has 8 s of slack.

**The slack above is measured from transmission, and so is the deadline.**
`Client.Tick` compares against `attemptStart`, which `startHandshake` sets
when the session seals the first INIT — before the adapter has polled.
With a 2 s interval that is up to 2 s of the 10 s already spent when the
first byte reaches the resolver, so the long-suffix case has **0 s**
spare, not 2 s, unless the adapter transmits immediately. The
establishment sequence must therefore poll at once on `startHandshake`
rather than waiting out the first interval, and the timings in this
section assume that; §4.3.3's `Transmitted` applies to handshake packets
too, for the same reason.

**The two directions are independent, and my previous revision was wrong
about this.** I wrote that a single `max_packet` must be valid in both
directions, taking the smaller of the two. It does not: §14.4 probes each
direction independently because path MTU can be asymmetric, and this
carrier is *always* asymmetric — the uplink cell is capped by a 255-byte
name, the downlink by 3× the query.

| direction | cell | `max_packet` | inner IP per packet |
|---|---|---|---|
| client → relay | 133 B (with a slot label) | 115 B | 78 B |
| relay → client, no EDNS(0) | 168 B | 150 B | 113 B |
| relay → client, EDNS(0) 1232 | 409 B | 391 B | 354 B |

So the relay's `max_packet` is **391 B**, not 116, and four times more IP
fits a downlink packet than an uplink one. That matters for the whole
downlink story, and it means §2.6's fragment counts differ sharply between
the two directions rather than sharing one column.

### 2.6 What an IP packet costs

A full-name poll moves 133 B up and 409 B down with EDNS(0). Inner IP
traffic needs **one poll per ARC packet** (§2.4), and because the two
directions have different `max_packet` values they fragment differently:
**66 B of IP per uplink fragment, 354 B per downlink packet.**

| inner IP | up: fragments | at 6/min | at 30/min | at 120/min | down: polls (EDNS) | down (no EDNS, 113 B) |
|---|---|---|---|---|---|---|
| 40 B | 1 | yes | yes | yes | 1 | 1 |
| 66 B | 1 | yes | yes | yes | 1 | 1 |
| 150 B | 3 | **no** | yes | yes | 1 | 2 |
| 300 B | 5 | **no** | **no** | yes | 1 | 3 |
| 1,200 B | 19 | **no** | **no** | **no** | 4 | 11 |

The "at N/min" columns are §2.4.1's 5 s window applied to the uplink: one
66-byte fragment fits at 6/min, three (198 B) at 30, eleven (726 B) at 120.
The downlink is far more generous — 354 B per packet with EDNS(0), so a
300-byte answer is one poll and a 1,200-byte one four. Only a resolver that
does not honour EDNS(0) fragments the downlink at all.

That asymmetry is the practical argument for the rate dial: at 30/min the
downlink already carries 354 B per poll, which is more than most DNS
answers need, while the uplink is still limited to 198 B of datagram by
the 5 s window. Raising the rate helps the uplink roughly four times as
much as the downlink, and that gap is why the dial exists.

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
**three polls at 30/min and impossible at the 6/min floor**:

- Up: the query is 137 B of ARC packet, so 3 fragments of 66 B (the 5 s
  window at 30/min admits 3). At 6/min they are 10 s apart, the first
  expires, and the datagram is lost before it ever leaves the tunnel
  (§2.4.1).
- Down: 337 B of ARC packet against a 354 B one-packet budget, so **one**
  poll with EDNS(0) — or three fragments without it.

So the downlink side of a lookup is cheap and the uplink side is not,
which is the asymmetry §2.6 quantifies. At the 30/min default that is 6 s
and it works. At the 6/min floor the lifeline carries **control and
one-fragment datagrams only**, which means a DNS query to the client's own
resolver is the one common flow that still fits (a 30-byte answer is 67 B
of ARC packet, one fragment) while a query with a large response is not.
That difference is why §2.3's dial defaults
to 30 rather than to the floor.

That is a much narrower promise than my earlier revision made, and it
follows directly from the 5 s reassembly window. Messaging that sends one
small datagram at a time: reachable. A web page, or anything whose first
exchange exceeds 69 bytes: not. §6.2 of the profiling design's promise to
the user ("full tunnel unavailable") is what it should say.

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
zone leaves 222 wire bytes of room under `_arcb.example.net`, which is
four labels — 63 + 63 + 63 + 29, plus one length byte each. (A single
label reaches only 63, so "a few labels" is 3–4 depending on the zone, and
the adapter computes the split rather than assuming one.) The client
always sends the *bootstrap* profile first with its longest name, because
that maximizes the answer under any resolver's buffer; if the answer is
truncated or the authority signals a larger record, it retries once with
EDNS(0) 1232 and never sizes a query to the record it expects.

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
| 1 relay, `tls`+`udp`, 1 cover name, 1 zone, `_arc.example.net` | 153 B | **yes** | yes |
| 1 relay, `tls`+`udp`+`front`, 1 name, 1 zone | 172 B | no | yes |
| 2 relays, `tls` only, no names, `_arc.x.io` | 167 B | **yes** | yes |
| 2 relays, `tls` only, no names, `_arc.example.net` | 174 B | no | yes |
| 2 relays, `tls`+`udp`, 1 cover name, 1 zone | 196 B | no | yes |
| 3 relays, `tls`+`udp`, no cover names, 1 zone | 223 B | no | yes |

**The limit is 168 body bytes, and what fits under it depends on the
record.** A two-relay record does fit — 167 bytes — if the carrier zone is
short (`_arc.x.io`), each relay has one endpoint, and there are no cover
names. It is 174 bytes with `_arc.example.net` and does not fit. So "one
relay per record" is not a property of the grammar, and my previous
revision was wrong to state it as one: it is a **publication rule**.

The rule is this, and it is a policy choice for a reason:

> A bootstrap record SHALL carry one relay, so that its size does not
> depend on the zone suffix, the number of endpoints, or whether cover
> names are present. Deployments that must rotate publish several beacon
> names instead of several relays in one record.

That is chosen over packing relays in because the alternative is a record
whose fit depends on a zone name a client cannot control, and because
rotation needs **independent retirement**: `b1._arcb` can be republished
or allowed to expire without touching `b2._arcb`, whereas a two-relay
record requires rewriting both entries at once — during exactly the
outage rotation exists to survive. With §3.3's candidate iteration the two
names behave like a pool anyway.

A front endpoint costs 1 + 2 + 1 + len(domain) bytes per relay, which is
why `front` usually pushes a record over 168. The front's domain is needed
because the client must present it as the cover name, and it is not
derivable from the beacon's own name.

**The padding example needs four labels, not one.** The beacon zone leaves
222 wire bytes of padding under `_arcb.example.net`, and a label tops out
at 63 bytes: 63 + 63 + 63 + 29, with their length bytes, is 222. My
earlier "three labels of at most 63" could not reach it.

### 3.3 What the client does with it

- **When.** At startup, when a session cannot be established, and hourly.
  Every failed establishment attempt backs off (1, 2, 4, … minutes,
  capped at 30, with jitter) and re-queries. Never per poll, never as a
  heartbeat: the beacon is read-only data and its query rate is not a
  message rate.
- **Verification.** Signature first, then the time window: `not_after`
  must be in the future, and a beacon older than one already accepted
  **for the same beacon name** (by `published`) is discarded, which is what
  stops a replay of a previous rotation from steering the client back.
  Watermarks are per name (§3.4) — comparing `published` across two names
  would let a fresh `b1` shadow a still-valid `b2`. A beacon that fails
  either check is discarded and logged as a warning; there is no
  trust-on-first-use, because a forged beacon is exactly how a client
  would be steered to an adversary's relay, and the client's own Noise
  handshake would not notice — it authenticates whatever key it was told
  to expect.
- **Precedence.** The device's enrolled relay address is tried first,
  then the beacon's relays. A beacon cannot displace a working enrolled
  endpoint; it exists to replace one that is gone.
- **Acceptance is not selection, and selection is not final.** A record
  that verifies gives the client a *candidate list*, not a relay to use.
  The enrolled endpoint is candidate 1, the first beacon name's relays are
  candidates 2..n, the second beacon name's after them, and so on down the
  configured list. The client tries candidates in order and moves to the
  next on failure — connection refused, handshake failure, or a session
  that dies before it is stable.

  This matters more than it looks. A valid, unexpired record can name a
  relay that is simply **dead**, and re-querying the first beacon name
  will keep returning it: signature valid, `not_after` in the future,
  nothing wrong with the record. Without candidate iteration the client
  would loop on a correct answer to the wrong question, and the live
  replacement at `b2._arcb` would never be reached. So §3.5's two-name
  rotation depends on this rule, not just on §3.2's sizing.
- **The retry state is per candidate.** A candidate that failed is
  skipped for a cooldown (default 5 minutes, doubling to an hour) rather
  than retried first on the next attempt, so a list with one dead relay at
  the front does not cost a failed handshake every time.
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

**The rollback watermark is per beacon name, not per deployment.** The
client persists the newest `published` it has accepted **for each beacon
name** it queries, alongside the profile. A beacon older than *its own*
name's watermark is refused even if it verifies and its `not_after` is
still in the future — otherwise a restart, or a second device on the same
profile directory, would reopen the window in which the operator's
previous rotation of that name is still valid.

A single shared watermark across names would break failover, which the
review caught: `b1._arcb` can carry a newer publication naming a dead
relay while `b2._arcb` carries an older but unexpired one naming the live
standby. If `b1`'s publication advanced the shared watermark, `b2` would
be discarded as a rollback and the client would never reach the relay that
works. The records are signed independently over their own names and are
published at different times, so their clocks are not comparable and must
not be compared.

The watermark is written before that name's relays are adopted, so a crash
mid-adoption leaves a client that refuses the old record for that name
rather than one that accepts both.

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
- **Rotation uses two beacon names, not two relays in one record.** That is
  §3.2's publication rule, and it is chosen for independent retirement:
  the rotating deployment publishes `b1._arcb` and `b2._arcb`, each with
  one relay, and flips which one is current. A two-relay record would
  require rewriting both entries during the outage rotation exists to
  survive — and, with a longer zone or any cover name, would not fit a
  512-byte answer at all.
- **The staging test rotates for real:** enroll a device, stand up a
  second relay on the same store, publish a beacon naming only the second,
  and assert the device establishes a **new session on the replacement**
  with its existing credential and no operator action. Then leave
  `b1._arcb` as a valid record naming the now-dead first relay and assert
  the client still reaches the second — which is §3.3's candidate
  iteration, and the reason a valid record alone is not enough.

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

The cold-start sequence and its poll counts are in §2.5, which is the one
place they are stated. This section adds only the *rule*: a pre-auth reply
is sent in answer to a poll that carried a cell of the association, never
unsolicited, and an unbound association gets at most 8 such cells a
minute.

The relay's downlink queue for a bound association is drained one cell
per answer, FIFO, and any answer may carry the next cell even while the
query's own packet is still incomplete. An empty queue answers `A1:-`.

### 4.3 Polling

The client's poll loop is the path's entire clock, and with one exception
it is the adapter's, not the engine's. Rules:

- **Anything to send** (uplink cells queued by `WriteBatch`): one cell per
  query, back to back, up to the rate cap.
- **Downlink backlogged** (the last answer carried a full-size cell, or a
  datagram is mid-emission): poll again as soon as the cap allows. A
  response that spans several intervals is **normal, not a stall** — an
  admitted datagram takes `⌊(5 s − RTT) / interval⌋ + 1` polls (§2.4.1), so at
  6/min a three-fragment datagram occupies thirty seconds of polling while
  working perfectly. The poll loop must not back off, mark the path
  suspect, or count those intervals as failure: the same rule as a partial
  MTU probe (§14.4), which also leaves path health alone.
- **The exception, and the reason the loop is the adapter's:** with
  uplink cells queued the next poll is due at once, but with nothing
  queued the next poll is still due at the keepalive (§2.3). An idle
  session therefore polls by timer, carrying an encrypted `DATA`/`PING`
  cell, never an empty unauthenticated one (§16.5), so the relay can tell
  a live client from a curious resolver — and so a cell the relay queued
  unprompted actually gets collected.
- **Pacing.** A token bucket of `-dns-lifeline-rate` polls per minute —
  the dial of §2.3, default 30, floor 6 — and a separate per-resolver
  bucket, so a client cannot spend a shared resolver's patience. On
  `SERVFAIL`, `REFUSED`, `FORMERR`, or an answer later than the interval,
  the bucket drains and the interval stretches — but **never past the
  keepalive floor of §2.3**: the floor is what keeps the session alive, so
  backing off below it is not caution, it is a slower way to close the
  session. What backs off instead is what the poll carries: after three
  failures in a row the poll holds only a PING, and application cells
  wait.
- **Giving up is explicit.** A path that cannot meet the floor at all —
  answers arriving after the 15 s suspect threshold, five failures in a
  row, or establishment failing three times (§2.5) — is reported unusable
  and closed, rather than kept at a rate that makes the session flap.
- **One answer, one cell.** An answer that carries a cell which does not
  authenticate (a stale cache entry for a repeated name, a rewriting
  middlebox, an off-path injector) is discarded and the poll repeated
  with a fresh nonce. A rejected answer proves nothing about the path;
  only an absence of authenticated progress for the stall timeout does.

#### 4.3.1 The window: two polls in flight

The window exists so a slow resolver does not set the pace. With one poll
outstanding, throughput is `1/RTT`, so a client behind a 2 s resolver
cannot exceed 30 polls a minute however high its cap — which is a real
defect on congested hotel and mobile networks, independent of throughput.

**Rule: at most `W = 2` polls in flight.** Not a tuning knob; the reason
for exactly 2 is §2.3.1 — deeper windows buy throughput only alongside a
raised cap, and that pair is what becomes visible.

- **Slot in the name.** Each poll carries a slot number in a `1`-led label
  (§2.2.1), 10 bits, so a slot is 0 or 1 here and the field leaves room for
  a deeper window later without a grammar change.
- **The nonce identifies the query; the slot only routes it.** A slot is
  reused every `W × interval`, and a delayed answer can outlive its slot:
  poll *A* on slot 0 is delayed or lost, slot 0 is reused for poll *C*, and
  *A*'s answer then arrives labelled slot 0. Matching on the slot alone
  would deliver a stale answer to the wrong query — or, worse, hand the
  session a cell it has already rejected.

  The answer echoes the question (§16.5), so it carries the query's own
  13-character nonce. **The adapter matches on nonce**, and treats the
  slot as a routing hint for its per-slot reassembly state, not as
  identity. An answer whose nonce is not outstanding is discarded, which
  is the same rule §4.3 already applies to a rewritten or injected cell.
- **Answers are matched by nonce, not by order.** A resolver may return
  answers out of order; the adapter routes each by its nonce to the session,
  so at most `W` packets are outstanding and no reordering buffer beyond
  that is needed.
- **One cell per poll, still.** The window multiplies *polls in flight*,
  never *cells in a poll* — so every emission remains one cell and the PTO
  problem §2.4 solves stays solved.
- **Ordering for control.** Control frames keep going out on the lowest
  free slot; data may use either. Because the session's retransmission
  handles loss, slots are independent and no ordering is promised across
  them.
- **The rate cap counts polls, not slots.** Two in flight doubles how
  quickly the cap is *reached*, not the cap itself.

#### 4.3.2 Who asks the session for a packet

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
- **Backpressure, and the emission queue is bounded and explicit.** An
  admitted inner datagram needs several polls to emit (§2.4.1), so it
  cannot be "one packet in flight" — the queue holds the fragments of at
  most **one admitted datagram**, in order, plus control. That is a bound
  with a number: `max fragments per datagram` =
  `⌊(5 s − RTT) / interval⌋ + 1` (§2.4.1),
  which is 26 at 300/min and 1 at 6/min, so the queue is never unbounded
  and never silently grows with the rate dial.

  When the queue is full and more IP arrives, the adapter **drops new
  datagrams** rather than evicting fragments of one already in emission —
  evicting would waste the polls already spent. Control is never dropped
  and never queued behind a datagram: it takes the next poll, and the
  datagram's remaining fragments resume after. A dropped datagram is
  counted and reported (§5.3.1), and because ARC does not retransmit IP
  (§4.3.4) it is simply lost, which is the honest outcome.
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

#### 4.3.3 Timers must run from transmission, not from sealing

This is the finding that decides whether the carrier works at all, and it
is a change the session needs, not a rule the adapter can obey.

`conn.sealPacket` sets `sentAt: now` when it seals a packet, and
`flushTransmits` hands the datagram to `WriteBatch` immediately. On UDP
those are the same instant, so `sentAt` is when the packet hits the wire.
**On this carrier they are not:** the adapter holds the datagram until its
next poll, which is up to 10 s at the steady rate. So with `sentAt` at
seal time:

- PTO (691 ms before any RTT sample) fires while the packet has not been
  transmitted, `onPTO` retires it, the session re-seals a replacement, and
  the adapter discards both as obsolete. The session burns its PTO budget
  on packets it never sent.
- `path.healthy` reads `oldestOutstanding` from the same clock, so a path
  carrying traffic honestly looks stalled for the whole interval between
  polls.
- The RTT sample, when it finally arrives, measures poll latency plus
  resolver latency as though it were network RTT — inflating PTO for every
  later packet.

**Rule: a request/response carrier reports when it transmitted.** The
datagram handed to `WriteBatch` carries an opaque acknowledgment token,
and the adapter calls back with it when the packet leaves for the
resolver:

```go
// Datagram gains a token the carrier echoes when it transmits.
type Datagram struct {
    PathID   uint32
    Data     []byte
    AckEliciting bool
    Token    uint64   // opaque to the session; see Client.Transmitted
}

// Transmitted starts the session's timers for a packet the carrier has
// now actually put on the wire: PTO, the health clock and the RTT sample
// all count from here, not from sealing.
func (c *Client) Transmitted(now time.Time, id uint32, token uint64)
```

The session keeps a *sealed but untransmitted* packet in a pending list,
outside `sentLog`, and moves it in when `Transmitted` arrives. That is
where the 691 ms PTO belongs.

This is the second addition the carrier needs beyond `PollPacket` (§4.3.2),
and unlike that one it cannot be worked around in the adapter: only the
session knows what it sealed.

**Every pending send needs a terminal outcome.** "Retired without charging
PTO" is not enough on its own, or a packet can sit in the pending list
forever and the session never learns its frames were dropped. A pending
send ends in exactly one of three ways, and the session distinguishes
them:

| outcome | when | what the session does |
|---|---|---|
| **transmitted** | the adapter calls `Transmitted` with the token | enters `sentLog`; PTO and the RTT sample start here |
| **abandoned** | the adapter calls `Abandoned(token, reason)` — backpressure, an obsolete handshake attempt, a dead path | frames requeued if they are retransmissible (control, stream) and dropped if not (`IP_PACKET`); **no PTO charged** |
| **expired** | neither callback within `2 × W × interval` | treated as abandoned, and counted as an adapter fault, because the adapter promised one of the two |

`Abandoned` is the third method this carrier needs. Without it the session
cannot tell "the adapter refused this" from "the network lost this", and
its loss estimate — which drives the scheduler (§15.2) — would blame the
path for the adapter's queue.

**Fragment admission happens before emission, not after.** §2.4.1 limits
an inner datagram to what completes inside 5 s, and `conn.sendOn` fragments
*after* the session already decided to send. So the check must run where
the rate is known: the session asks the carrier for its current inner-MTU
before queuing an `IP_PACKET`, and refuses a datagram that would not
complete. An emission that starts and then discovers it cannot finish has
already spent its polls.

This is the fourth thing the session must learn about a carrier — after
`constrained`, `max_packet` and the token — and the first that is not a
constant but a live value the adapter updates as its rate changes (§2.3).

**A queued frame that does not fit the current reply is progress, not a
stall.** `AnswerFor(now, slot, maxPacket)` takes the arriving poll's
budget, so a frame queued when the path was getting 391 B answers may not
fit a 150 B no-EDNS answer. Three rules, and they are ordered:

1. **Send what fits.** `AnswerFor` packs as many whole frames as the
   budget allows, in queue order, and returns `true` if it sent anything —
   even an ACK alone. A frame is never split across answers, because
   `conn.transmitPacket` does not split frames and a split would need
   reassembly the session does not have here.
2. **A frame that does not fit is not a failure of the path.** It stays
   queued and the answer still counts as transmitted and ACKed, so the
   outstanding-age clock (§4.4.1) clears and the path stays healthy. The
   alternative — treating "did not fit" as "lost" — would mark a working
   path unhealthy every time a resolver dropped EDNS.
3. **A frame that cannot fit any answer for `2 × W × interval` is
   reported.** That is a genuine stall (a frame larger than any cell the
   path will ever carry, e.g. after a resolver permanently stopped
   honouring EDNS), so it is logged and the path is reported degraded. It
   is *not* retried forever, and it is not silently dropped either — the
   operator needs to know the resolver changed shape.

This is the case the review asked about and I had left implicit: "does not
fit" and "was lost" look identical to a timer, and they must not.

#### 4.3.4 What ARC does and does not repair

Two facts about the existing implementation bound this section, and my
previous revisions got both wrong.

**The relay cannot re-send a packet.** `conn.open` checks
`p.replay.Check(h.PacketNumber)` *before* decrypting, so identical
ciphertext is dropped as a replay: it never reaches `lastRecv`, the frame
parser, or an ACK. Only the *session*, which re-seals frames into a new
packet number, can retransmit anything.

**ARC does not retransmit IP payloads at all.** `conn.sendOn` passes an
IP packet as `ip` and its fragments as `extra`; `sentLog` stores only
`retx` — the control and stream frames — and `onPTO` returns `s.control`.
The comment on `sentPacket` says it plainly: "IP payloads never are
(§11)". So a lost downlink cell carrying an `IP_PACKET` or `IP_FRAGMENT`
is **not** repaired by ARC. It is repaired by whatever inner protocol
notices, or not at all.

That distinction has to be stated, because §5.4 says this path carries
application DNS:

| downlink content | lost cell means | repaired by |
|---|---|---|
| control frames (`PING`, `ACK`, `PATH_*`, `NEW_PATH`, `CLOSE`) | the packet never assembles | ARC's PTO re-seals the frames in a fresh packet |
| handshake (`COOKIE_REPLY`, `HANDSHAKE_RESP`, `AUTH_RESULT`) | the packet never assembles | the client's own retry (INIT/AUTH timer), or one re-emission |
| `STREAM` data | the packet never assembles | ARC's PTO, via `onStreamLost` |
| `IP_PACKET`, `IP_FRAGMENT` | the datagram is **lost** | the inner protocol: TCP retransmits, DNS retries, QUIC retransmits |

**So application IP over this path is best-effort, and the spec says so
rather than implying otherwise.** That is a change to §5.4's promise: the
lifeline carries a name lookup because the resolver retries it, not
because ARC guarantees the delivery. A UDP inner flow that does not retry
gets what it gets. This is the same guarantee the tunnel gives any path —
ARC never retransmitted IP — but on a path with multi-percent cell loss it
matters enough to write down.

**One cell per packet makes all of this simple.** With `max_packet` at the
cell budget (§2.4), every packet is one cell, so:

- **There is no cursor and no partial assembly.** A cell either arrives
  and reassembles into a complete packet, or it does not and nothing is
  half-built. The §12.1 expiry never fires for this carrier.
- **There is no emitter state per packet.** The adapter sends the next
  datagram `WriteBatch` gives it, one per poll. If it is lost, the session
  either re-seals it (control, handshake, stream) or does not (IP).
- **PTO cannot preempt an emission**, because an emission is never
  longer than one poll — which is the bug §2.4 exists to prevent.

**Two rules about who may be dropped, and the first one was wrong:**

- **An ACK owed to an ack-eliciting packet is never dropped.** My previous
  revision said ACK-only packets are "dropped rather than queued", and
  that makes liveness impossible on this carrier: an idle client polls with
  `DATA`/`PING`, the relay owes it an ACK, and if the ACK-only answer is
  dropped the client's `lastRecv` never advances — so the path goes
  `SUSPECT` for the crime of being idle.

  The rule is instead: **a poll's answer always carries the ACK it owes, if
  any**, and it does so inside the *same* ARC packet as any other downlink
  frames — `conn.transmitPacket` already piggybacks `p.acks.peek()` when it
  fits, so an ACK costs 24 framed bytes of the packet rather than an extra
  poll. At `max_packet` 118 that leaves 94 B for control frames, which is
  everything this carrier ever has queued on an idle session. Only when
  there is *nothing* else to send is the answer an ACK-only packet — and
  that packet is the single most important one this carrier sends, because
  it is what keeps an idle session alive.
- **An answer with no ACK and no cell is `A1:-`**, unchanged. It is a fact
  about the path, not the session (§4.4), and it is what an idle client
  sees when the relay owes nothing.

**The relay needs a poll-scoped way to build its answer.** The ACK rule
above assumes `conn.transmitPacket` piggybacks a pending acknowledgement,
but that path is push-driven: the relay seals a packet when it has frames
to send, and an idle session's PING can arrive when it has none. The ACK
it owes is then sitting in `p.acks` with nothing to carry it.

So the relay side needs the same shape as the client's `PollPacket`:

```go
// AnswerFor seals the reply to one poll: any due acknowledgement, then
// one downlink cell's worth of frames, in one packet. maxPacket is the
// answer budget for THIS poll (the resolver's declared buffer, capped at
// 3x the query), so a cell is never sealed larger than the answer that
// will carry it. It is called when a poll arrives, not when the relay has
// something to say. It reports false only when the session is gone.
func (s *RelaySession) AnswerFor(now time.Time, slot uint8, maxPacket int) (RelayDatagram, bool)
```

Called from the relay engine's loop when the adapter hands up a poll, with
the budget that poll's query allows. Three properties matter:

- **`maxPacket` comes from the poll, not from the session.** The answer
  cell is `min(resolver buffer, 3 × query)`, which varies per query — 168 B
  without EDNS(0), 409 B with it — so a session fixed at 391 B would seal
  packets that a no-EDNS poll cannot carry. The relay applies the same
  asymmetric rule as the client (§2.4) and it is the *arriving* query that
  sets it.
- **The ACK is included even when nothing else is**, which is what makes
  an idle session's `lastRecv` advance (§4.4.1). Without this method the
  relay has no way to produce that packet.
- **The answer is poll-scoped, so recovery starts from *its*
  transmission** — the same problem as §4.3.3, mirrored. A relay
  `RelayDatagram` gains a token, and the adapter calls
  `RelayTransmitted(token)` when the answer leaves for the resolver.
  Otherwise the relay's PTO fires on answers the adapter is still holding,
  and its RTT samples poll latency, exactly as on the client side.
- **The relay's ack timeout is `W × interval + RTT`, not `RTT` and not one
  interval.** Two polls are in flight, so the client may already have sent
  slot 1 before slot 0's answer returns; it cannot acknowledge slot 0 in a
  poll that has left. The next opportunity is the *reuse* of slot 0, which
  is `W × interval` after it was issued:

  | rate | W | interval | timeout at RTT 0.5 s | vs PTO 0.69 s |
  |---|---|---|---|---|
  | 6/min | 2 | 10 s | 20.5 s | 30× too short |
  | 30/min | 2 | 2 s | 4.5 s | 6.5× too short |
  | 120/min | 2 | 0.5 s | 1.5 s | 2.2× too short |
  | 300/min | 2 | 0.2 s | 0.9 s | 1.3× too short |

  My previous revision said one interval, which is right for `W = 1` and
  wrong by an interval once a second slot exists. At 6/min the relay would
  have re-sent every multi-poll transfer long before its ack could arrive.

**And one correction on `AUTH_RESULT`.** My earlier table said "the
client's first `DATA` or `ACK`" proved it arrived. It does not:
`Client.Tick` repeats `AUTH` in *new* DATA packets until the result comes
back. The relay retires that packet on one emission instead, and answers
whatever AUTH arrives next.

Tests: a loss-free IP packet within the reassembly window at both rates
completes with the path never `SUSPECT`; an IP packet needing more
fragments than the rate allows is refused rather than half-delivered
(§2.4.1); an IP packet with one cell lost is not repaired by ARC and its
absence shows in the path's loss estimate; a lost control packet recovers
by PTO re-seal; an idle session keeps `lastRecv` advancing because its
PING is answered with an ACK; a relay answer held by the adapter fires no
relay PTO until `RelayTransmitted`; and an abandoned send requeues its
control frames without charging PTO.

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

#### 4.4.1 Liveness needs a whole packet, and one cell gives one

`path.healthy` has **two** clocks, and the one I had not accounted for
binds first:

```go
limit := suspectPTOs * p.rtt.pto()          // 3 × PTO
if now.Sub(p.lastRecv) > idleLimit(...) { return false }
t0, ok := p.sent.oldestOutstanding()
return !ok || now.Sub(t0) < limit || silent < limit
```

The second clause — an outstanding packet older than `3 × PTO` — is
stricter than the silence threshold, and at a 10 s poll interval it
dominates. With `sentAt` finally meaning transmission time (§4.3.3), a
PING transmitted at poll *n* and **not** acknowledged stays outstanding
for the whole 10 s to poll *n+1*, and `3 × PTO` is under 3.3 s for any RTT
below about a second. So an unacknowledged poll marks the path unhealthy
long before it is silent.

That makes §4.3.4's rule that a poll's answer always carries its ACK not a
courtesy but **the health mechanism**: it is the only thing that clears
`oldestOutstanding` between polls.

| rate | interval | `lastRecv` age | outstanding age if the ACK is lost | `3 × PTO` at RTT 0.2 s |
|---|---|---|---|---|
| 6/min | 10 s | 10 s | 10 s | 0.68 s |
| 30/min | 2 s | 2 s | 2 s | 0.68 s |

**The deadline is asymmetric, and both directions must use their own.**
This is the same asymmetry as §4.3.4's ack timeout, and I had applied it to
recovery but not to health — which means the relay would have marked every
multi-poll downlink unhealthy while it was working correctly.

The client's deadline can be `3 × PTO` because a poll it sends is
acknowledged in the answer to *that* poll. **The relay's cannot**: it
transmits an answer immediately, but the ACK cannot arrive until the
client's next poll, `W × interval` later. So for a packet the relay sent,
the outstanding-age clause must be measured against
`W × interval + 3 × PTO`:

| rate | W × interval | relay's limit at RTT 0.2 s | client's limit |
|---|---|---|---|
| 6/min | 20 s | 20.7 s | 0.68 s |
| 30/min | 4 s | 4.7 s | 0.68 s |
| 120/min | 1 s | 1.7 s | 0.68 s |

Without that, a relay at 6/min would call its own answers lost 0.68 s after
sending them, thirty times before an ACK was possible — the same error the
ack-timeout finding caught, in the health clock rather than the
retransmission one. Both now derive from one place: **the carrier reports
its `W × interval` to the session, and the session adds it to every
deadline that waits on the peer's next poll.**

Two consequences:

- **One lost ACK is one unhealthy sample, not a dead path.** The clause
  makes the path unhealthy immediately, but `healthy` is a *predicate*,
  re-evaluated every tick, and the next answered poll makes it true again.
  Nothing in §14.6 kills a path for one unhealthy interval; `SUSPECT` is
  entered after repeated evidence, and the path returns to healthy on the
  next packet. The spec should say this so an implementer does not turn a
  single lost ACK into a path failure.
- **The adapter must not batch polls to "save budget".** Polling every
  10 s is what the keepalive requires; polling every 30 s to be frugal
  would leave an outstanding packet for 30 s and the path unhealthy for
  two thirds of that, which is not a saving.

With one cell per packet and an ACK in every answer, both clocks stay
satisfied: `lastRecv` ages by one interval and nothing stays outstanding
past one round trip. The requirement on any future adapter is therefore
two-part: **every poll must carry one whole packet, and every answer must
carry the ACK it owes.**

**The window of §4.3.1 does not change this, and that is deliberate.** Two
polls in flight means two outstanding packets, so `oldestOutstanding`
returns the older one — but it is only one poll interval old, not two,
because the second slot is issued in the *same* interval. The clocks above
are therefore unchanged by `W = 2`, and a deeper window would be too: what
matters is that a slot is issued every interval and answered before the
same slot is reused. That is why the window is safe where a longer poll
interval would not be.

What a deeper window *would* change is the **reuse deadline**: slot 0
cannot be reissued until its previous answer has arrived or been declared
lost, or the adapter cannot tell the two apart. At `W = 2` that is a
one-interval constraint and never binds; at `W = 8` with a 2 s interval in
flight against a 5 s resolver it would, and the adapter would have to
stall the loop or drop the slot. That is a further reason not to grow the
window without also growing the sequence field (§2.2.1) and the reorder
story.

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

The byte caps are stated in **hours at a reference rate**, because the
rate is now a dial (§2.3) and a fixed byte cap means different things at
different rates. Four caps:

| cap | direction | counts | default | full hour at 30/min | exhausts at 300/min |
|---|---|---|---|---|---|
| `-dns-lifeline-rate` | both | polls/min, the dial of §2.3 | 30, floor 6 | — | — |
| `-dns-lifeline-up-bytes` | client→relay | cell payload sent | 128 KiB/h | 236 KiB/h, so **binds** | in ~3 min |
| `-dns-lifeline-down-bytes` | relay→client | cell payload received | 512 KiB/h | 719 KiB/h, so **binds** | in ~4 min |
| relay per resolver and per zone | queries | real source address, §5.3.2 | operator | — | — |

- **The caps bind at the default rate too, which is the point.** A client
  that polls flat out at 30/min for an hour would send 236 KiB and receive
  719, so the 128/512 defaults let it do so for roughly 33 and 43 minutes
  respectively. That is a real limit on a genuinely active hour, and it is
  the *bytes* that bind rather than the rate.
- **Raising the dial spends the same budget faster.** At 300/min the
  defaults exhaust in 3–4 minutes, so a client that wants sustained
  throughput raises the byte caps as well — deliberately, and per the
  operator's judgement about their resolver. The rate dial alone does not
  buy throughput; it buys *burstiness* within a fixed allowance, which is
  the honest way to expose it.
- **The caps are per hour wall-clock**, not rolling windows, so exhaustion
  is a clean boundary a test can hit, and the reset is predictable.
- **Exhaustion carries control only**, at the floor of 6/min: keepalives
  and ACKs continue, and every other frame waits for the next hour or the
  path to be closed. Control cannot be throttled further without killing
  the session (§2.3) — and §5.3.1 explains that this must be enforced in
  the relay's session, where frames are classifiable, not at the
  nameserver.
- **What survives path replacement.** The caps belong to the *device*, not
  the path: a lifeline that dies and reopens, or moves to a second relay,
  keeps counting. Otherwise closing and reopening the path would be a
  trivial way to reset the budget, which is the one thing an operator's
  resolver must not see.
- **The relay keys its copy on the authenticated device, not the
  association.** This is the one place the relay's accounting must not
  follow the transport. An association's synthetic address (§4.2.1) is
  deliberately per-association, so a relay that counted per association
  would reset its quota every time the path reopened — exactly the reset
  the client already refuses. The authoritative server therefore charges
  the bound **device identity** (the token's device, from `AUTH`), and it
  keeps a small table of per-device usage for the hour. Before a device
  has authenticated there is nothing to charge, so the pre-auth path keeps
  its own per-association budget (§4.2.2) and nothing else.
- **Cross-relay continuity is client-side only, and that is stated.** Two
  relays serving one deployment do not share usage counters — nothing
  reads the accounts store for this, and adding that would put a write on
  the hot path of every poll. So a device that alternates between two
  relays is bounded per relay, twice its own cap in the worst case. That
  is acceptable because the client enforces its own device-wide budget
  first (§5.3.1 meters before sealing); the relay's copy is a backstop for
  a misbehaving client, not the primary limit.
- **The exhaustion test reconnects on a new association:** the same
  authenticated device exhausts its allowance, closes the path, opens a
  new association, and the relay still answers `A1:-` — which is the
  assertion that the quota is keyed on the device.

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

**And the relay must enforce it in its session, not at the nameserver.**
§5.3 says the relay enforces its own per-device copy and that exhaustion
leaves control flowing — but those two requirements contradict each other
if the cap is metered at the authoritative server, which sees only
encrypted cells. A single byte cap over cell payload cannot distinguish a
keepalive from an application packet, so once the relay charged a device
to its limit it would reject the very polls that keep the session alive,
and the session would die of budget instead of surviving on control.

A class marker in the query name would fix it on the wire — the §2.2.1
grammar has room for one — but it costs another label of every cell (and
it would let a client lie about which class it is spending). Since the
slot label already costs 4 wire bytes and has taken the handshake to two
cells at every zone size (§2.5), a second label would start eating into
payload at the shorter zones too. The better place is where the frames are
already visible:

- **The nameserver charges only what it can see:** queries per real source
  (§5.3.2) and the pre-auth per-association budget (§4.2.2). Both are
  properties of the DNS channel, and both are cheap to enforce without
  decrypting anything.
- **The relay's session charges the device**, after reassembly and
  decryption, using exactly the frame classification §5.3.1 defines for
  the client. It is the same rule on both ends, so there is nothing to
  coordinate and nothing to lie about.
- **Control is therefore uncapped on the relay side** by construction:
  PINGs, ACKs and handshake frames are admitted by class before the
  application allowance is consulted. The relay's cost is bounded by the
  rate limits it already applies (§9.2, §9.3), not by the byte quota.

The cost of doing it here is that the relay decrypts a packet before it
learns the device is over budget. That is bounded work — one cell, one
packet, under the handshake and rate limits — and it is the same work it
was going to do anyway to forward the packet.

Test: an exhausted relay-side *application* allowance with authenticated
keepalives still flowing, and a session that survives to the next window.

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
- **IP traffic, but only what one fragment carries below the ceiling.**
  The narrowness is forced by numbers, not caution: at the steady 6
  polls/min only a single 66-byte fragment reassembles inside the 5 s
  window (§2.4.1), so a 100-byte DNS query is *impossible* there and a
  30-byte answer is the largest comfortable datagram. At the default three
  fragments fit (198 B). Application DNS still gets a reserved slice of
  the budget — the first 4 KiB/hour of downlink, marked as a privileged
  flow by the session (§5.3.1) — but a query that does not fit one
  fragment is **refused**, not slowly attempted: a half-delivered datagram
  wastes a poll and delivers nothing.
- **Everything else, subject to §15.2 item 6.** A flow is placed here
  only when nothing else is validated, and only while its packets fit the
  current fragment budget. Messaging that sends one small datagram at a
  time: reachable. Anything whose first exchange exceeds 69 bytes needs
  the path to be at its ceiling, and the adapter will say so rather than
  stall.
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
| Everything but DNS blocked (`iptables` default drop, resolver allowed), **cookies required** | A session establishes over the DNS path alone inside one handshake attempt (10 s per phase) in the polls of §2.5, and a ping through the tunnel gets its reply within two polls |
| Beacon queried cold, no session possible | The client sends the fixed 271-byte bootstrap query, learns endpoints and cover names from a signed record, and logs the regime |
| Beacon forged (signature flipped), replayed past `not_after`, **rolled back per name after a restart**, sinkholed by a wildcard | Each is rejected and logged; the client falls back to its enrolled relay and never adopts a retired key for a new connection |
| `b1` newer but naming a dead relay, `b2` older but naming the live one | Both are accepted: the watermark is per name (§3.4), so `b2` is not discarded as a rollback, and the client establishes on it |
| Beacon answer above 3× the query | The nameserver refuses it; a client that stops padding gets no beacon and says so |
| Beacon too large for the bootstrap profile (a `front` endpoint, or a long zone) | No answer in the 512-byte profile; the client retries with EDNS(0) and succeeds there, and logs which profile it used |
| A legal two-relay record (167 B, `_arc.x.io`) | Accepted in the 512-byte profile even though the publication rule asks for one relay per record, so a client is not broken by an operator who packs two |
| Full-length uplink cells against a 512-byte answer budget | The downlink cell is 168 B, not the 243 B a padded short query gets — a client that fills the name loses downlink — and no answer exceeds 3× its query |
| A padded name carrying a cell | The padding labels reassemble away and exactly one cell is recovered; a `0`-led label is never read as cell data |
| **A loss-free IP packet split into 2 fragments at 30/min, real engine timers** | Both arrive inside the 5 s reassembly window, and the path never goes `SUSPECT` (PTO counts from transmission, §4.3.3) |
| **The same 2-fragment packet at 6/min** | Refused rather than half-delivered: the first fragment expires before the second is sent (§2.4.1), and the adapter reports the path control-only |
| **An IP packet whose single cell is lost** | ARC does **not** retransmit it; the loss shows up in the path's loss estimate and the inner protocol retries. Asserted explicitly so nobody assumes a repair that does not exist |
| **An idle session's PING is answered with an ACK** | `lastRecv` advances every poll and `oldestOutstanding` clears, so the path stays healthy indefinitely with nothing else to send (§4.3.4, §4.4.1) |
| **A lost ACK makes one unhealthy sample, then recovers** | The path is not declared dead: the next answered poll restores health (§4.4.1) |
| Resolver retries a query whose answer was lost | Harmless: the repeated name gets the same emission, and since identical ciphertext is dropped by `p.replay.Check`, nothing depends on it |
| A downlink cell lost carrying control frames | Recovers by PTO re-seal into a new packet number (not by re-sending the old bytes) |
| **The seal-to-transmit gap does not fire PTO** | A datagram held by the adapter for 10 s produces no PTO and no health dip until `Transmitted` is called (§4.3.3) |
| **Relay-side application allowance exhausted, authenticated keepalives flowing** | The session survives to the next window: the relay meters in its decrypted session, so control is admitted by class and never charged to the application allowance |
| A `HANDSHAKE_INIT` split across two polls (long zone) | The adapter carries cell 0 then cell 1 of the *same* attempt, and the relay reassembles it; interleaving two attempts fails to reassemble and is a test in its own right |
| **The rate dial at 120/min, two polls in flight** | Throughput reaches `min(rate, W/RTT)`: at 0.5 s RTT that is the full 120/min, where window 1 would give 120 too but a 2 s resolver gives 60/min instead of 30. The test asserts the *formula*, not a fixed number |
| **Answers arriving out of order across the two slots** | Each answer is matched by the query's nonce, not its slot, so a delayed slot-0 answer cannot be delivered to a reused slot 0 (§4.3.1) |
| **A stale answer whose slot has been reused** | Discarded, because its nonce is no longer outstanding — the failure the slot-only rule would have had |
| **A slot reused before its answer returns** | Impossible at `W = 2`: slots are issued one per interval and the previous answer is back or declared lost first (§4.4.1) |
| **The relay's ack timeout is `W × interval + RTT`** | At 6/min that is 20.5 s, not 10.5: the client may already have sent slot 1 before slot 0's answer returns, so slot 0's reuse is the next opportunity (§4.3.4) |
| **A no-EDNS poll gets a no-EDNS answer** | `AnswerFor` is given the arriving poll's budget, so it never seals a 391 B packet into a 150 B answer (§4.3.4) |
| **The emission queue is bounded** | At most one admitted datagram's fragments, `⌊(5 s − RTT) / interval⌋ + 1` of them, and control always takes the next poll ahead of a datagram's remaining fragments (§4.3.2) |
| **The dial raised mid-session** | The inner-MTU grows with it, so a datagram refused at 6/min is accepted at 120/min without a reconnect (§2.4.1) |
| **The dial at its default leaves the zone unremarkable** | At 30/min the journal shows 0.5 q/s; a test asserts the configured rate is what is actually offered, so no code path quietly raises it |
| Answer budget shrinks mid-transfer (EDNS → no EDNS) | The emission re-splits to the smaller budget and reaches the tail; no cell is stranded waiting for a larger poll |
| A client receives but rejects a cell (a middlebox rewrote it) | The packet fails to assemble, is dropped at the assembly window, and a whole fresh copy is sent after the PTO |
| A control packet with its single cell lost | Recovers by PTO: the session re-seals the frames into a new packet with a new number, since replayed ciphertext would be dropped |
| `AUTH_RESULT` lost, client sends another AUTH | The session still establishes; the relay does not treat the retried AUTH as a receipt for the missing result |
| Resolver changing source port and egress between the two INITs | Cookies still verify, because they key on the association's synthetic address (§4.2.1), not the resolver's |
| A downlink-only transfer with no uplink work | The client's backlog polls each carry a fresh demand-PING, so packets drain at the ceiling rather than one per keepalive |
| Resolver rewriting TXT content / truncating / caching stale cells | Cells that do not authenticate are discarded; the path is not declared dead until the stall timeout |
| Resolver returning `SERVFAIL` at 20 polls/min | The path keeps the 6/min floor with PING-only polls, sheds application cells, and either recovers or is reported unusable — it never backs off below the floor |
| A faster path available | The DNS path stops polling within one idle interval and carries no flows |
| Application allowance exhausted with data queued in both directions | Control continues at the 6/min floor; application packets are dropped by the session, not queued; drops are counted per direction; closing and reopening the path, **or opening a new association**, does not reset the counters (§5.3) |
| Full tunnel with managed DNS active (`~.` on the tunnel) | The lifeline keeps answering; the journal shows the physical link's upstream, never `127.0.0.53` or a loopback stub |
| `-allowlist` without `-dns-lifeline` | No DNS carrier is opened; the status line says it was not configured, not that the network refused it |
| 300-byte application DNS answer through the tunnel | Completes in the poll count §2.6 gives for the zone; the journal records the wire cost |

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
   required** in the cold start of §2.5, and then holds 10 minutes with
   its path never going `SUSPECT` — which needs authenticated keepalive
   *replies*, since `A1:-` cannot advance session liveness (§4.4). That is
   why this stage is bidirectional for control; application downlink is
   still stage 3.
3. **Downlink data.** One cell per ARC packet (§2.4), the inner-IP limit
   of §2.4.1, backlog polling with `demand`, and the best-effort
   statement of §4.3.4 in the journal — an IP packet lost to a cell is not
   repaired by ARC. Exit: a one-fragment datagram completes at the steady
   rate with the path never `SUSPECT`, a two-fragment one completes at the
   ceiling and is refused below it, and a downlink-only transfer drains at
   the ceiling.
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

What the lifeline does need beyond the adapter is eight additions, all
named where they are argued. They split into the four the client needs,
three the relay needs, and one that is neither:

**Client side:**

- a **constrained** flag, a `max_packet` per direction, and a live
  **inner-MTU** value on the path (§2.4, §2.4.1, §4.1);
- a **`PollPacket(now, id, demand)`** query, called from the engine loop
  rather than the adapter's timer (§4.3.2);
- a **`Transmitted(now, id, token)`** call so timers start when the packet
  leaves, not when it was sealed (§4.3.3) — the one addition the adapter
  cannot work around;
- an **`Abandoned(token, reason)`** call so every pending send has a
  terminal outcome and the adapter's queue is never blamed on the path
  (§4.3.3);
- a **per-path allowance** admitted before sealing (§5.3.1);
- a **synthetic peer address** per association, routed like
  `stream.IsStreamAddr` (§4.2.1).

**Relay side:**

- **`AnswerFor(now, slot)`** so a poll's answer can be built when the poll
  arrives rather than when the relay has something to say (§4.3.4);
- **`RelayTransmitted(token)`** and a relay ack timeout of
  `poll interval + RTT`, since the ACK of an answer cannot arrive before
  the next poll (§4.3.4).

**Neither, but required:** the answer to every poll carries the ACK it owes
(§4.3.4), because `oldestOutstanding` would otherwise mark an idle path
unhealthy between polls (§4.4.1).

The window (§4.3.1) adds no further surface: it reuses `PollPacket` twice
per interval and needs only the slot label in the name grammar (§2.2.1).

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
