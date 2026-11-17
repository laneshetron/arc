# ARC — Surviving the hosting freeze and the UDP ban

**Status:** draft design. Extends `network-profiling.md` §6.2 (regime →
carrier mapping) and §8 (reliability mechanics, carrier error taxonomy).
`mini-tspu` (a separate repository modelling TSPU as an inline bridge) is
the reference censor; its README cites the field reports.

## 1. The two behaviours

**The freeze.** A TCP flow opened from inside Russia to a "foreign hosting"
prefix stops delivering server→client data once it has carried about
16 KB from the outside (15–20 KB reported; a later report says ~25 data
packets in either direction). There is no RST and no FIN: the censor
drops the outside's packets silently, and the client's packets still pass.
SSH is exempt. Each new TCP connection gets a fresh budget.

**The UDP ban.** More than ~25 datagrams on a UDP flow to a hosting
address get *all* traffic between the two addresses dropped, TCP
included, for about 10 minutes. Trigger and length are anecdotal.

Measured on arc main @390eb4d with the relay on a hosting address behind
mini-tspu (Docker, 2026-11-16):

| Client | Outcome |
|---|---|
| `-no-udp -front` | Session up; frozen within 16 KB; iperf gets 0 bytes after the first second. arc stays on the dead TCP connection for 25 s or more and never redials. |
| default (UDP + `-front`) | UDP ban fires ~100 ms after the session starts and also kills the front to the same IP. |

Both are failures of objective 1 (keep *any* stable connection): the
first because the stream carrier cannot tell a frozen connection from an
idle one, the second because the client volunteers the one packet shape
that burns the relay's address.

## 2. Detecting a stalled stream carrier

The stream carrier today learns a connection is dead only from the
kernel: an RST, a FIN, or TCP's own retransmission timeout, which takes
~15 minutes (`tcp_retries2`) and never fires while the peer's ACKs keep
arriving. The session notices sooner (its path turns suspect after 3 PTOs
and is abandoned after 30 s of silence, §14.6), but abandoning the path
does nothing to the TCP connection under it: the carrier keeps writing
into the same frozen connection, and rejoining puts the path back on it.

**Rule.** A client stream connection is *stalled* when it has written at
least one frame since it last read one, and the oldest such write is
older than the stall timeout. The carrier then closes the connection,
reports `timeout-at-N-bytes` (§8 taxonomy, `At` = bytes exchanged), and
redials.

- *Bytes in flight but no progress* is measured at the frame layer, not
  from `TCP_INFO`, so it works the same on every OS and through every
  TLS profile. A read of any frame is progress. An idle connection
  (nothing written) never stalls, so keepalive spacing is irrelevant.
- **Stall timeout:** 2 s by default. The
  session already sends a PING at least every PTO on a suspect path
  (§14.1), so a frozen connection has writes outstanding within one PTO
  of freezing, and the relay answers any ack-eliciting packet within a
  round trip. 2 s is above the RTT plus queueing of any link arc should
  still call usable; a false positive costs one TCP+TLS handshake and a
  §14.5 address validation at the relay, not the session.
- **Redial pacing.** A connection that delivered at least one frame
  before it stalled resets the reconnect backoff and redials at once:
  stalls themselves bound the rate to one dial per stall timeout, so this
  is not a retry storm (§7). Dials that fail keep the existing doubling
  backoff.
- **The relay side** needs no change for correctness: the client's new
  connection is a new synthetic address, which the relay validates and
  migrates the path to (§14.5) in one round trip. The frozen connection on
  the relay idles out (5 min) or fails on its own.

`timeout-at-N-bytes` was already in the taxonomy for deaths the kernel
reports as timeouts; a stall is the same failure mode found sooner, and
the profiler should treat them alike. `reset-at-N-bytes` is its sibling
for censors that inject RSTs instead.

## 3. Rotating stream connections before the cap

Detection alone turns the freeze into a sawtooth: ~16 KB, a 2 s stall, a
redial. That survives, but at a few KB/s. To keep data moving, the
carrier must leave a connection *before* the censor freezes it.

**Learned budget.** The carrier keeps the `At` of its stalls. A stall is
evidence of a byte cap when its connection received roughly the same
amount as the previous stalled connection did (within 25 %), both above
a floor (4 KB, below which a stall is not a cap but a dead link). Two
agreeing stalls (hysteresis, §8) set a rotation budget of half the
smaller received count. That's `bulk_throttle = after-N-bytes` in the
profile (§6.1). A configured budget (`-stream-rotate-bytes`) skips the
learning, for a profile that already knows the regime.

**Make before break.** Once a budget is known, the carrier keeps one
spare connection dialed ahead (TLS and any front upgrade done, nothing
sent on it yet). When the current connection has received its budget,
the carrier *writes* only on the spare and keeps *reading* both, then
dials the next spare. The relay sees authenticated packets from a new
synthetic address and migrates the path's downlink there (§14.5); until
then it keeps sending on the old connection, which still has the other
half of the cap. The old connection is closed one stall timeout after
the switch. A spare older than a minute is replaced before use.

The relay's downlink lag is the weak point: whatever the relay has
queued or sent on the old connection past the cap is lost (the inner
connections recover it), and §14.5 holds the downlink there for a
validation round trip. Moving it at once for stream-to-stream changes
is safe (a stream address is a TCP connection that completed TLS with
the relay, and its packets cannot be captured for replay), but the
measured gain decides whether it is worth the special case.

**Cost and limits.** Throughput is bounded by budget per connection
setup: with a warm spare, the switch itself costs about one round trip,
but each connection still costs a TCP+TLS(+front upgrade) handshake,
3–4 RTTs, per ~8 KB of downlink, so the dial rate bounds it: at a 50 ms
RTT, ~40–60 KB/s. This is a survival mode,
not a data plane: enough for messaging and a usable web, not for video.
Pre-dialing several successors would multiply it, at the price of many
short, same-sized TLS connections to one address, a shape a classifier
can learn. Rotation makes the session survive; it does not hide it.
The packet-count variant of the freeze (~25 packets, both directions)
is not covered by a byte budget; a packet budget is the same mechanism
and is deferred until a field report confirms that variant.

**Versus a domestic hop.** The freeze applies only to flows to foreign
hosting prefixes. A relay (or a plain TCP forwarder) on a domestic,
non-hosting address is not frozen at all, and its own uplink to the
foreign relay crosses no TSPU. That gives full throughput with no
rotation, and it is the right answer whenever a domestic host is
available; it is an infrastructure question (rendezvous and relay
distribution, `network-profiling.md` §10), not a carrier one. The two
compose: rotation is what keeps a session alive between losing a
domestic hop and getting the next one, and what a client does when it
was only ever given a foreign relay.

## 4. Holding UDP back under a censorship posture

The UDP ban turns a carrier that works for a fraction of a second into a
10-minute outage of *every* carrier to that address. The profile cannot
discover it safely: probing UDP to the relay (P1) is exactly what burns it.

**Rule.** Under a censorship posture (`-censorship`, opt-in, as every
camouflage behaviour is, §1), the client opens no UDP carrier to an
address that a stream carrier also uses. The relay is presumed to sit on
foreign hosting: the regime that matters (hosting + censorship) cannot
be measured without risk, and the cost of the presumption (no UDP to that
address) is small next to a 10-minute outage.

- UDP to a *different* relay address is not held back: a ban there costs
  only that address. That is the hook for a sacrificial UDP endpoint once
  relays have more than one address.
- Learned rotation (§3) and the freeze it answers are independent of the
  posture: rotation acts only on observed stalls, so it is on by default.
- Without the posture nothing changes: UDP stays primary (§6.2, `open`).

This is the §6.2 row "QUIC throttled/blocked → demote UDP carriers"
taken one step further for hosting: under a censorship posture to a
hosting address, UDP is not merely demoted but not sent.

## 5. Testing

`test/netns/tspu.sh` runs arc's client through the mini-tspu bridge with
the relay on a hosting address and asserts:

| Scenario | Assertion | Main @390eb4d |
|---|---|---|
| Front only, freeze on | Downlink keeps flowing: the client receives well over the freeze budget during an iperf run, and the client reports `timeout-at-N-bytes` stalls | fails (0 bytes after 1 s) |
| Front only, freeze on, rotation learned | Downlink throughput above the stall-and-redial sawtooth | n/a |
| `-censorship`, UDP + front | No `udp-ban` event from the censor; the session carries traffic over the front | fails (ban in ~100 ms) |

mini-tspu is a private repository (laneshetron/mini-tspu), so CI checks
it out with a read-only token in the `MINI_TSPU_TOKEN` secret and skips
the job without one; locally, Docker builds it from `../mini-tspu`.

## 6. Deferred

- A packet-count rotation budget (§3).
- `TCP_INFO`-based stall detection (unacked bytes with no ACK progress)
  for a faster, RTT-scaled stall timeout.
- Relay-side budgets: the relay knows exactly how much it wrote on each
  connection and could stop short of the cap and FIN, so the client
  rotates without the learning phase.
- Feeding stalls and bans into a persisted upstream profile (§3), so a
  second session starts with the budget and the posture already learned.
