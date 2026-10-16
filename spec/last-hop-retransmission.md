# ARC — Retransmitting Losses on the Last Hop

**Status:** draft design, feeds spec 0.3. Companion to the ARC/1 handoff
(`ARC-v1-Protocol-and-Implementation-Handoff.md`); section references (§N)
point there. Nothing here is implemented yet.

## 1. Problem

On a Mac whose Wi-Fi went off-channel for about 90 ms every 455 ms (AWDL,
with an iPhone nearby), downloads through ARC fell to a fraction of the
link's speed. The relay sent every packet, yet ~10% never reached the
Mac's `en0`. They were lost in blocks: at 2,000 packets/s, ~110 of each
stall's ~180. A 100 Hz ping across the same Wi-Fi saw those stalls only as
up to 95 ms of delay. The access point kept a fixed number of frames
(roughly 64) for the absent station and dropped the rest.

| Download over the Mac's Wi-Fi | Stalling | Not stalling |
|---|---|---|
| Relay → Mac through ARC, relay's CUBIC, 1 flow | 18–25 Mbit/s | 125–198 Mbit/s |
| UDP relay → Mac at fixed rate, loss | 8–18%, any rate or size | 0% |

`test/netns/stall.sh` reproduces the stall: a Wi-Fi hop that stops for
90 ms every 455 ms and keeps HOLD frames while stopped. CUBIC, medians of
3 runs of 8 s at 40 ms RTT, 400 Mbit/s "ISP":

| AP holds | Plain routing | ARC | ARC, FEC off |
|---|---|---|---|
| 64 frames | 9.70 Mbit/s | 8.91 | 8.52 |
| 256 frames | 38.4 | 33.7 | 34.6 |
| unlimited (delay only; 1 run) | 202 | — | — |

Without stalls all three reach 320–380 Mbit/s. The stall's *delay* costs
TCP little (202 Mbit/s with unlimited holding); its *loss* costs it almost
everything. ARC does slightly worse than plain routing because it sends
more frames into the same few slots (FEC repairs, acknowledgements).

ARC can do better than plain routing here, because the relay sits close to
the lossy hop and learns of each loss one last-hop round trip after it
happens, long before the far TCP sender would. This document proposes
letting the relay resend IP packets lost on the last hop, so a stall costs
the tunneled flow delay instead of loss.

## 2. Alternatives considered

- **Holding at the relay** (branch `stall-hold`, commit `5b92436`): the
  relay stops sending once a busy path falls silent and resumes when the
  client is heard again. It worked as designed: constant-rate UDP at
  20 Mbit/s lost 1.8% instead of 15%. But TCP gained nothing (8.0 vs 8.7
  Mbit/s). After each stall, the client's queued ACKs release a
  line-rate burst from the sender (~33 packets/ms at 400 Mbit/s), which
  fills 64 frames in about 2 ms. No silence detector can react in time,
  and on the real network the relay is 16–25 ms from the client. The
  relay held ~1 packet per stall while the sender retransmitted 60–75
  segments per loss recovery.
- **FEC (§11.2)**: a block code can't rebuild 55 ms of consecutive loss
  in time to matter. `auto` correctly stays off for bursts that long.
- **Redundancy (§11.1)**: needs a second path whose stalls don't line up,
  and doubles traffic.
- **Split TCP (§11.3)**: does recover these losses (ARC retransmits
  stream data), but only for TCP and only for new connections. It also
  terminates the client's TCP at the client, which is a much larger
  change to what the tunnel does.

Retransmission recovers the losses whatever their timing. It costs
bandwidth only for packets actually lost, plus memory for recently sent
packets.

## 3. Design

### 3.1 Scope

- **Relay → client only, at first.** The client's own stalled sends sit
  in its Wi-Fi driver's queue, not lost. The same mechanism can later
  serve the uplink (§7).
- **Datagram carriers only.** Never over a stream carrier (TLS/TCP,
  HTTPS front): those already deliver reliably, and resending on top would
  repeat the TCP-over-TCP problem §15.3 warns about.
- **IP payloads only.** Control frames and stream data already have
  their own retransmission.

### 3.2 Negotiation and control

- `AUTH_RESULT` features **bit 3 (`RETRANSMIT`)**: the relay will
  retransmit downlink IP packets on request. A relay that doesn't
  advertise it never retransmits IP payloads.
- New client → relay frame **`RETRANSMIT` (`0x17`, 5 bytes:
  `seq:u32; mode:u8`)**, handled like `FEC` and `REDUNDANCY`: mode 0 off,
  1 on. Other modes are malformed. It is retransmitted until
  acknowledged, and the relay applies only a `seq` greater than the last
  applied. The client controls it because the client knows its link
  (§3.7).
- Sent only when bit 3 is advertised. `0x17` is in the required range
  (§10): an old relay rejects the packet, so a client must not send it
  without the bit.

### 3.3 Identity and delivery once

- While retransmission is on, every downlink IP packet carries a datagram
  ID: `IP_DATAGRAM` instead of `IP_PACKET` (8 bytes more), or
  `IP_FRAGMENT`s with that ID. MTU probes already cover the larger frame
  whenever FEC or redundancy is negotiated (§14.4). Bit 3 allows
  `IP_DATAGRAM` too, and sizes the probes the same way.
- A retransmission repeats the original's datagram ID. The receiver's
  existing delivery window (§11.1, 65,472 IDs: about 2 s at 30,000
  packets/s) delivers each ID at most once. A spurious retransmission
  (from reordering beyond the loss threshold, or a lost ACK) costs
  bandwidth, not a duplicate delivery.
- FEC and retransmission may both rebuild a packet. The window
  deduplicates those too.

### 3.4 Retention

The relay keeps a copy of each recently sent downlink IP packet, keyed by
datagram ID, and records in each `sentPacket` the IDs it carried (one, or
a fragment's).

- **Age:** a packet is kept at most `retain_age`. The default is 250 ms:
  a 90 ms stall, plus a last-hop round trip of up to 100 ms to learn of
  the loss, plus slack. A retransmission later than that would mostly
  arrive after the far sender has already resent the data.
- **Per-session bytes:** at most `min(4 MiB, 2 × send_rate × retain_age)`,
  where `send_rate` is the path's best recent delivery rate (§15.2). At
  400 Mbit/s and 250 ms that's 4 MiB (about 3,300 full-size packets).
  When full, the oldest copies go first.
- **Relay-wide bytes:** at most `-retransmit-memory` (default 256 MiB).
  Under pressure, the sessions holding the most stop retaining until
  they're back under their share. A session that can't retain just loses
  packets as today.
- Copies live in a per-session ring of pooled buffers. One extra 1.3 KB
  copy per packet is small next to encryption.

### 3.5 Triggering a retransmission

When `onAck` declares a packet lost (three later packets acknowledged, or
one sent 9/8 RTT later; §15.2 item 8), for each IP datagram it carried the
relay resends the whole datagram once if all of these hold:

1. The copy is still retained and younger than `retain_age`.
2. It hasn't been retransmitted before. One retransmission per datagram:
   a second loss of the same datagram means the hop is still stalled or
   very lossy, and the far sender's own recovery is the right tool.
3. The datagram's current downlink path (§15.2 item 7) is a validated,
   healthy datagram path. If the path is suspect, the packet is dropped
   as today. Health handles outages.
4. The **budget** allows it: retransmitted bytes over the last second at
   most 25% of bytes sent. That's generous for stalls (~10% loss) and for
   ordinary random loss, and it caps the extra load where loss is heavy
   enough to call for redundancy or split TCP anyway.

Retransmissions go out ahead of new IP packets in the same flush. A
retransmitted packet is a normal ack-eliciting packet with a new packet
number. If it is lost too, it counts as lost like any packet but isn't
resent (rule 2).

### 3.6 Faster loss detection

§10.2 lets the receiver delay acknowledging IP payloads by up to 25 ms.
With retransmission on, the client acknowledges at once when a packet
arrives after a gap in packet numbers, as it already does for stream
data. The relay then learns of a stall's losses one last-hop round trip
after the stall ends. This costs at most one extra ACK per gap.

### 3.7 Policy (reference client)

`-retransmit off|on`, defaulting to `on` once the measurements in §5
justify it. The cost is near zero when nothing is lost: memory at the
relay and 8 bytes per packet. The client asks for it on every session
whose relay advertises bit 3. An `auto` mode, on only while downlink
losses come in runs, can be added if `on` proves costly somewhere.

## 4. How it interacts with the tunneled transport

A stall that ends at time `t` releases the frames the AP kept, then the
client's ACKs.

- The relay learns of the losses at `t + ½ RTT_last`, and retransmissions
  reach the client at `t + RTT_last`.
- The far sender learns of the hole from the client's SACKs at about
  `t + ½ RTT_inner`. Linux RACK (and similar) waits a reordering window,
  initially `min_rtt / 4`, before retransmitting.
- **When `RTT_last < min_rtt_inner / 4`** (relay near the client, or a far
  server), the repair fills the hole before the sender gives up on it. The
  flow sees only reordering and delay: no retransmission, no window
  reduction. In `stall.sh` the relay is next to the AP (`RTT_last` ≈ 1 ms),
  so this case should approach the unlimited-holding row (202 Mbit/s).
- **When `RTT_last` is larger** (the real case: 16–25 ms last hop, 30–40 ms
  inner RTT), the sender retransmits anyway and reduces its window. Then
  the repair's arrival shows that retransmission was spurious:
  - A receiver that reports D-SACK lets Linux undo the reduction
    (`TCPDSACKUndo`) and widen RACK's reordering window for later losses.
    **Whether macOS sends D-SACK is unknown, and decides how much CUBIC
    gains here.**
  - Even without undo, the sender's retransmission is no longer the only
    copy. If the far sender's retransmission itself falls into the next
    stall, the flow still has the relay's copy, which avoids the slow
    recovery episodes measured in §2.
- **BBR** mostly ignores loss: v1 entirely, v3 once loss in a round exceeds
  2%. Retransmission keeps v3 under that threshold. Most of the
  real-world gap was measured with Cloudflare, which runs BBR (~110 Mbit/s
  through ARC vs ~410 direct, while stalling). Whether ARC's extra loss is
  what costs BBR that much is not established; §5 measures it.
- **UDP applications** (QUIC, VoIP, games) receive a late copy instead of
  nothing. QUIC treats it like any reordered packet. Real-time media
  usually drops it as late. `retain_age` bounds the lateness.

## 5. Test plan, including BBR

Docker Desktop's kernel (linuxkit) has only reno and cubic, so BBR needs
another Linux. Three tiers, each comparing **plain routing, ARC, and ARC
with retransmission** on the same runs.

### 5.1 `stall.sh` extensions (first PR, before any protocol change)

- `LAST_HOP_RTT`: delay between the relay and the AP, taken out of the ISP
  leg so the end-to-end RTT stays 40 ms. Values 1, 10, 20 ms, to cross the
  `min_rtt / 4` line of §4.
- An `arc-rtx` mode, once the feature exists.
- Per run, from the sender's namespace (`SHOW_LOGS`, already partly
  there): `TcpRetransSegs`, `TcpExtTCPSackRecovery`, `TcpExtTCPTimeouts`,
  `TcpExtTCPDSACKRecv`, `TcpExtTCPDSACKUndo`, `TcpExtTCPLossUndo`, and the relay's
  retransmission counters (sent, wasted as duplicates, refused by budget,
  expired).
- A congestion-control check that fails loudly when `bbr` is requested but
  unavailable, instead of the current "skipping".

### 5.2 Tier 1: CI with BBR (GitHub Actions `ubuntu-latest`)

Ubuntu's kernel ships `tcp_bbr`. A `workflow_dispatch` job (not on every
push; CI runners are noisy, see the netns notes) runs:

```sh
sudo modprobe sch_netem tcp_bbr
sudo CCS="cubic bbr" ./test/netns/stall.sh bin 10 5
```

over `HOLD` ∈ {64, 256} and `LAST_HOP_RTT` ∈ {1, 20 ms}. CI runners vary
from day to day, so each comparison is within one run, and main's code
runs the same day as the change (a draft PR carrying main) for a baseline.

### 5.3 Tier 2: real Wi-Fi stalls (Mac + us-east-1 relay)

- Stalls on demand: an iPhone near the Mac with Continuity active.
  Confirm with a 100 Hz ping to the gateway right before and after each
  run: stalls show as ~90 ms spikes every ~455 ms. AWDL comes back on by
  itself, and stalls stop when the phone leaves.
- Sender: the relay itself (`iperf3 -s` bound to its tunnel address) with
  `-C bbr` and `-C cubic`. Amazon Linux 2023 ships `tcp_bbr`.
- Alternate the relay between retransmission off and on (a temporary
  systemd drop-in, as in the earlier `-no-offload` A/B), 5 runs each,
  interleaved so that drift in the stall pattern affects both alike.
- Measure goodput, the client's `-status` loss and burst, the relay's
  counters, and the relay-side TCP counters for the iperf3 flow.
- Direct-path control (no ARC, same sender): needs a temporary security
  group rule for one TCP port on the relay. Ask before changing the
  infrastructure.
- Optional: Cloudflare's speed test through ARC as a real BBR server. It
  returns 429 to the relay's IP after a few hundred MB, so keep runs few.

### 5.4 Regressions (every tier)

- Clean path: within 5% of today's throughput, up and down (`stall.sh`
  stalls-off rows, `bench.sh`).
- Random and bursty loss: `fec.sh` scenarios, retransmission on vs off,
  with FEC auto. Retransmission should help under uniform loss too, since
  it repairs what FEC misses.
- `degraded.sh` and `e2e.sh` pass, including failover and the TLS
  fallback (no retransmission over stream carriers).

### 5.5 Success criteria

- `stall.sh`, `HOLD` 64, `LAST_HOP_RTT` 1 ms: ARC with retransmission at
  least 5× today's ARC for CUBIC, and not below plain routing for BBR.
- `LAST_HOP_RTT` 20 ms: at least 2× today's ARC for CUBIC. If D-SACK undo
  doesn't happen there, record that, since it decides whether `auto` is
  needed.
- Real Wi-Fi, stalling: ARC with retransmission beats today's ARC for
  both BBR and CUBIC, and the client's measured downlink loss falls well
  below 1%.
- No regression beyond noise in §5.4.

## 6. Spec changes

- §10.1: frame `0x17 RETRANSMIT`, `AUTH_RESULT` features bit 3.
- §10.2: immediate acknowledgement after a gap while retransmission is
  on. "A missing ACK does not trigger retransmission of IP payloads"
  becomes "unless retransmission is negotiated (§11.4)".
- §11: "v1 does not retransmit TUN datagrams" gains the same exception.
- New §11.4: this design's §3.
- `wire-registry.md`: the frame and the feature bit.

## 7. Implementation plan (one reviewed PR each)

1. `stall.sh`: `LAST_HOP_RTT`, the TCP counters, and the BBR CI job.
   Record baselines for plain routing and ARC with BBR before changing
   anything.
2. Wire and spec: the feature bit, `RETRANSMIT` frame, fixtures, and
   immediate ACK after gaps, with nothing retransmitted yet.
3. Relay retention and retransmission behind `arc-relay -retransmit`,
   with session-harness tests (a stall's losses are repaired exactly once,
   the budget holds, nothing goes over stream carriers, memory stays
   bounded under a long outage) and the §5 measurements.
4. Client control and default, after the measurements.
5. Possibly: the uplink, for links that drop rather than queue the
   client's own stalled sends (some cellular modems).

## 8. Open questions

- Does macOS send D-SACK? It decides how much CUBIC gains when the
  relay is far from the client (§4).
- Is 64 frames typical of access points in power-save buffering, and does
  it vary with frame size? This affects how much the AP keeps, not the
  design.
- Should a retransmission go on a second path when one is healthy
  (§11.1)? That's probably better for stalls on one link, but it changes
  which flows see reordering.
- Are AWDL stalls regular enough to predict, so the relay could pause
  just before one? That's not pursued here: it would be fragile and
  Apple-specific.
