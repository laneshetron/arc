# ARC/1 — Adaptive Relay Connectivity
## Implementation Handoff and Experimental Protocol Specification

**Document ID:** `arc-v1-spec`  
**Version:** 0.2 — revised wire baseline, **not an IETF RFC** (changes from 0.1: Appendix A)  
**Date:** 2026-10-11  
**Status:** Proposed / implementation-ready baseline; all on-wire values are provisional until a first interop test  
**Intended audience:** Systems/network engineers implementing a client, relay, adapters, and test harness  
**Working name:** ARC (Adaptive Relay Connectivity)

> **Thesis.** Present an ordinary, stable IP network to unmodified applications while an adaptive communications runtime discovers usable physical and logical channels, carries a single encrypted session over any permitted subset of those channels, and schedules traffic to maximize *useful* application performance. An optional application SDK may expose higher-level communication and remote-execution capabilities without breaking the IP abstraction.

---

# Part I — Engineering handoff

## 1. Executive summary

ARC is a software-defined overlay network with five major pieces:

1. **Client TUN/VPN interface.** Captures ordinary IPv4/IPv6 packets and injects responses. No application changes required.
2. **Session engine.** Establishes a single cryptographically authenticated and encrypted end-to-end client↔relay session. Session identity is independent of IP address, port, underlying interface, and adapter.
3. **Path manager and scheduler.** Discovers, probes, validates, scores, and combines paths such as Wi-Fi/UDP, cellular/UDP, TLS/TCP, an authorized DNS query/response path, or an authorized ICMP Echo path. Paths may join and leave without terminating the session.
4. **Transport adapters.** Carry ARC packets over one available channel: whole packets on datagram and stream carriers, and bounded *cells* on constrained request/response carriers. An adapter transports opaque encrypted ARC packets; it must not interpret the tunneled IP traffic.
5. **Relay/gateway.** Terminates the ARC session, reassembles IP packets, performs policy enforcement and Internet egress, and returns replies through suitable paths.

**Core design invariant:** An ARC session is not a TCP connection, QUIC connection, physical interface, VPN socket, or IP 5-tuple. Those are replaceable carriers of authenticated ARC packets.

### Scope at a glance

| Capability | ARC/1 baseline | Later extension |
|---|---|---|
| Drop-in TUN-based IP overlay | MUST | — |
| Stable session across path changes | MUST | — |
| Client↔relay encryption and authentication | MUST | — |
| Wi-Fi + cellular path aggregation | MUST in controlled testbed | Generalized multiparty routing |
| UDP + TCP/TLS adapters | MUST | MASQUE/HTTP/3 optimization |
| DNS and ICMP adapters | Experimentally defined; feature-gated | Adaptive transport discovery |
| IP packet reassembly, bounded buffering | MUST | FEC/adaptive parity |
| Per-path RTT/loss/bandwidth tracking | MUST | Learned congestion controller |
| IPv4 egress | MUST | IPv6 egress, NAT64, advanced routing |
| Compression of IP packet payloads | NOT in v1 | Only for safe, useful data classes |
| Optional SDK | Interface sketch | Remote calls, typed streams, remote rendering |
| Mesh networking | OUT OF SCOPE | Separate routing/identity layer |

### Product promise and limitation

ARC can maximize performance **among usable, permitted channels**. It cannot guarantee Internet access in a network that supplies no authorized route to an ARC relay. In particular, merely observing DNS, ICMP, iMessage, or another service's connectivity does not establish permission or technical ability to carry arbitrary traffic through it. All testing on restricted networks must respect ownership, network access controls, and service terms.

## 2. Design goals and non-goals

### Goals

- **G1: Transparent networking.** Normal applications can use the existing OS IP stack without modifications.
- **G2: Continuity.** Preserve a session when networks appear, disappear, renumber, or change transport type.
- **G3: Multipath goodput.** Use multiple independent underlying links simultaneously when doing so improves completed useful work.
- **G4: Graceful degradation.** Continue control messages and, where feasible, low-rate data on constrained permitted carriers.
- **G5: Strong security.** Encryption, peer authentication, anti-replay, path validation, and least-privilege egress independent of carrier.
- **G6: Extensibility.** Version transport adapters independently from core session semantics; support an optional higher-level SDK.
- **G7: Observability.** Explain exactly why a path is used or avoided, without logging packet plaintext or secrets.

### Non-goals for ARC/1

- Implementing an unrestricted bypass of captive portals, paywalls, administrative policies, or service access controls.
- Replacing TLS or decrypting arbitrary HTTPS traffic; transparent compression of encrypted content is not promised.
- Providing anonymity against the relay operator; the relay necessarily sees destination IP metadata unless separately protected.
- Guaranteeing that one TCP flow reaches the arithmetic sum of all link throughputs. Aggregating many flows is the first target.
- Building a peer-to-peer mesh, a general-purpose programmable browser, or a universal protocol for invoking remote code.
- Designing original cryptographic primitives, a proprietary congestion-control algorithm, or a new DNS standard.

## 3. System architecture

```text
                       NORMAL APPLICATIONS             OPTIONAL SDK
                              |                            |
                              v                            v
                         OS TCP/IP stack               ARC service API
                              |                            |
                              v                            |
                       TUN / VPN virtual NIC               |
                              |                            |
                              +------------+---------------+
                                           |
                              ARC session/runtime
                     +---------------------+---------------------+
                     | Auth + encryption, packet/frame codec    |
                     | IP reassembly, dedup, session lifetime   |
                     | Path discovery, validation, telemetry    |
                     | Scheduler, quotas, policies             |
                     +---------------------+---------------------+
                                           |
                              Transport adapter interface
                     +---------+------------+------------+---------+
                     |         |            |            |         |
                  UDP/QUIC   TLS/TCP      HTTPS       DNS Q/R   ICMP Echo
                     |         |            |            |         |
                Wi-Fi, cellular, tethered links, other authorized carriers
                     \         |            |            |         /
                      +--------+------------+------------+--------+
                                           |
                                       ARC relay
                                 Session + egress gateway
                                           |
                                        Internet
```

**Control plane:** Bootstrap, peer authentication, `PATH_JOIN`, challenge/response validation, configuration, link probes, shutdown, and key lifecycle.

**Data plane:** IP packets carried in authenticated ARC frames (fragmented only when a path requires it), carrier framing, path scheduling, reassembly, deduplication, and virtual-interface delivery.

The data plane does **not** depend on control messages being sent on the same carrier. Every authenticated path is associated with the same logical session.

## 4. Key architecture decisions

**D1 — TUN, not a custom application socket stack.** Implement ordinary IP connectivity first. Optionally support SDK streams and task RPCs in later versions.

**D2 — Client↔relay overlay encryption, independent of adapter.** TLS/QUIC may encrypt the outer transport, but an ARC packet is encrypted before passing to any adapter. DNS/ICMP adapters never receive plaintext IP packets.

**D3 — Packet-oriented overlay.** The default payload is an unreliable IP datagram. TCP already provides application reliability where applicable. Avoid blanket retransmission of all tunneled packets, which can amplify head-of-line blocking and congestion collapse.

**D4 — Narrow carrier contract.** A path transmits and receives bounded cells and reports observed constraints. It does not decide how to split application flows or which packets are valuable.

**D5 — Conservative multipath policy first.** Prefer flow pinning and multi-flow aggregation in v1. Experimental single-flow striping, replication, and FEC come only after repeatable measurement.

**D6 — Lower bandwidth is not automatically lower priority.** High-RTT DNS/ICMP channels may be valuable for reachability/control while being harmful for throughput striping.

**D7 — Separate kernel packet handling from remote application execution.** The optional SDK must be opt-in, explicitly scoped, and never require the relay to inspect general HTTPS traffic.

## 5. Trust and threat model

**Trusted:** Client application/OS VPN component, provisioned relay public key, runtime cryptography, and the operator's authorized gateway configuration.

**Untrusted:** Local Wi-Fi/cellular operators, intermediate resolvers/proxies, other network users, raw carrier packet bytes, replayed/duplicated/reordered packets, and the outer transport connection itself.

**Attacker capabilities:** Observe, drop, delay, replay, reorder, inject, spoof, and truncate packets; switch client network addresses; attempt resource exhaustion via DNS/ICMP and handshake inputs.

**Explicitly not protected:** Malware controlling the endpoint; a malicious but correctly authenticated relay; destination traffic metadata from the relay; traffic analysis based on observable connection timing and size; endpoint application sessions themselves.

---

# Part II — ARC/1 experimental protocol specification

## 6. Conventions and terminology

The capitalized terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** have the meanings from RFC 2119 and RFC 8174.

- **Session:** Long-lived authenticated cryptographic relationship between one client and one relay. Endpoints keep a local session handle for logging and state; **no session-wide identifier appears on the wire** after the handshake.
- **Path:** One concrete bidirectional or request/response communication relationship over a particular adapter and underlying network interface, identified by a 32-bit `path_id`. Path 0 is the bootstrap path; the relay assigns all other path IDs.
- **Connection ID (CID):** An 8-byte opaque value chosen by a *receiver* for one path. Every `DATA` packet carries the receiver's CID for the path it travels on. Each path has its own CIDs, so an observer cannot link paths by CID.
- **Adapter / carrier:** Encodes/decodes ARC packets for a specific transport, such as UDP, TLS/TCP, DNS, or ICMP.
- **ARC packet:** One of `HANDSHAKE_INIT`, `HANDSHAKE_RESP`, `COOKIE_REPLY`, `DATA`, or `STATELESS_RESET` (§8).
- **Frame:** A TLV inside the encrypted payload of a `DATA` packet (§10).
- **Cell:** A carrier-local fragment of one ARC packet, used **only** on constrained request/response carriers such as DNS and ICMP (§12).
- **IP fragment:** An ARC-level fragment of one complete original TUN IP packet, carried inside encryption; not IP-layer IPv4 fragmentation.
- **Epoch:** The generation of a directional traffic key (§13).
- **Goodput:** Useful bytes/operations completed at the receiving application, excluding duplicate, retransmitted, and carrier overhead bytes.

All multibyte integers are **unsigned, network-byte-order (big endian)** unless explicitly noted. Reserved fields are zero and MUST be rejected if nonzero. Implementations MUST strictly validate lengths before allocating memory.

## 7. Packet types and versioning

The first byte of every ARC packet is its **type**:

| Type | Name | Direction | Size (bytes) |
|---|---|---|---|
| `0x01` | `HANDSHAKE_INIT` | client → relay | exactly 122 |
| `0x02` | `HANDSHAKE_RESP` | relay → client | exactly 81 |
| `0x03` | `COOKIE_REPLY` | relay → client | exactly 25 |
| `0x04` | `DATA` | both | 37 – 16,384 |
| `0x05` | `STATELESS_RESET` | relay → client | exactly 25 |
| `0x10` | `CELL` (carrier fragment, §12) | both | 19 – 16,384 |

- Protocol name: `ARC/1`. The protocol version (`0x01`) is carried explicitly only in `HANDSHAKE_INIT` and is bound into the Noise prologue, so it cannot be downgraded without detection. All later packets of a session inherit the session's version.
- A relay MUST silently drop a `HANDSHAKE_INIT` with an unknown version. A future version negotiation mechanism requires a separately authenticated extension; there is no unauthenticated downgrade fallback.
- Endpoints MUST silently drop packets with an unknown type, an invalid size for their type, or nonzero reserved bits. They MAY emit a rate-limited `ERROR` frame on an authenticated path.
- Maximum ARC packet size: **16,384 bytes**.
- There is no magic number. Type codes plus exact sizes are enough to separate ARC packets from noise, and every packet that matters is authenticated. Leaving magic out saves bytes on every packet.

## 8. Packet formats

### 8.1 `HANDSHAKE_INIT` (client → relay, 122 bytes)

```text
Offset  Size  Field
0       1     type        = 0x01
1       1     version     = 0x01
2       8     sender_cid  = client's receive CID for path 0 (random)
10      16    cookie      = all zero, or the cookie from a COOKIE_REPLY (§9.3)
26      96    noise_msg1  = Noise IK message 1: e (32) || encrypted s (48) || encrypted empty payload (16)
```

### 8.2 `HANDSHAKE_RESP` (relay → client, 81 bytes)

```text
Offset  Size  Field
0       1     type        = 0x02
1       8     dest_cid    = sender_cid from the HANDSHAKE_INIT
9       72    noise_msg2  = Noise IK message 2: e (32) || encrypted payload (24 + 16)
```

The 24-byte Noise payload of message 2 is `relay_cid[8] || reset_token[16]`: the relay's receive CID for path 0 and the stateless reset token bound to it (§14.7). These values are encrypted and authenticated by the handshake.

### 8.3 `COOKIE_REPLY` (relay → client, 25 bytes)

```text
Offset  Size  Field
0       1     type        = 0x03
1       8     dest_cid    = sender_cid from the HANDSHAKE_INIT
9       16    cookie
```

### 8.4 `DATA` (both directions, 18-byte header)

```text
Offset  Size  Field
0       1     type           = 0x04
1       1     epoch_low      = sender's key epoch mod 256 (§13)
2       8     dest_cid       = receiver's CID for this path
10      8     packet_number  = per-path, per-direction counter
18      N     ciphertext     = AEAD(frames) || 16-byte tag
```

- The plaintext MUST contain at least one complete frame, so `N >= 3 + 16` and the smallest `DATA` packet is 37 bytes.
- There is no length field. Packet length comes from the carrier: the datagram length, a stream length prefix (§12.2), or cell reassembly (§12).
- `path_id` is **not** on the wire. The receiver derives it from `dest_cid`, and the sender uses the `path_id` that the CID was issued for.

### 8.5 `STATELESS_RESET` (relay → client, 25 bytes)

```text
Offset  Size  Field
0       1     type        = 0x05
1       8     cid         = the dest_cid of the DATA packet that triggered the reset
9       16    reset_token
```

### 8.6 DATA packet protection

```text
AEAD      = ChaCha20-Poly1305 (RFC 8439)
Nonce     = u32_be(path_id) || u64_le(packet_number)      (12 bytes)
AAD       = the 18 DATA header bytes, exactly as transmitted
Plaintext = concatenated frame TLVs
```

- For each direction and path, the sender starts `packet_number` at 0 and adds 1 for every `DATA` packet. Packet numbers **do not reset** when the epoch changes.
- `packet_number = 2^64 − 1` MUST NOT be used; Noise `REKEY` reserves that nonce (§13).
- Path IDs are never reused within a session (§14.3). Together with per-path packet numbers, this means a `(key, nonce)` pair can never repeat. A packet number is consumed when assigned, even if the send then fails.
- A sender MUST NOT re-send an already encrypted packet on a different path. Control information that needs retransmission goes in a **new** packet.
- The nonce layout matches Noise's ChaChaPoly nonce, except that the leading 32 bits carry `path_id` instead of zero.

## 9. Authentication and session establishment

### 9.1 Required cipher suite

ARC/1 MUST use the established **`Noise_IK_25519_ChaChaPoly_SHA256`** handshake pattern.

Each relay has a persistent X25519 static key pair. A client MUST obtain the relay static public key from trusted configuration or another authenticated provisioning mechanism. IK requires the initiator to know the responder's static key, so the pin is **built into the handshake**: if the configured key is wrong, the relay cannot decrypt message 1 and the client cannot decrypt message 2. No separate "verify the pin" step exists for an implementation to forget.

The client has a static X25519 key (persistent or per install). The relay learns it from message 1 and MAY use it for rate limiting and device binding. Authorization MUST use a separate short-lived credential (§9.2) and MUST NOT rely only on the client static key.

**Noise prologue:** `UTF8("ARC/1") || version[1] || sender_cid[8]`, which is `"ARC/1"` followed by bytes 1–9 of the `HANDSHAKE_INIT`. The cookie is left out so a client can add one without generating a new message 1.

**Noise payloads:** message 1: empty. Message 2: `relay_cid[8] || reset_token[16]`.

**Traffic keys:** Noise `Split()` produces the epoch-0 keys: the first key for client→relay, the second for relay→client. The relay derives them after writing message 2, and the client after reading it. The standard sequential Noise transport wrapper is **not** used, because datagrams may arrive out of order. Implementations need a vetted Noise library that supports encryption with an explicit nonce under the split cipher states.

### 9.2 Handshake sequence

```text
Client                                          Relay
  |  HANDSHAKE_INIT (msg1, cookie=0)               |
  |----------------------------------------------->|
  |                   [only if under load]         |
  |  COOKIE_REPLY                                  |
  |<-----------------------------------------------|
  |  HANDSHAKE_INIT (same msg1, cookie)            |
  |----------------------------------------------->|
  |  HANDSHAKE_RESP (msg2: relay_cid, reset_token) |
  |<-----------------------------------------------|
  |  Split() -> epoch-0 keys                       |
  |  DATA path 0: AUTH {credential}                |
  |----------------------------------------------->|
  |  DATA path 0: AUTH_RESULT {status, ipv4, mtu}  |
  |<-----------------------------------------------|
  |  ACTIVE                                        |
```

- The client MUST NOT send `AUTH` until message 2 has been processed successfully, which proves the relay holds the pinned key.
- The server MUST NOT forward IP traffic until it has validated the `AUTH` credential.
- The relay MUST NOT send any `DATA` packet for a session until it has received an authenticated `DATA` packet from the client. This confirms the client derived the keys.
- The client MUST NOT install full-tunnel routes until it receives `AUTH_RESULT(success)`.
- Credentials SHOULD be short-lived, audience-bound to the relay/operator, and revocable. They MUST be sent only inside `DATA` encryption.
- No 0-RTT application data and no resumed session tickets in v1. A failed or expired session requires a new handshake.

**Loss recovery.**
- The client retransmits the **byte-identical** `HANDSHAKE_INIT` (same ephemeral key) with exponential backoff: 1 s initial, doubling.
- After a 10 s handshake timeout, the client gives up on that attempt and starts over with a new ephemeral key and a new `sender_cid`.
- For 10 s, the relay caches the `HANDSHAKE_RESP` for each completed `HANDSHAKE_INIT`. If byte-identical INIT bytes arrive from the same source, it re-sends the cached response without doing a new Diffie-Hellman computation.
- If no `AUTH_RESULT` arrives, the client retransmits `AUTH` in new `DATA` packets. The relay MUST process duplicate `AUTH` idempotently.

**Resource limits.** The relay MUST implement handshake timeouts, a cap on pending handshakes, per-source rate limits, and the cookie mechanism in §9.3.

### 9.3 Cookies (address validation under load)

When the relay is under load, it does not perform Diffie-Hellman for an INIT whose cookie is missing or invalid. "Under load" means pending handshakes are above a threshold or a per-source rate limit has been exceeded. Instead the relay answers with `COOKIE_REPLY`:

```text
cookie = HMAC-SHA256(cookie_secret,
                     UTF8("ARC/1 cookie") || src_ip || u16_be(src_port) || sender_cid)[0:16]
```

- `src_ip` is 4 bytes for IPv4 or 16 bytes for IPv6, in network order.
- `cookie_secret` is random, rotates every 120 s, and the previous secret is still accepted.
- The client re-sends the same INIT bytes with the cookie filled in. The relay verifies the cookie with a constant-time comparison **before** doing any Diffie-Hellman.
- The client accepts a `COOKIE_REPLY` only when its `dest_cid` matches an outstanding INIT. A forged `COOKIE_REPLY` costs at most one round trip.
- Anti-amplification holds without cookies: `HANDSHAKE_RESP` (81 bytes) and `COOKIE_REPLY` (25 bytes) are both smaller than `HANDSHAKE_INIT` (122 bytes).
- Cookies are for spoofable datagram carriers. Carriers whose source address the transport has already verified (TCP, TLS) MAY skip them.

### 9.4 Session states

```text
NEW -> HANDSHAKING -> AUTHENTICATING -> ACTIVE -> DRAINING -> CLOSED
  \-> FAILED       \-> FAILED           \-> FAILED
```

- After the handshake completes (message 2 written or read), both peers enter `AUTHENTICATING`.
- The relay moves to `ACTIVE` after it validates `AUTH`. The client moves to `ACTIVE` after it validates a successful `AUTH_RESULT`.
- **Credential refresh:** in `ACTIVE`, the client MAY send `AUTH` again with a fresh credential, and the relay answers with `AUTH_RESULT`. If the refresh fails, the relay sends `CLOSE(AUTH_FAILED)` and stops forwarding. A relay MAY close a session whose credential expired without a refresh (`SESSION_EXPIRED`).
- A path failure MUST NOT close an `ACTIVE` session while another validated path remains usable.
- If all paths are unavailable, the session MAY stay suspended for a configured grace interval (default 120 s) with a bounded queue of control work. It MUST NOT buffer arbitrary IP traffic indefinitely.
- Session and credential expiry are independent of path changes.

## 10. Data frame TLV format

A decrypted `DATA` plaintext consists of one or more frames:

```text
frame_type:   1 byte
frame_length: 2 bytes, big-endian
frame_value:  frame_length bytes
```

- Frames MUST lie entirely within their `DATA` packet.
- Unknown frame types in `0x80..0xFF` are optional extensions and MAY be ignored.
- Unknown types in `0x00..0x7F` signal a required feature: the receiver MUST reject the whole packet, with a rate-limited `ERROR(UNSUPPORTED)` if possible.
- A frame's own length fields never repeat `frame_length`. Variable-length fields take the rest of the frame value.

### 10.1 Frame registry

| Hex | Name | Value | Direction | Ack-eliciting |
|---|---|---|---|---|
| `00` | `PADDING` | `frame_length` zero bytes (any nonzero byte → malformed) | Either | No |
| `01` | `AUTH` | `credential` (1–4096 bytes) | Client → relay | Yes |
| `02` | `AUTH_RESULT` | 28 bytes: `status:u8; ipv4:u32; prefix4:u8; tun_mtu:u16; dns_ipv4:u32; keepalive_ms:u32; idle_ms:u32; features:u64` | Relay → client | Yes |
| `03` | `IP_PACKET` | one complete IP packet | Both, after AUTH | Yes |
| `04` | `IP_FRAGMENT` | `datagram_id:u64; total_len:u16; offset:u16; data` | Both, after AUTH | Yes |
| `05` | `NEW_PATH` | 28 bytes: `path_id:u32; cid:8B; reset_token:16B` | Relay → client | Yes |
| `06` | `PATH_JOIN` | 8 bytes: `cid:8B` (client's receive CID for this path) | Client → relay | Yes |
| `07` | `PATH_CHALLENGE` | 8 bytes: `data` | Either | Yes |
| `08` | `PATH_RESPONSE` | 8 bytes: `data` | Either | Yes |
| `09` | `PATH_ABANDON` | 6 bytes: `path_id:u32; code:u16` | Either | Yes |
| `0A` | `PING` | empty | Either | Yes |
| `0B` | `ACK` | see §10.2 | Either | No |
| `0C` | `CLOSE` | 2 bytes: `code:u16` | Either | No |
| `0D` | `ERROR` | 2 bytes: `code:u16` | Either, diagnostic only | Yes |

**`AUTH_RESULT`:**
- `status=0` means success. Any other value is a failure, and all other fields MUST then be zero.
- `tun_mtu` MUST be at least 1280 on success.
- `dns_ipv4=0` means the relay supplied no resolver. Full-tunnel mode MUST then get an authenticated resolver setting from trusted, explicit client configuration.
- No `features` bits are defined in v1; they MUST be zero.
- IPv6 configuration and pushed routes are deferred to an extension frame.
- The relay controls address assignment by deployment policy. Receiving an address does not by itself authorize inbound Internet exposure.

**`IP_PACKET`:** the value is exactly one IP packet. The receiver MUST check that the version nibble is 4 or 6, and that the packet's declared length (IPv4 Total Length, or IPv6 Payload Length + 40) equals `frame_length`. v1 relays reject IPv6 by policy (§17.2).

**`IP_FRAGMENT`:**
- 12-byte fixed prefix. Data length = `frame_length − 12`, and it MUST be greater than 0.
- `offset + data_len <= total_len`, and `20 <= total_len <= 65535`.
- Fragments whose byte ranges overlap with conflicting contents cause the whole datagram to be discarded.

**`ERROR` codes:** `1 MALFORMED`, `2 AUTH_FAILED`, `3 UNAUTHORIZED`, `4 PATH_UNAVAILABLE`, `5 CAPACITY`, `6 UNSUPPORTED`, `7 SESSION_EXPIRED`, `8 PROTOCOL_VIOLATION`. Unknown values are informational and MUST NOT crash an implementation. `CLOSE` and `PATH_ABANDON` use the same code space, plus `0 NO_ERROR`.

### 10.2 `ACK` frame

```text
path_id        u32   path whose packet-number space is being acknowledged
largest        u64   largest packet number acknowledged
ack_delay_us   u32   microseconds between receiving `largest` and sending this ACK
first_range    u32   packets acknowledged contiguously below `largest`
range_count    u8    0..32
ranges[range_count]:
    gap        u32
    length     u32
```

The ranges follow QUIC (RFC 9000 §19.3.1):
- The first range covers `[largest − first_range, largest]`.
- Let `smallest` be the low end of the previous range. Each `(gap, length)` pair then covers `[hi − length, hi]`, where `hi = smallest − gap − 2`.
- Any arithmetic underflow makes the frame malformed. The value length MUST equal `21 + 8 × range_count`.

Behavior:
- An `ACK` MAY travel on any path. For example, the fast path can carry ACKs for the DNS path.
- Receivers SHOULD acknowledge ack-eliciting packets within `max_ack_delay` (default 25 ms), or after every second ack-eliciting packet, whichever comes first.
- A packet that contains only non-ack-eliciting frames MUST NOT be acknowledged on its own.
- ACKs are **measurements only**. An ACK of an ARC packet does not guarantee application delivery, and a missing ACK does not trigger retransmission of IP payloads. Control frames with a nonce or ID are safe to resend in a fresh packet.
- `ack_delay_us` lets the sender subtract the receiver's hold time when computing RTT. On poll-driven carriers this hold time is most of the observed delay.

## 11. Packet reassembly and deduplication

- A sender uses `IP_FRAGMENT` only when an IP packet plus `DATA` overhead (37 bytes) does not fit the path's maximum packet size. It SHOULD send all fragments of one datagram on the same path.
- Each sender keeps a monotonically increasing `datagram_id:u64` per session direction. It MUST NOT reuse IDs while the session is alive.
- The receiver reassembles fragments keyed by `datagram_id`, regardless of which path they arrived on. It delivers each completed datagram **at most once**.
- Bounded defaults:
  - 1,024 incomplete datagrams per session
  - 8 MiB of incomplete bytes per session
  - 5 s expiry per incomplete datagram
  - 8,192 recently completed IDs kept in dedup state
  - On quota pressure, evict the oldest incomplete datagram.
- Whole `IP_PACKET` frames are protected against duplication by the per-path replay window (§13). In v1, senders MUST NOT replicate IP payloads across paths. Replication and FEC are later extensions and would need their own datagram identity.
- A missing fragment simply expires; v1 **does not** retransmit TUN datagrams. TCP recovers its own losses, and other applications have their own semantics.
- The relay MUST reject client packets whose inner source address is not leased to that session.

## 12. Carrier framing and cells

### 12.1 Cells (constrained carriers only)

Cells exist so that a constrained request/response carrier can move an ARC packet larger than one carrier message. **UDP, QUIC, and stream carriers do not use cells** (§12.2). A cell's content is a fragment of a complete ARC packet, never application plaintext.

```text
Offset  Size  Field
0       1     type            = 0x10
1       1     flags           = 0x00 in ARC/1
2       8     assoc_id        = carrier association, chosen by the client
10      4     cell_packet_id  = identifies one ARC packet within the association
14      2     total_len       = total ARC packet bytes (25..16384)
16      2     offset          = byte offset into the ARC packet
18      N     chunk           = N = cell length − 18, N > 0
```

- `offset + N <= total_len`.
- **`assoc_id`** is a random 64-bit value. The client picks it when it opens a constrained carrier and keeps it for the life of that carrier path.
  - It groups cells no matter which address delivered them. A recursive resolver may send one client's queries from many egress IPs, so reassembly MUST NOT be keyed on source address.
  - It is an **unauthenticated hint**. The relay binds an `assoc_id` to a session only after a fully reassembled packet carrying it has authenticated (a `DATA` packet that decrypts, or a completed handshake). An `assoc_id` already bound to another session is ignored.
- The sender splits a packet into contiguous, non-overlapping cells, all with the same `cell_packet_id`, which MUST be unique within the association's reassembly window. All cells of one packet SHOULD use the same carrier path.
- The receiver reassembles keyed by `(assoc_id, cell_packet_id)` and hands the packet to the ARC layer only once it is complete.
- Reassembly limits:

  | Association state | Incomplete packets | Bytes | Expiry |
  |---|---|---|---|
  | Bound to a session | 64 | 256 KiB | 10 s |
  | Unbound | 4 | 16 KiB | — |

  Unbound associations also share a global budget and are rate-limited per resolver.
- **Downlink.** The relay keeps a downlink cell queue for each bound association. It MAY answer any request that carries a cell of a bound association with the next queued downlink cell, even before that request's own ARC packet is complete. Requests on unbound associations get an empty answer. An off-path attacker cannot guess `assoc_id`. An on-path attacker could drain the queue, but such an attacker can already drop packets.
- **Polling.** With nothing pending upstream, the client polls with a newly encrypted `DATA` packet containing a `PING` frame, carried in ordinary cells. There are no unauthenticated empty polls.
- Cell headers and DNS/ICMP wrappers are **not authenticated** until reassembly and successful ARC verification, so the allocation and state limits above are mandatory.

**Why two fragmentation layers?** `IP_FRAGMENT` is end-to-end and inside the encryption. Cells are local to one carrier and sit outside the encryption. On fast carriers only the first layer exists. Cells are confined to the constrained adapters, so a DNS adapter never has to understand IP or session reassembly.

### 12.2 Framing summary

| Carrier kind | Framing |
|---|---|
| UDP, QUIC DATAGRAM | One ARC packet per datagram. No cell header. |
| Reliable byte stream (TLS/TCP, QUIC stream) | `packet_length:u16` (big-endian) followed by exactly one ARC packet. Values below 25 or above the negotiated maximum are invalid. The adapter buffers until a full packet is present, within per-connection memory bounds. |
| Request/response (DNS, ICMP) | One `CELL` per request or response (§16.5, §16.6). |

## 13. Key epochs and replay protection

- Epoch 0 starts at Noise `Split()`. Each direction has its own key and its own epoch counter.
- **Rekey triggers:** a sender advances its sending epoch when its current key has been used for `REKEY_AFTER_TIME = 120 s` or for `REKEY_AFTER_PACKETS = 2^32` packets in total across all paths, whichever comes first. The next key is derived with Noise `REKEY`:

```text
new_key = ChaCha20-Poly1305-Encrypt(key = old_key,
                                    nonce = 0x00000000 || u64_le(2^64 − 1),
                                    aad = empty,
                                    plaintext = 32 zero bytes)[0:32]
```

- A sender MUST NOT advance from epoch `e` to `e+1` until it has received an acknowledgement for at least one packet it sent in epoch `e`. This keeps the peer at most one epoch behind.
- **Epoch resolution.** `epoch_low` is the epoch mod 256. A receiver whose current receive epoch is `e` maps an incoming `epoch_low` as follows; any other value is dropped:
  - `e mod 256` → epoch `e`
  - `(e+1) mod 256` → epoch `e+1`
  - `(e−1) mod 256` → epoch `e−1`, but only while the previous key is still retained
- **Committing a new epoch.** A receiver MAY derive the key for `e+1` on demand. It commits to the new epoch **only if AEAD authentication succeeds**, then keeps the old key for `KEY_OVERLAP = 60 s` and erases it. A receiver MUST NOT derive keys more than one epoch ahead.
- **Replay window.** A receiver keeps a sliding window of at least **4,096** packet numbers **per path and direction**. Because packet numbers don't reset at epoch changes, the window spans epochs. Receive processing MUST run in this order:
  1. Look up `dest_cid`, which gives the session and the path.
  2. Resolve the epoch.
  3. Check the replay window. Drop duplicates and packets too old for the window.
  4. Open the AEAD.
  5. Only if it succeeds: update the replay window and commit any epoch change.

  Unauthenticated packets therefore cannot move or poison the window.
- Since windows are per path, a slow path's late packets compete only with that path's own traffic, not with a fast path's packet numbers.
- **Integrity limit.** An endpoint MUST close a session once it has counted 2^36 failed AEAD decryptions, and handshake again.
- **Restarts.** A restarted process MUST establish a new session, with new ephemeral keys and new CIDs, instead of restoring old counters under old keys.

> **Security review gate:** An independent cryptographic review is required before deployment beyond controlled pilots. Noise IK and Noise `REKEY` are standard. The following are ARC-specific choices and must be covered by test vectors, audit, and fuzzing:
> - the explicit per-path nonce
> - the epoch-resolution rule
> - cookies and stateless reset tokens
> - association binding

## 14. Paths, joining, migration, and failure

### 14.1 Path state machine

```text
DISCOVERED -> PROBING -> VALIDATED -> ACTIVE -> SUSPECT -> DRAINING -> DEAD
                    \-> FAILED                 \-----> DEAD
```

- `DISCOVERED`: system detects a candidate interface/adapter combination.
- `PROBING`: establish carrier connectivity and exchange authenticated path validation messages.
- `VALIDATED`: both sides have proven they can communicate in both directions on this carrier.
- `ACTIVE`: eligible for scheduler use.
- `SUSPECT`: elevated loss, timeouts, or degraded reachability; send probes and generally reduce new data.
- `DRAINING`: stop new data and let pending delivery finish, subject to a deadline.
- `DEAD`: remove per-path state; the session may continue via other paths.

### 14.2 Bootstrap path

Path 0 carries the handshake. Its CIDs come from the handshake itself: the client's receive CID is `HANDSHAKE_INIT.sender_cid`, and the relay's receive CID and reset token come from the message 2 payload. The client treats path 0 as validated once it receives a valid `AUTH_RESULT`. The relay treats it as validated once it receives a valid `AUTH`.

### 14.3 Path IDs and connection IDs

- The relay pre-issues path slots with `NEW_PATH(path_id, relay_cid, reset_token)` frames:
  - It SHOULD keep at least two unused slots outstanding.
  - It MUST cap outstanding slots (default 8).
  - Path IDs are strictly increasing and never reused within a session.
- CIDs MUST be unpredictable and unique among the relay's live sessions. The client's CIDs MUST be unpredictable.
- Each path uses CIDs that appear nowhere else, so paths cannot be linked by CID.

### 14.4 Adding a new path

1. The client opens a carrier on the new underlay and takes an unused slot `(p, relay_cid, token)`.
2. It generates a random `client_cid` and sends `DATA` with `dest_cid = relay_cid`, encrypted with nonce space `p`, containing `PATH_JOIN(client_cid)`. The same packet MAY also carry other frames, including IP traffic.
3. The relay authenticates the packet, records the source address as a candidate for path `p`, and replies to that address with `DATA(dest_cid = client_cid)` containing `PATH_CHALLENGE(n)`.
4. An authenticated challenge arriving on that carrier proves bidirectional reachability, so the client marks path `p` `VALIDATED` and answers `PATH_RESPONSE(n)`.
5. When the relay verifies the response, it marks path `p` `VALIDATED`.

Rules during joining:
- **Before validation** the relay MAY process authenticated uplink from the candidate path. It MUST limit the bytes it sends to the candidate address to 3× the bytes received from it. For DNS and ICMP carriers it MUST also enforce separate per-client and per-zone query budgets.
- **MTU probing:** once a path is validated (path 0: once the session is `ACTIVE`), each endpoint SHOULD send one separate probe: a `PING` padded with `PADDING` (§10.1) to the size needed to carry a full TUN-MTU packet unfragmented (§17.4). If the probe is acknowledged, the sender raises that path's maximum packet size and stops using `IP_FRAGMENT` there. A lost probe leaves the path at its current size and MUST NOT count toward path health or loss statistics. Probing is separate from validation so that a path with a small MTU still validates. Each direction probes independently, because path MTU can be asymmetric.
- **Retransmission:** `PATH_JOIN` retransmissions use new packets with the **same** `client_cid`, which makes them idempotent. A `PATH_JOIN` for an already-joined path with a different `client_cid` is a `PROTOCOL_VIOLATION`, and that path is abandoned.
- A `PATH_RESPONSE` matching any outstanding challenge for that path is accepted.

### 14.5 Address change on an existing path (NAT rebinding)

The client usually cannot tell that its NAT mapping changed, so the relay handles rebinding on datagram carriers:

- When an **authenticated** `DATA` packet for path `p` arrives from a new source address, the relay keeps sending to the old address.
- It sends `PATH_CHALLENGE` to the new address, subject to the 3× limit.
- It switches path `p` to the new address only after a matching `PATH_RESPONSE` arrives from that address.
- Unauthenticated packets never trigger this.
- On stream carriers, a new connection is a new path.

### 14.6 Path death and recovery

- **Keepalives.** By default, every 10 s of idle time on actively used paths, a sender sends `PING`. The resulting `ACK` serves as the reply and the RTT sample. The interval adapts to NAT lifetime, battery, and transport behavior.
  - On request/response carriers, the authenticated polls double as keepalives.
  - ACKs for low-rate carriers may be sampled so that heartbeats don't congest them.
- **Timeouts.** A path becomes `SUSPECT` after 3 unanswered probes or a measurable transport failure. It becomes `DEAD` after an additional configurable timeout.
- **Session continuity.** The session stays `ACTIVE` while any validated path remains usable. New data is reassigned automatically, with no application reconnect and no new VPN IP.
- **Proof of success.** Never infer path success from local socket writability alone. Require a remote response or authenticated acknowledgements.
- **Abandoning.** `PATH_ABANDON(path_id, code)` retires a path explicitly. Its path ID and CIDs are never reused.

### 14.7 Stateless reset

If the relay loses session state, for example on restart, it can no longer send an authenticated `CLOSE`.

- **Sending a reset.** When the relay receives a `DATA` packet whose `dest_cid` it does not recognize, it MAY reply with `STATELESS_RESET(cid, token)`:

  ```text
  token = HMAC-SHA256(reset_secret, UTF8("ARC/1 reset") || cid)[0:16]
  ```

  - `reset_secret` is persisted across relay restarts.
  - The relay MUST rate-limit resets.
  - The relay MUST NOT send a reset in response to a packet of 25 bytes or fewer. The reset (25 bytes) is always smaller than any `DATA` packet (≥ 37 bytes).
- **Receiving a reset.** The client compares the token, in constant time, with the token issued for that CID: in message 2 for path 0, or in `NEW_PATH` for other paths.
  - On a match, the client treats the session as dead immediately and starts a new handshake.
  - Otherwise it ignores the packet.
- v1 defines no client-to-relay reset. Relays detect lost clients by idle timeout.

## 15. Scheduler and congestion control

### 15.1 Required per-path observations

`transport`, `interface`, `state`, `max_packet_size`, `srtt`, `rttvar`, `loss_ewma`, `delivery_rate`, `send_queue`, `in_flight`, `energy_cost_estimate`, `monetary_cost`, and `last_validated`.

Do not mistake carrier **capacity** for achievable application goodput. Queueing delay, reordering, CPU cost, cellular metering, and duplication overhead matter.

### 15.2 Baseline scheduling algorithm

**v1 MUST support:**

1. A per-path rate cap (token bucket) from configuration and measurement. The scheduler MUST NOT transmit faster than a carrier's native congestion controller (TCP, QUIC) or configured limits allow. v1 does **not** run an additional outer congestion controller over UDP: flows are pinned to a path (item 2), so each tunneled flow's own congestion control adapts to that path, as with single-path VPNs such as WireGuard. Measured capacity is used to weight where *new* flows go. An outer controller for UDP is a measured later extension.
2. Five-tuple hash / flow affinity for IP traffic; keep a flow on a preferred path for a bounded hysteresis interval to limit reordering.
3. Weighted path selection across independent flows based on measured delivery rate, RTT, loss, queueing, and user policy.
4. Immediate control-plane preference for low-latency validated paths; use redundant control probes when path health is uncertain.
5. Path failure migration without terminating the outer session.
6. A policy that avoids loading extremely slow paths (DNS/ICMP) with bulk traffic when faster paths are available.
7. Scheduling at **both** endpoints. The relay chooses downlink paths per flow from the validated paths. By default it SHOULD send a flow's downlink on the path where that flow's most recent uplink packet arrived, unless that path is `SUSPECT` or worse. Only packets carrying IP traffic count: keepalives and probes on other paths MUST NOT move the downlink.
8. Loss-aware primary selection. Each endpoint estimates every path's loss rate in both directions: the sender from acknowledgements (packets declared lost by the packet threshold, out of those resolved), the receiver from gaps in received packet numbers (a late packet cancels the gap it opened). Both feed an EWMA over windows of at least 32 packets and 100 ms. An estimate with no new samples for 30 s is forgotten, since only paths carrying traffic produce samples.

The reference implementation pins all IP traffic to one primary path chosen by the client, which sees uplink loss through acknowledgements and downlink loss through packet-number gaps; the relay follows by item 7. Paths are ranked by

```text
cost(path) = (srtt + 20 ms) * sqrt(max(loss, 0.005))
```

where `loss` is the worse direction's estimate (0 if unknown). This follows the Mathis relation for loss-limited TCP, throughput ∝ 1 / (RTT · √loss). The 20 ms term stands in for the relay-to-destination leg all paths share, and the 0.005 floor keeps a clean path from looking infinitely better than a nearly clean one. A healthy primary is left for loss only when another healthy path costs less than half as much, and at most once per 2 s, so paths of similar quality do not trade places and reorder flows. With equal RTTs this moves traffic off a path above about 2% loss. When every path is lossy, the primary moves at most about once per 30 s, as estimates expire.

Illustrative, **non-normative** path cost:

```text
score(path, flow) =
      + w1 * predicted_completion_time
      + w2 * loss_penalty
      + w3 * queue_delay
      + w4 * metered_data_cost
      + w5 * energy_cost
      + w6 * flow_reordering_penalty
```

Minimize cost subject to per-path rate, carrier MTU, user preferences, and control-plane liveness. Weights MUST be configurable for experiments; avoid claiming a learned optimum without measurement.

### 15.3 Important transport interactions

- Two upstream networks may share one bottleneck; correlated capacity must be measured rather than blindly summed.
- Multi-flow traffic is the primary aggregation target. A single TCP flow may not improve if IP packet striping creates excessive reordering.
- Do not enable general automatic IP retransmissions on top of a reliable TCP carrier; TCP-over-TCP head-of-line effects can be severe.
- QUIC DATAGRAM is useful for unreliable overlay traffic, but QUIC's own loss/congestion behavior still applies to the carrier.
- Consider cost and battery constraints as first-class policy inputs; maximum bandwidth is not always the user's desired objective.

## 16. Transport adapter contract

An adapter MUST expose the conceptual interface below (language-neutral):

```go
type Carrier interface {
    ID() string
    Capabilities() Capabilities
    Open(ctx context.Context, endpoint Endpoint, underlay Underlay) error
    // Send transmits one complete ARC packet. Adapters that need cells
    // (RequiresCells) fragment internally and reassemble on receive.
    Send(ctx context.Context, packet []byte) error
    Recv(ctx context.Context) ([]byte, error)
    Stats() CarrierStats
    Close() error
}

type Capabilities struct {
    Bidirectional bool
    RequestResponseOnly bool
    RequiresCells bool
    MaxPacketSize int  // largest ARC packet sendable without cells
    MaxCellSize int    // when RequiresCells
    SupportsUnsolicitedDownlink bool
    HasNativeCongestionControl bool
}
```

`Send` MUST return either an explicit error or successful local enqueue; success does not imply remote receipt. The adapter MUST maintain bounded transmit and receive queues, expose backpressure, and avoid blocking the session event loop indefinitely. `Underlay` MUST identify an appropriate OS network interface or bound socket when the platform supports it. The adapter MUST keep its sockets outside the TUN routing loop.

### 16.1 UDP adapter (required)

- Send one ARC packet per UDP datagram to the configured relay IP/port. No cell header.
- Start with a maximum UDP payload of 1232 bytes, which is safe on any IPv6 path. Raise it to the full-packet size (§17.4) once the post-validation probe succeeds (§14.4), and probe further with DPLPMTUD (RFC 8899) using `PADDING`.
- Bind sockets to Wi-Fi and cellular separately when the OS permits and report failures independently.
- Carry ARC Noise, control, and data in the same envelope. Validate source association for a joined path.
- Enforce the per-path rate cap and pacing of §15.2. A UDP socket's buffer accepting a write is not delivery.

### 16.2 QUIC adapter (optional but recommended)

- Use an ordinary TLS-authenticated QUIC connection to carry ARC packets in RFC 9221 DATAGRAM frames where available; a dedicated stream handles control or compatibility fallback.
- Outer QUIC security **does not** replace ARC session security because another path may use a completely different carrier.
- As multipath QUIC evolves, prefer its existing path management where it solves the same problem; do not reimplement it gratuitously. The runtime still needs heterogeneous non-QUIC adapters.
- Avoid redundant retransmission semantics on the same packet.

### 16.3 TLS/TCP adapter (required)

- Dial a configured relay endpoint with normal TLS 1.3 server identity verification and ALPN (provisionally `arc/1`).
- Carry length-prefixed ARC packets (§12.2) over the resulting TLS byte stream.
- Expose delivery metrics conservatively: remote ACKs distinguish true overlay arrival from local stream-buffer success.
- Treat long-lived head-of-line delay as a scheduling cost, particularly for UDP application traffic encapsulated over TCP.

### 16.4 HTTPS / enterprise proxy adapter (optional)

- Support standards-based HTTP CONNECT where explicitly permitted and available. Consider RFC 9298 CONNECT-UDP or RFC 9484 CONNECT-IP for compatible proxy infrastructure.
- Do not assume arbitrary HTTP endpoints are relays. Authenticate both proxy access and ARC relay identity.
- Frame ARC packets across the approved stream or datagram mechanism. HTTP proxy support is a compatibility layer, not a pretext to ignore network policies.

### 16.5 DNS request/response adapter (experimental, feature-gated)

**Model:** Client issues queries for a subdomain delegated to the operator's authoritative DNS service. That authoritative endpoint can receive upstream encoded cells and supply downstream encoded cells as DNS answers, when permitted by the resolver and network.

- Requires an operator-controlled DNS zone, explicit authorization to use the network's DNS facility in this way, and a reachable authoritative service.
- Query type for the experiment: `TXT` under a configurable dedicated zone.
- Each question name is constructed as `<nonce>.<b32-label-1>.[<b32-label-2>...]._arc.<zone>`, where `<nonce>` is 13 lowercase no-padding base32 characters encoding 8 random bytes, and the remaining labels are a lowercase no-padding base32 encoding of exactly one `CELL` (§12.1) divided into labels of **at most 50 ASCII characters**. Decoders MUST be case-insensitive, because resolvers may randomize the case of query names (DNS 0x20). The example configured zone `example.net` therefore yields names ending in `._arc.example.net`. The entire DNS name MUST remain within DNS length limits; the adapter sizes upstream cells to the current zone suffix and label budget.
- Authoritative responses MUST contain exactly one TXT RR in the successful response, with TXT character-strings concatenated in wire order. Its ASCII content is exactly `A1:` followed by the unpadded base64url encoding of one downlink cell, or exactly `A1:-` when no downlink cell is queued. Downlink cells default to at most 280 bytes, so the answer fits in a 512-byte DNS response without EDNS(0). The downlink cell is taken from the queue of the request's bound association (§12.1). Requests on unbound associations get `A1:-` and never content for another session. The client MUST reject malformed or ambiguous answers and must not assume TXT data from intermediaries remains unchanged.
- Each request MUST have a unique name even when repeating a poll, so caching does not cause accidental stale responses. The authoritative response SHOULD use TTL=0 but **MUST NOT** assume recursive resolvers honor this precisely.
- DNS is inherently request/response here. If no upstream application data is pending, send a **newly encrypted DATA/PING packet**, carried through ordinary cells, at an adaptive, conservatively rate-limited interval to collect queued downlink cells. The authenticated packet MUST fit the channel by cell fragmentation; if no suitable one-cell PING fits the DNS name budget, treat this transport as ineffective. Never use unauthenticated empty polls; the encrypted PING identifies and authenticates the requesting session.
- Maintain strict per-client, per-resolver, and per-zone query budgets. Do not hammer public recursive resolvers, attempt to hide abnormal use, or assume that resolvers and captive portals will allow this behavior.
- Handle resolver rewriting, negative caching, TXT response truncation, transport changes, DNSSEC incompatibilities, and intermittent packet loss by declaring the path unusable rather than sending indefinitely.
- Expect poor efficiency: base32 expands bytes ~1.6×, DNS labels restrict query payload, each ARC packet may need many cells, and downstream progress may require client polling. The DNS path SHOULD normally be control-only when a better path exists.

**Protocol mapping note:** The above defines a workable *experimental adapter*, not a guarantee that a DNS query will reach the authoritative relay. A production adapter needs interoperable explicit answer grammars, truncation behavior, and golden fixtures before its experimental flag is removed.

### 16.6 ICMP Echo adapter (experimental, feature-gated)

- On platforms permitting appropriately privileged ICMP Echo operations, carry one `CELL` (§12.1) in an Echo Request's data field to a **relay host under the operator's control**; a cooperating Echo responder returns the next downlink cell inside an Echo Reply.
- Support IPv4 ICMP Echo (RFC 792) and, only when implemented/tested, IPv6 Echo (RFC 4443).
- The implementation MUST distinguish an ordinary kernel-generated echo reply (which simply echoes the request payload) from an ARC-aware reply. ARC reassembly plus authenticated session headers provide the definitive test; a naive ping response is **not** proof of a usable ARC path.
- The relay host MUST suppress the kernel's own Echo Replies for the ARC target address (for example Linux `net.ipv4.icmp_echo_ignore_all`, or a dedicated address with firewall rules). Otherwise the client receives two replies. The relay may require raw-socket/ICMP privileges and OS firewall configuration to implement custom payload replies. In v1 the client side is Linux-only: unprivileged ICMP sockets (`net.ipv4.ping_group_range`) or raw sockets. Apple Network Extension providers are not expected to support it. Client OS VPN APIs may not expose needed ICMP privileges. Detect unsupported platforms and disable this adapter cleanly.
- ICMP is request/response under this profile. Poll using a normal encrypted ARC DATA/PING packet, not a bare echo with arbitrary filler. Use bounded polling, small payloads, anti-amplification, and abuse controls; do not rely on unsolicited server messages.
- Packet loss, ICMP shaping, inconsistent middleboxes, and short datagram lifetimes are expected. This is reachability/fallback functionality, not the primary high-bandwidth link.

### 16.7 Transport discovery policy

Candidate discovery MUST be conservative:

1. Enumerate available physical interfaces and explicit user/operator-configured gateways.
2. Probe direct UDP and verified TLS/TCP first.
3. Optionally probe explicitly configured HTTPS proxies.
4. Probe DNS/ICMP adapters **only** when enabled by user/operator policy and permitted for that network.
5. Validate the remote authenticated ARC session over a path before making it eligible for application traffic.
6. Persist a short-lived, privacy-respecting negative cache for repeatedly failing transport/interface pairs, but retry when the network identity materially changes.

Never equate an open port, working ping, a successful ordinary DNS lookup, or access to a named messaging platform with permission to carry arbitrary traffic.

## 17. IP routing, addressing, DNS, and MTU

### 17.1 Client TUN

- Create a virtual point-to-point network interface after authenticated configuration.
- Apply IP routes and DNS settings as an atomic operation where the OS permits.
- Linux reference: TUN + routing policy rules; isolate outer adapter sockets from the overlay (socket marks, interface binding, and/or reserved host routes).
- Android: `VpnService` and `protect(socket)` to prevent loopback of tunnel sockets; bind underlays to specific `Network`s when feasible.
- Apple platforms: `NEPacketTunnelProvider` / Network Extension entitlement; use in-provider networking APIs and test per-interface binding behavior. Platform permissions are a product dependency, not merely a Go library concern.

### 17.2 Relay/gateway

- Lease a unique virtual IPv4 address per authenticated session in the initial implementation.
- Verify client source addresses; reject spoofing and disallowed destination classes.
- Implement outbound SNAT/masquerading for IPv4 or an equivalent policy-controlled forwarding model.
- Enforce tenant isolation, egress ACLs, DNS policy, anti-spam restrictions, and per-session bandwidth quotas.
- Default: no unsolicited inbound connectivity to clients; do not allow one client's packets into another client's virtual address space.
- Persist no user traffic content by default. Log only minimal operational data with explicit retention limits.

### 17.3 DNS resolution

DNS used *by applications* inside the VPN is distinct from the **DNS carrier adapter**. The client should normally direct application DNS queries through the protected virtual interface to a designated relay resolver to avoid leaks. The DNS carrier adapter uses an out-of-band, explicitly configured resolver and operator-controlled zone; it MUST avoid recursively routing its own resolution back into the virtual interface.

### 17.4 MTU

- Start with a conservative virtual MTU of **1280 bytes** (IPv6-compatible), even if v1 initially enables only IPv4.
- Per-packet overhead for a full TUN packet is **37 bytes**: 18 bytes of `DATA` header, a 16-byte AEAD tag, and a 3-byte `IP_PACKET` frame header. A 1280-byte TUN packet therefore needs a 1317-byte UDP payload, which is a 1345-byte path MTU over IPv4 or 1365 bytes over IPv6. Paths that cannot carry that use `IP_FRAGMENT` (12 more bytes per fragment). Cells (18 bytes) apply only to constrained carriers.
- `tun_mtu` is fixed for the session by `AUTH_RESULT`, because flows may move between paths of different MTUs.
- Both endpoints SHOULD clamp TCP MSS on the TUN interface to `tun_mtu − 40`.
- Use ARC `IP_FRAGMENT` and cell fragmentation rather than depending on unreliable outer IP fragmentation.
- The relay SHOULD implement appropriate ICMP Packet Too Big / fragmentation-needed behavior if its egress MTU is smaller; do not create black-hole paths.
- A lower TUN MTU may improve constrained-carrier performance but does not eliminate DNS's substantial encoding overhead.

## 18. Optional application SDK: proposed future extension

Transparent IP is mandatory; an application-specific SDK is not.

A future SDK SHOULD make the runtime's existing functions available without granting arbitrary access to traffic of other applications. Suggested interface:

```go
type Runtime interface {
    NetworkState(ctx context.Context) (State, error)
    Paths(ctx context.Context) ([]PathInfo, error)
    SetPriority(ctx context.Context, flow FlowHandle, p Priority) error
    OpenStream(ctx context.Context, service string, opts StreamOptions) (Stream, error)
    SendMessage(ctx context.Context, service string, body []byte, opts MessageOptions) error
    ExecuteRemote(ctx context.Context, task Task, policy PrivacyPolicy) (Result, error)
}
```

`ExecuteRemote` must be a **cooperative application operation**, with explicit service permissions, resource budgets, trust boundaries, sandboxing, privacy policy, cancellation, and auditability. It is not an extension of transparent arbitrary HTTPS tunneling.

Potential opt-in capabilities: request prioritization, content-addressed caching/deduplication, remote rendering, remote fetching, typed RPC, application-specific compression, and store-and-forward synchronization. Each requires separately specified security and failure semantics.

---

# Part III — Build plan

## 19. Suggested implementation stack and repository

**Recommendation:** Go for the first daemon, protocol implementation, relay, and Linux prototype; thin Swift/Kotlin adapters for platform VPN integrations. Use vetted cryptographic and transport libraries. A Rust core is an alternative if mobile binary size, tight memory ownership, or FFI becomes paramount.

```text
arc/
  README.md
  spec/
    ARC-v1-Protocol-and-Implementation-Handoff.md
    wire-registry.md
    ARC-v1-Wire-Fixtures.json
    generate_arc_fixtures.py
  cmd/
    arc-client/                # Linux CLI and TUN daemon
    arc-relay/                 # Session terminator + egress
    arc-lab/                   # Impairment scenarios / replay harness
  internal/
    wire/                      # Packet, frame, cell parsers + encoders
    crypto/                    # Noise IK handshake, explicit-nonce AEAD, epochs, cookies
    session/                   # Session state and replay protection
    path/                      # Path identity, challenge/response, probes
    scheduler/                 # Flow mapping, policy, pacing, metrics
    reassembly/                # Cell and original IP datagrams
    tun/                       # Linux virtual interface management
    gateway/                   # Address allocation, packet policy, forwarding
    carrier/
      udp/
      tlstcp/
      quic/                    # optional
      dns/                     # experimental
      icmp/                    # experimental
  sdk/                         # future; can initially expose only state
  mobile/
    ios/                       # NEPacketTunnelProvider glue
    android/                   # VpnService glue
  test/
    fuzz/
    interoperability/
    impairment/
    network-namespace/         # Linux netns + tc netem; on macOS run inside a privileged Docker container
    performance/
  deploy/
    dev-relay/
    production-hardening/
```

### Recommended concurrency model

One actor/event loop owns each session's immutable identity and mutable state (keys, replay windows, datagram IDs, paths). Adapter I/O goroutines push bounded events to this actor. Packet encode/encrypt may run in parallel **only** after the actor has atomically assigned each packet its `(path_id, epoch, packet_number)`. Incoming decrypt may run in parallel but replay admission and key-epoch transitions must be race-safe.

Never let one blocked DNS/ICMP carrier stall the session actor. Use backpressure and per-path bounded queues.

## 20. Build stages with acceptance gates

### Stage A — Wire, crypto, single path

**Implement:** Packet/frame/cell encoding and validation; Noise IK handshake with cookies; AUTH/RESULT; per-path replay windows; epoch rekey; stateless reset; UDP carrier; Linux TUN; one Linux relay with controlled IPv4 egress; TUN loop avoidance.

**Exit criteria:** Two independent processes can exchange IP traffic through a relay; a wrong relay key makes the handshake fail; forged or replayed DATA packets never reach the TUN; a relay restart is detected through stateless reset and leads to a new session; malformed input survives fuzzing without panics or unbounded allocation.

### Stage B — Two paths and state continuity

**Implement:** Separate underlays, path state machine, NEW_PATH/PATH_JOIN/challenge/response, relay-side rebinding validation, ACK-range telemetry, flow-pinned weighted scheduler, failover, per-path queues, congestion/pacing hooks, metrics dashboard.

**Exit criteria:** Concurrent traffic over two independently rate-limited links improves aggregate multi-flow goodput over the faster link alone in an appropriate test; unplugging one link leaves VPN-assigned IP and session intact; prevalidated remaining path resumes forwarding without a full handshake.

### Stage C — TCP and HTTP compatibility

**Implement:** TLS/TCP length-prefixed packet stream adapter; stream backpressure; authenticated TLS server validation; controlled HTTP CONNECT compatibility experiment.

**Exit criteria:** Same session can join a TLS/TCP path while UDP is working, stop using UDP, and continue IP traffic via TLS/TCP. Test head-of-line blocking and avoid misleading performance claims.

### Stage D — DNS and ICMP laboratory adapters

**Implement:** Dedicated authorized test DNS zone and custom authoritative responder; DNS query encoding/answer parsing/polling; authorized ICMP responder on controlled hosts; capability probes, strict budgets, and platform disablement.

**Exit criteria:** Explicitly configured restricted **lab** network can carry session control (and then small IP traffic, if feasible) through each adapter; rate limits work; malformed/rewritten DNS and normal ICMP Echo responses cannot be mistaken for authenticated ARC data; unpermitted carriers are never automatically tried.

### Stage E — Hardening and deployability

**Implement:** Production auth backend, tenancy, quotas, metrics, alerting, static analysis, fuzzing at every parser boundary, secrets rotation, relay HA strategy, packet capture privacy controls, crash recovery, and platform packaging.

**Exit criteria:** Independent security review completed; denial-of-service budgets exercised; multi-day soak tests survive network churn; egress policy blocks source spoofing, cross-tenant access, and unauthorized destinations.

### Stage F — Optional SDK / content-aware execution

**Separate design effort:** Per-app permissions, privacy model, explicit remote-operation RPC protocol, cache consistency, content-aware compression, remote rendering, trust, and execution sandboxing. Do not let it delay a usable baseline VPN.

## 21. Example configuration (illustrative, not final schema)

```yaml
client:
  relay_identity:
    address: relay.example.net
    static_noise_public_key: "BASE64_X25519_PUBLIC_KEY"
    auth_credential_source: "os-keychain"
  vpn:
    mode: full-tunnel
    tun_mtu: 1280
    dns_mode: via-relay
    ipv6: false
  scheduler:
    policy: balanced # balanced | throughput | latency | low-cost
    allow_metered_cellular: true
    max_active_paths: 4
    flow_affinity_seconds: 20
  adapters:
    udp:
      enabled: true
      endpoint: "relay.example.net:4433"
    tls_tcp:
      enabled: true
      endpoint: "relay.example.net:443"
      expected_alpn: "arc/1"
    dns:
      enabled: false
      authoritative_zone: "example.net"
      qps_budget: 2
    icmp:
      enabled: false
      echo_target: "192.0.2.10"
  privacy:
    record_packet_contents: false
    diagnostics_opt_in: false

relay:
  require_auth: true
  ipv4_pool: "10.77.0.0/16"
  max_sessions_per_identity: 3
  default_egress_policy: restricted
  max_handshake_attempts_per_source_per_minute: 30
```

Values in `192.0.2.0/24` are documentation-only IPs. This YAML is an illustrative configuration profile; actual file parsing/schema validation belongs to Stage A.

## 22. Validation matrix

| Scenario | Underlay condition | Expected outcome |
|---|---|---|
| Baseline | UDP only, no loss | Full IP connectivity, correct NAT and DNS behavior |
| Multipath | 2 independent 25 Mbps links | Measurable multi-flow gain; track useful goodput vs single link |
| Asymmetric | 100 Mbps/150 ms and 20 Mbps/30 ms | Interactive flows remain responsive; bulk spreads appropriately |
| Churn | Wi-Fi disappears while cellular remains | Same session and VPN IP; no new app-facing network configuration |
| NAT rebinding | Source UDP address changes | Relay validates new address on the same path before moving downlink |
| Relay restart | Relay loses session state | Client receives a stateless reset and re-handshakes promptly; no long black hole |
| Handshake flood | Spoofed HANDSHAKE_INIT flood | Relay switches to cookies; no DH per spoofed packet; legitimate clients connect |
| Slow + fast paths | DNS-latency path alongside fast UDP | Slow-path packets are not dropped by the fast path's replay window |
| UDP blocked | TLS/TCP works | VPN stays reachable through authenticated TCP adapter |
| Constrained | Lab DNS resolver + authorized authoritative zone | Control-plane and small-payload fallback subject to budgets |
| ICMP-only lab | Permitted controlled Echo responder | Explicit fallback, with ordinary ping responses rejected |
| Blackhole | All carriers unavailable | No false connectivity claim; queues bounded; fail safely |
| Spoofed path | Forged PATH_JOIN or response | Not admitted; requires authenticated session and challenge |
| Packet replay | Old valid DATA ciphertext injected twice | At most one authenticated delivery |
| Out of order | Arbitrary reorder and duplication | Correct IP fragment reassembly and dedup; bounded memory |
| Malformed | Truncated header/length/TLV/cell | Drop safely, no panic, no large allocation |
| Key rollover | Old and new packets reordered | Epoch transition succeeds; invalid future epoch rejected |
| DNS rewrite | Resolver changes labels/TXT answers | Detect invalid carrier; disable or retry within policy |
| Source spoofing | Client inner IPv4 src differs from lease | Relay refuses egress |
| Routing loop | VPN captures relay endpoint by mistake | Preflight validation detects/protects underlay sockets |
| IPv6 | IPv6 disabled in baseline | No silent IPv6 leak; later test valid dual stack |

### Metrics to collect

- Per path: link presence, RTT p50/p95, loss, goodput, queueing delay, send bytes, receive bytes, control overhead, carrier retransmissions where exposed, power/cost estimate.
- Per session: logical lifetime, authentication events, active path count, migrations, bytes completed, duplicate fragments, replay drops, fragment timeout, DNS fallback time, stall duration.
- End-to-end: browser task completion time, page first-interaction latency, file transfer duration, multi-flow throughput, single-flow throughput, packet-loss resilience, battery impact.
- Privacy: default metrics MUST exclude plaintext IP payloads, DNS QNAME contents other than aggregate transport health, credentials, private session keys, and full URLs.

### Quantitative initial performance gates (targets, not guarantees)

- In a clean lab, baseline UDP adapter goodput should aim for **≥80% of a mature single-path VPN reference** under otherwise identical load, with CPU profiling identifying bottlenecks.
- With two comparable independent links and sufficient parallel flows, target **≥1.6×** the goodput of the faster single link in controlled conditions; do not claim this for a single TCP connection without measurement.
- With an already-validated alternate path, aim for **sub-2-second** useful forwarding recovery after detectable primary path failure; report median and p95 separately.
- Fuzz parsers to zero crashes and bounded allocations; validate replay and source-address policy with deliberately adversarial fixtures.

## 23. Interoperability fixture requirements

A **companion JSON file** (`ARC-v1-Wire-Fixtures.json`) and its Python generator (`generate_arc_fixtures.py`) provide deterministic packet, frame, cell, AEAD, rekey, cookie, reset-token, and invalid-input examples. These are codec fixtures; they do not replace Noise IK handshake vectors.

Before declaring ARC/1 on-wire formats frozen, add deterministic fixtures for:

1. Exact encoding of every packet type for known field values. *(v0.2 fixtures: done)*
2. Exact cell header and byte-for-byte fragment reassembly. *(done)*
3. Every frame type, including lengths, `ACK` range decoding, `IP_FRAGMENT` offset/length validation, and unknown-extension behavior. *(done)*
4. Noise IK handshake using a vetted implementation, cross-checked against a second one, including rejection on a relay-key mismatch. *(done: generated with Python `noiseprotocol`, verified against Go `flynn/noise`)*
5. Explicit-nonce ChaCha20-Poly1305 with fixed keys, a nonzero `path_id`, an authenticated header, and tag-failure mutation cases. *(done)*
6. Noise `REKEY` vectors and out-of-order epoch acceptance/rejection. *(done)*
7. Cross-language client↔relay interop, including changes from UDP to TLS/TCP mid-session.
8. DNS encoding of a known cell and parsing of multi-string TXT response, including case normalization and negative caching fixtures.
9. ICMP request/response framing on a controlled test host and proof that ordinary echo replies are not accepted as ARC reply data.

**Do not invent cryptographic expected outputs by hand.** Generate them with a vetted implementation, check with at least one independent implementation, and commit them as checked-in fixtures.

## 24. Open questions and deferred design decisions

**O1 — One relay versus multi-relay:** v1 binds a session to one logical relay. Geographic relay selection and mid-session relay migration require authentication, NAT state continuity, and likely a network of coordinated relays; defer.

**O2 — Two fragmentation layers.** *Resolved in v0.2:* cells apply only to constrained request/response carriers. Fast carriers send ARC packets directly.

**O3 — Flow-aware vs packet striping:** v1 uses flow affinity. Controlled single-flow striping with reordering buffers and limited duplication should be a benchmarked extension.

**O4 — Loss estimation:** v0.2 adds per-path packet numbers, ACK ranges, and `ack_delay`. Still open: how far ACKs can be sampled on low-rate carriers while loss estimates stay useful.

**O5 — DNS adapter viability:** Which resolvers pass queries, honor suffix/QTYPE, and permit bidirectional data with acceptable performance? It may be useful only for control-plane survival.

**O6 — ICMP availability:** Which target OS versions permit custom ICMP payload send/receive from a VPN extension without elevated privileges? Disable where unsupported.

**O7 — Authentication and gateway trust:** Finalize short-lived credential issuance, per-device revocation, relay identity rotation, tenant boundaries, and operator privacy policy before open beta.

**O8 — Remote rendering:** A future opt-in SDK can reduce transferred information by changing the *representation of a task*, not just compressing bytes. That requires its own security, privacy, and application-consistency specification.

**O9 — Resource policy:** Battery, metered-cellular caps, cost, and operator traffic restrictions must be configurable. A throughput-only objective will be wrong in many situations.

**O10 — Licensing/IP strategy:** Investigate existing multipath VPN implementations, MASQUE, transport libraries, and cryptographic implementations before claiming novelty or distributing adapted code.

## 25. Immediate engineering backlog

Ordered, each item independently demonstrable:

- [ ] Define `wire` parser/serializer with zero-copy bounded parsing and negative corpus.
- [ ] Define cell reassembly with per-association quotas and timeouts.
- [ ] Integrate vetted Noise IK (relay key pinned by construction), cookies, and stateless reset.
- [ ] Implement DATA AEAD with per-path packet numbers, epoch rekey, and per-path anti-replay windows.
- [ ] Implement AUTH/RESULT and session state actor.
- [ ] Implement IP_FRAGMENT split/reassembly and dedup.
- [ ] Build Linux UDP client/relay with a TUN device and a single leased IPv4 address.
- [ ] Implement relay IPv4 policy, egress SNAT, DNS-forwarding config, and anti-spoof checks.
- [ ] Add NEW_PATH/PATH_JOIN/challenge/response, rebinding validation, and multi-interface UDP sockets.
- [ ] Add active telemetry and flow-affinity weighted scheduling.
- [ ] Build network namespace + `tc netem` benchmark harness and result exporter (Linux CI natively; privileged Docker container on macOS).
- [ ] Add TLS/TCP adapter and mid-session transport migration test.
- [ ] Add feature-gated DNS test-zone adapter; prove behavior under resolver constraints.
- [ ] Add feature-gated ICMP adapter only for supported, authorized platforms.
- [ ] Implement production auth/operations; security review; long soak; mobile platform integration.

## 26. Standards and technical references

Normative or useful reference materials, verified as relevant as of document date:

- **RFC 2119 / RFC 8174:** Requirement keywords — https://www.rfc-editor.org/rfc/rfc2119 and https://www.rfc-editor.org/rfc/rfc8174
- **Noise Protocol Framework:** Standard handshake patterns, `Noise_IK_25519_ChaChaPoly_SHA256`, and `REKEY` — https://noiseprotocol.org/noise.html
- **WireGuard:** Prior art for Noise IK with cookies over UDP — https://www.wireguard.com/papers/wireguard.pdf
- **RFC 8899:** Datagram Packetization Layer PMTU Discovery — https://www.rfc-editor.org/rfc/rfc8899
- **RFC 8439:** ChaCha20-Poly1305 — https://www.rfc-editor.org/rfc/rfc8439
- **RFC 2104:** HMAC (cookies, reset tokens) — https://www.rfc-editor.org/rfc/rfc2104
- **RFC 9000 / RFC 9221:** QUIC transport and unreliable QUIC DATAGRAM — https://www.rfc-editor.org/rfc/rfc9000 and https://www.rfc-editor.org/rfc/rfc9221
- **RFC 8684:** Multipath TCP — https://www.rfc-editor.org/rfc/rfc8684
- **RFC 9298 / RFC 9484:** CONNECT-UDP and CONNECT-IP — https://www.rfc-editor.org/rfc/rfc9298 and https://www.rfc-editor.org/rfc/rfc9484
- **RFC 1035 / RFC 6891:** DNS message format and EDNS(0) constraints — https://www.rfc-editor.org/rfc/rfc1035 and https://www.rfc-editor.org/rfc/rfc6891
- **RFC 792 / RFC 4443:** ICMPv4 and ICMPv6 — https://www.rfc-editor.org/rfc/rfc792 and https://www.rfc-editor.org/rfc/rfc4443
- **IETF Multipath QUIC draft:** Work in progress and not a final RFC at this document date — https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/
- **Apple Packet Tunnel Provider:** https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
- **Android VpnService:** https://developer.android.com/reference/android/net/VpnService
- **Existing tunnel examples (background only):** iodine (https://github.com/yarrick/iodine) and ptunnel-ng (https://github.com/utoni/ptunnel-ng). Do not assume fitness, security, or licensing for ARC.

---

# Final architecture summary

**ARC is a drop-in network first, a programmable communications runtime second.**

The client presents a normal virtual IP interface. Beneath it, a persistent encrypted session is mapped to authenticated, independently validated physical paths. The scheduler selects paths according to actual application goodput, liveness, latency, cost, and policy. Carriers may be bidirectional streams, datagrams, or constrained request/response services; DNS and ICMP are explicitly optional controlled fallback adapters rather than hidden assumptions about what a network permits. The remote relay reassembles and forwards policy-approved IP traffic. A future SDK can expose richer work semantics, but ordinary applications remain unaware of ARC.

**First concrete milestone:** Two Linux machines exchange IP traffic through an ARC relay over one UDP path using the defined authenticated packet, cell, and frame formats. **Second:** simultaneously use two independent paths without changing the session or virtual IP address. **Third:** make the exact same core session engine run over TLS/TCP, followed by DNS and ICMP in an authorized laboratory.

**Document maturity warning:** This specification is sufficiently concrete to start a reference implementation and generate interoperability fixtures. It is *not* a completed or security-audited Internet standard. Freeze wire bytes only after independent interop tests and cryptographic review.

---

# Appendix A — Changes from v0.1

| Area | v0.1 | v0.2 | Reason |
|---|---|---|---|
| Handshake | Noise XX + separate pin check | **Noise IK**; the pin is enforced by the cryptography; 1 RTT | The client always knows the relay key; a pin check that can be skipped is a hazard |
| DoS | "MUST validate addresses", no mechanism defined | `COOKIE_REPLY` under load; responses smaller than requests | Avoids a Diffie-Hellman per spoofed packet |
| Header | 40 bytes with magic, version, session ID, path ID, 32-bit epoch | **18 bytes**: type, epoch_low, dest CID, packet number | Size and privacy: a fixed session ID let observers link every path |
| Identity on the wire | 16-byte session ID on every packet | Separate receiver-chosen CIDs for each path | An observer cannot link paths |
| Packet numbers | One session-wide space; window shared across paths | **Per-path** spaces; `path_id` in the nonce; replay window per path | Slow paths no longer fall outside the fast path's window; per-path loss detection is trivial |
| Rekey | Custom HKDF chain every 2^20 packets / 30 min; counters reset | Noise `REKEY` every 120 s / 2^32 packets; counters continue; 1-byte epoch resolution; limit on failed decryptions | Fewer ARC-specific crypto choices; the real ChaCha20-Poly1305 limits are integrity limits |
| ACK | Up to 16 explicit u64 packet numbers, no delay field | QUIC-style ranges + `ack_delay_us`, per path; ack-eliciting rules | Enables loss and RTT estimation; correct RTT on poll-driven carriers |
| Overhead per full TUN packet on UDP | 92 bytes; 1280-byte packets exceeded the 1200-byte default payload | **37 bytes**; defaults consistent | v0.1 fragmented every full-size packet |
| IP framing | `IP_FRAGMENT` for everything, redundant length fields | `IP_PACKET` (3 bytes) + `IP_FRAGMENT` only when needed | Overhead |
| Cells | On every carrier, grouped by transport peer | Constrained carriers only; grouped by `assoc_id`; per-association downlink queue | Resolvers use many egress IPs; downlink polling could not work |
| Paths | Client-chosen IDs; JOIN/CHALLENGE/RESPONSE/ACCEPT | Relay-issued `NEW_PATH` slots; JOIN → CHALLENGE → RESPONSE | CIDs and reset tokens issued ahead; one fewer round trip |
| NAT rebinding | "Handle as a new path" (the client cannot detect it) | Relay validates the new address for the same path | Matches what the client can actually observe |
| Lost session | Timeout only | `STATELESS_RESET` with a token derived per CID | Avoids long black holes after relay restarts |
| Credentials | `AUTH` once per session | Refresh with `AUTH` in a running session | Short-lived credentials vs long sessions |
| Congestion control | Required outer pacing/CC on UDP | Per-path rate caps; flow pinning lets inner CC adapt | Simpler; avoids fighting the tunneled TCP |
| Relay scheduling | Unspecified | Downlink follows each flow's most recent uplink path | The relay must choose paths too |
| ICMP | — | Kernel echo suppression required; Linux-only client | Avoids duplicate replies; matches platform reality |
