# ARC/1 — Adaptive Relay Connectivity
## Implementation Handoff and Experimental Protocol Specification

**Document ID:** `draft-arc-transport-00`  
**Version:** 0.1 — design baseline, **not an IETF RFC**  
**Date:** 2026-10-10  
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
4. **Transport adapters.** Convert generic bounded *cells* into communications appropriate for one available channel. An adapter transports opaque encrypted ARC packets; it must not interpret the tunneled IP traffic.
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

**Data plane:** IP fragmentation into authenticated ARC frames, encapsulation into carrier cells, path scheduling, reassembly, deduplication, and virtual-interface delivery.

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

- **Session:** Long-lived authenticated cryptographic relationship between one client and one relay, identified by a random 128-bit Session ID.
- **Path:** One concrete bidirectional or request/response communication relationship over a particular adapter and underlying network interface.
- **Adapter:** Encodes/decodes carrier cells for a specific transport, such as UDP, TLS/TCP, DNS, or ICMP.
- **ARC packet:** Versioned packet with an authenticated header and zero or more encrypted frames.
- **Cell:** A bounded carrier-neutral fragment of an ARC packet; a single ARC packet may require multiple cells on a constrained carrier.
- **IP fragment:** An ARC-level fragment of one complete original TUN IP packet; not IP-layer IPv4 fragmentation.
- **Goodput:** Useful bytes/operations completed at the receiving application, excluding duplicate, retransmitted, and carrier overhead bytes.

All multibyte integers are **unsigned, network-byte-order (big endian)** unless explicitly noted. Unused fields are zero and MUST be rejected if nonzero. Implementations MUST strictly validate lengths before allocating memory.

## 7. Version negotiation and identifiers

- Protocol name: `ARC/1`.
- Wire `version`: `0x01`.
- Packet magic: ASCII `AR` (`0x41 0x52`).
- Cell magic: ASCII `AC` (`0x41 0x43`).
- A Session ID is 16 random bytes generated once per handshake and MUST NOT be reused with different keys.
- The client selects each 32-bit `path_id`. `path_id=0` is the bootstrap path. Additional IDs MUST NOT be reused in the same session.
- ARC/1 recognizes only version 1. Unknown versions MUST be dropped without attempting to decrypt them. Future explicit version negotiation requires a separately authenticated extension; no unauthenticated downgrade fallback.
- A version-1 endpoint MUST silently drop packets with unknown `kind` values, malformed lengths, or nonzero reserved bits. It MAY emit a rate-limited diagnostic on an authenticated path.

## 8. ARC packet envelope

Every ARC packet begins with this **40-byte fixed header**:

```text
Offset  Size  Field
0       2     magic            = 0x41 0x52
2       1     version          = 0x01
3       1     kind             = 0x01 HANDSHAKE | 0x02 DATA
4       1     flags            = 0x00 in ARC/1
5       1     reserved         = 0x00
6       16    session_id       = opaque random bytes
22      4     epoch            = 0 during handshake; starts at 0 for DATA
26      4     path_id          = 0 for handshake; otherwise current path
30      8     packet_number    = per-direction counter within an epoch
38      2     payload_length   = bytes following this header
40      N     payload          = handshake bytes or authenticated ciphertext
```

- Maximum total ARC packet size for v1: **16,384 bytes**, including the 40-byte header.
- `payload_length` MUST exactly equal the available bytes after the header.
- `kind=HANDSHAKE`: `epoch=0`, `path_id=0`, `packet_number=0,1,2` respectively for the three Noise XX handshake messages; payload is the Noise message, not additional ARC frame TLVs. Header fields and Session ID are bound into the Noise prologue described below.
- `kind=DATA`: payload is ChaCha20-Poly1305 ciphertext plus a 16-byte authentication tag. **The entire 40-byte ARC header is AEAD associated data.** Ciphertext decrypts to one or more ARC frame TLVs.
- `DATA` payloads smaller than 16 bytes MUST be rejected. An empty frame sequence is not sent.
- A session uses a single, session-global outgoing packet-number space *per direction and epoch*. Paths do **not** allocate independent packet-number spaces. Packet number uniqueness is enforced before encryption, even if the chosen path fails.
- A sender MUST NOT retransmit a previously encrypted packet after changing its authenticated `path_id`. Retransmitted control information uses a **new** packet number and encryption operation.

### 8.1 Nonce and header authentication

For DATA packets in each direction and epoch:

```text
AEAD      = ChaCha20-Poly1305 (RFC 8439)
Nonce     = four 0x00 bytes || uint64_le(packet_number)
AAD       = all 40 header bytes, exactly as transmitted
Plaintext = concatenated frame TLVs
```

The 64-bit little-endian nonce suffix matches the Noise ChaChaPoly nonce layout. Although header integers are big-endian, this AEAD nonce layout is explicitly little-endian. Packet numbers start at zero in each new epoch. Duplicate packet numbers under the same key MUST NEVER be encrypted.

## 9. Authentication and session establishment

### 9.1 Required cipher suite

ARC/1 MUST use the established **`Noise_XX_25519_ChaChaPoly_SHA256`** handshake pattern. This selection avoids inventing a new key agreement and provides ephemeral Diffie-Hellman forward secrecy.

Each relay has a persistent 32-byte X25519 static private key and published public key. A client MUST obtain and pin the expected relay static public key via its trusted configuration or another authenticated provisioning mechanism **before** considering a session authenticated. Noise XX alone does not supply external server identity verification.

A client may generate a persistent X25519 static identity locally. Application-level authorization uses a separate short-lived credential and MUST NOT rely only on identifying this client public key.

**Noise prologue:** the exact byte concatenation `UTF8("ARC/1") || session_id[16]`. Each handshake message is carried as the payload of the corresponding ARC `HANDSHAKE` packet. Noise handshake payloads are zero length in v1.

### 9.2 Handshake sequence

```text
Client                                          Relay
  |  HANDSHAKE #0: Noise XX message 1              |
  |----------------------------------------------->|
  |  HANDSHAKE #1: Noise XX message 2              |
  |<-----------------------------------------------|
  |  Verify relay static key against local pin     |
  |  HANDSHAKE #2: Noise XX message 3              |
  |----------------------------------------------->|
  |  Derive directional ARC DATA keys              |
  |  DATA: AUTH {credential}                       |
  |----------------------------------------------->|
  |  DATA: AUTH_RESULT {status, addresses, mtu}    |
  |<-----------------------------------------------|
  |  ACTIVE / bootstrap path 0 usable              |
```

For `Noise XX`, the initiator-to-responder and responder-to-initiator keys output by Noise `Split()` become ARC's initial per-direction DATA traffic keys. Implementations MUST use a vetted Noise implementation with access to the resultant traffic keys and an AEAD implementation supporting explicit nonces; the standard sequential Noise transport record wrapper is **not** used because datagrams may arrive out of order.

- The client MUST authenticate the relay key before sending `AUTH` or accepting configuration.
- The server MUST NOT forward IP traffic before successful `AUTH` credential validation.
- The client MUST NOT install full-tunnel routes until receiving `AUTH_RESULT(success)`.
- Credentials SHOULD be short-lived, audience-bound to the relay/operator, revocable, and transmitted only inside DATA encryption.
- The server MUST implement handshake timeouts, per-origin rate limiting, resource quotas, and address-validation/amplification protection for spoofable datagram carriers.
- No 0-RTT application data or resumed session tickets in v1. A failed or expired session requires a new Noise handshake with a new Session ID.

### 9.3 Session states

```text
NEW -> HANDSHAKING -> AUTHENTICATING -> ACTIVE -> DRAINING -> CLOSED
  \-> FAILED       \-> FAILED           \-> FAILED
```

- After completing Noise message 3, both peers enter `AUTHENTICATING`.
- The relay transitions to `ACTIVE` after validating `AUTH`; the client after validating success in `AUTH_RESULT`.
- A path failure MUST NOT close an `ACTIVE` session while another validated path remains usable.
- If all paths are unavailable, the session MAY remain suspended for a configured grace interval (default: 120 seconds), with bounded queued control work; do not indefinitely buffer arbitrary IP traffic.
- Session and token expiry are independent of path changes.

## 10. Data frame TLV format

A decrypted DATA plaintext consists of one or more frames. Every frame begins with:

```text
frame_type: 1 byte
frame_length: 2 bytes, big-endian
frame_value: frame_length bytes
```

Frames MUST be fully contained within the containing ARC DATA packet. Unknown frame types in `0x80..0xFF` are optional extensions and MAY be ignored; unknown values in `0x00..0x7F` indicate a required feature and MUST cause the packet to be rejected, with a rate-limited authenticated error if possible.

### 10.1 Frame registry

| Hex | Name | Required fields in frame value | Allowed role |
|---|---|---|---|
| `01` | `AUTH` | `credential_length:u16; credential:bytes` (max 1024) | Client → relay, once per session |
| `02` | `AUTH_RESULT` | `status:u8; ipv4:u32; ipv6:16B; prefix4:u8; prefix6:u8; tun_mtu:u16; keepalive_ms:u32; idle_ms:u32; features:u64; dns_ipv4:u32` | Relay → client |
| `03` | `IP_FRAGMENT` | `ip_version:u8; datagram_id:u64; total_len:u16; offset:u16; fragment_len:u16; fragment_data:bytes` | Both, after AUTH |
| `04` | `PATH_JOIN` | `requested_path_id:u32; client_nonce:u64; requested_cell_mtu:u16` | Client → relay |
| `05` | `PATH_CHALLENGE` | `nonce:u64` | Either |
| `06` | `PATH_RESPONSE` | `nonce:u64` | Either |
| `07` | `PATH_ACCEPT` | `path_id:u32; status:u8; negotiated_cell_mtu:u16` | Relay → client |
| `08` | `PING` | `nonce:u64` | Either |
| `09` | `PONG` | `nonce:u64` | Either |
| `0A` | `CLOSE` | `code:u16` | Either |
| `0B` | `ERROR` | `code:u16` | Either, diagnostic only |
| `0C` | `ACK` | `epoch:u32; path_id:u32; count:u8; packet_numbers[count]:u64[]` | Either |

`AUTH_RESULT.status=0` means success. All other values indicate failure; all address and parameter fields MUST be zero on failure. In v1, a zero `ipv6` address with `prefix6=0` disables IPv6. `tun_mtu` MUST be at least 1280 if IPv6 is enabled. `dns_ipv4=0` means no DNS resolver was supplied; full-tunnel mode MUST obtain an authenticated resolver setting from the relay or a trusted, explicit client configuration. The relay controls assigned addresses and routes by deployment policy; receiving an address does not by itself authorize arbitrary inbound Internet exposure.

`IP_FRAGMENT` has a 15-byte fixed value prefix. `fragment_len` MUST exactly match the subsequent byte count; `offset+fragment_len <= total_len`; `total_len` MUST be between 20 and 65535; the completed IP packet MUST pass IP version and declared-length validation. A complete IP packet is represented by `offset=0` and `fragment_len=total_len`. Fragments with overlapping, conflicting byte ranges cause the entire datagram to be discarded.

`ACK.count` MUST be 1–16. These ACKs are **measurements only**: an ACK of an ARC DATA packet does not guarantee application delivery; missing ACKs do not automatically trigger retransmission of IP payloads. ACKs MAY be sampled to reduce overhead. Control requests with a nonce or ID are safe to repeat using a freshly encrypted packet.

Minimal error codes: `1 MALFORMED`, `2 AUTH_FAILED`, `3 UNAUTHORIZED`, `4 PATH_UNAVAILABLE`, `5 CAPACITY`, `6 UNSUPPORTED`, `7 SESSION_EXPIRED`. Unknown error values are informational and SHOULD NOT crash an implementation.

## 11. Packet reassembly and deduplication

- Each sender maintains a monotonically increasing `datagram_id:u64` for each original TUN packet within the session direction. It MUST NOT reuse IDs while the session is alive.
- The receiver reassembles fragments keyed by `(session_id, direction, datagram_id)`, regardless of arrival path.
- It delivers a completed original IP packet **at most once**, even if fragments or whole packets are duplicated on multiple paths.
- Bounded defaults: max 1,024 incomplete IP datagrams per session; max 8 MiB of incomplete IP bytes; 5-second expiry per incomplete datagram; max 65,535-byte original IP packet; max 8,192 recently completed IDs in dedup state. Evict oldest incomplete datagram on quota pressure.
- A missing IP fragment expires; v1 **does not** retransmit the entire TUN datagram automatically. TCP-over-IP can recover its own lost packets; other applications have their own semantics.
- High-loss, high-latency carriers MAY be assigned smaller IP fragments, but they are expected to have poor transparent-IP goodput. This is a measured fallback, not a performance guarantee.
- Peers MUST validate inner IP packet lengths and ownership of virtual source/destination addresses. The relay MUST reject client packets with an IP source address not leased to that session.

## 12. Carrier cell fragmentation

A cell is the universal bounded adapter payload. Its content is *a fragment of a complete encrypted ARC packet*, not arbitrary application plaintext. Cells allow DNS and other limited carriers to transport an ARC packet larger than one carrier message.

**Cell header: 18 bytes**

```text
Offset  Size  Field
0       2     magic             = 0x41 0x43 ("AC")
2       1     version           = 0x01
3       1     flags             = 0x00 in ARC/1
4       8     cell_packet_id    = cryptographically random u64
12      2     total_len         = total ARC packet bytes (max 16384)
14      2     offset            = byte offset into ARC packet
16      2     chunk_len         = number of following chunk bytes
18      N     chunk             = exactly chunk_len bytes
```

- For ordinary cells: `total_len >= 40`, `offset+chunk_len <= total_len`, `chunk_len > 0`.
- There is no unauthenticated empty-cell poll in ARC/1. On request/response carriers, a client polls by sending a normal authenticated ARC `DATA` packet containing a `PING` frame (carried in one or more ordinary cells); the responding endpoint uses that authenticated session identity to select pending downlink data.
- Sender divides an ARC packet into contiguous, non-overlapping cells, using the same random `cell_packet_id` for every cell of that ARC packet. All cells of one ARC packet SHOULD use the same physical path. A newly sent, freshly encrypted ARC packet receives a new cell packet ID.
- Receiver reconstructs the ARC packet using `(transport peer/association, cell_packet_id)` and delivers it to the ARC authentication layer only once complete. Unauthenticated cell headers MUST NEVER be trusted as proof of session, path, or identity.
- Cell reassembly caps: max 128 incomplete cell packets per transport peer, max 1 MiB per transport peer, expiry after 5 seconds. Before authentication or on unvalidated paths, use stricter per-origin caps and rate limiting.
- Only the ARC packet is cryptographically authenticated. Cell headers and DNS/ICMP wrappers are **not authenticated until reassembly and successful ARC DATA verification**, so allocation and state limits are mandatory.

**Why two fragmentation layers?** `IP_FRAGMENT` allows authenticated fragments of a single original IP datagram to travel on different paths; the cell layer breaks one already-encrypted ARC packet into smaller pieces appropriate for one carrier. Keeping both avoids forcing a DNS adapter to understand IP or session reassembly.

### 12.1 Stream carrier framing

On a reliable byte-stream carrier (e.g., TLS/TCP or a QUIC stream), transmit `cell_length:u16` (big-endian, includes all 18 cell-header bytes) followed by exactly one cell. Values smaller than 18 or larger than negotiated maximum are invalid. A stream read can return a partial frame; the adapter MUST buffer until an entire length-prefixed cell exists. Enforce per-connection memory bounds.

On UDP or QUIC DATAGRAM carriers, one datagram contains exactly one cell. Adapter MTUs include the 18-byte cell header plus outer transport overhead.

## 13. Cryptographic key epochs and replay protection

- `epoch=0` begins after Noise `Split()`.
- Each direction uses the appropriate Noise-derived 32-byte traffic key. Packet numbers start at zero and advance globally across all paths.
- Before encrypting either 2^20 packets or 30 minutes of traffic under one directional key (whichever occurs first), the sender advances to a new epoch, resets its outgoing packet counter to zero, and derives the next key:

```text
prk      = HKDF-Extract(salt = 32 zero bytes, IKM = old_traffic_key)
new_key  = HKDF-Expand(prk,
                       info = UTF8("ARC/1 traffic update") || u32_be(new_epoch),
                       L = 32)
```

- A receiver MAY derive exactly one next-epoch receive key when seeing a packet bearing `current_epoch+1`; it commits to the new epoch **only if AEAD authentication succeeds**. This supports migration and out-of-order packets without requiring a key-update control packet.
- Retain at most the current and previous receive-epoch keys, with a bounded previous-key overlap of 120 seconds after new-epoch acceptance. Erase retired secrets promptly.
- No peer may accept epochs more than one ahead. A receiver MUST maintain a sliding anti-replay window of at least 8,192 packet numbers per receive epoch, shared across all paths. Duplicates MUST be rejected before frame processing.
- A restarted process MUST establish a **new** session with new ephemeral keys and Session ID rather than restoring a prior packet-number counter under old keys.
- Large delay variance on DNS paths may create late packets outside the replay window; they may be discarded, which is intentional for a bounded datagram protocol.

> **Security review gate:** An independent cryptographic review is required before deployment beyond controlled pilots. The Noise handshake is standard; the datagram packetization, replay window, and traffic-key epoch schedule are ARC-specific composition choices. They must be covered by test vectors, audits, and fuzzing.

## 14. Paths, joining, migration, and failure

### 14.1 Path state machine

```text
DISCOVERED -> PROBING -> VALIDATED -> ACTIVE -> SUSPECT -> DRAINING -> DEAD
                    \-> FAILED                 \-----> DEAD
```

- `DISCOVERED`: system detects a candidate interface/adapter combination.
- `PROBING`: establish carrier connectivity and exchange authenticated path validation messages.
- `VALIDATED`: both sides prove ability to communicate bidirectionally on this carrier.
- `ACTIVE`: eligible for scheduler use.
- `SUSPECT`: elevated loss, timeout, or degraded reachability; send probes, generally reduce new data.
- `DRAINING`: stop new data and allow pending delivery to finish, subject to a deadline.
- `DEAD`: remove per-path state; session may continue via other paths.

### 14.2 Bootstrap path

`path_id=0` carries the Noise handshake. The client regards path 0 as authenticated when it has validated the Noise relay static key and received a valid `AUTH_RESULT`. The relay may use path 0 after receiving valid encrypted `AUTH` and enforcing anti-amplification rules. NAT rebinding or a carrier swap for path 0 MUST be handled as a candidate new path, not silently assumed equivalent.

### 14.3 Adding a new path

1. Client opens a new adapter and allocates fresh `path_id > 0`.
2. It sends encrypted `PATH_JOIN(path_id, client_nonce, mtu)` via that adapter, using that `path_id` in the ARC packet header.
3. Relay checks the session, authorizes requested transport, associates the candidate physical address/adapter with the path ID, and sends encrypted `PATH_RESPONSE(client_nonce)` plus `PATH_CHALLENGE(server_nonce)` on the same candidate carrier.
4. Client verifies `PATH_RESPONSE` and sends encrypted `PATH_RESPONSE(server_nonce)`.
5. Relay verifies the returned challenge and sends `PATH_ACCEPT(path_id, success, mtu)`; both endpoints can now consider the path eligible. The client SHOULD wait for `PATH_ACCEPT` before sending ordinary IP data over it.
6. Keepalive and path measurement begin independently per path.

The server MUST enforce anti-amplification limits for an unvalidated datagram source, e.g. total bytes sent no more than three times bytes received until address validation succeeds. For DNS and ICMP request/response carriers, use separate per-client and per-zone query budgets.

`PATH_JOIN` retransmissions use new ARC packet numbers but the **same** `(path_id, client_nonce)`, allowing idempotent handling. A path ID that appears with a different authenticated client nonce is a protocol error.

### 14.4 Path death and recovery

- Heartbeats: default idle keepalive every 10 seconds on actively used paths; adjustable according to NAT lifetime, battery, and underlying transport behavior. On request/response-only carriers, authenticated `PING` polls may serve as keepalives. The relay MAY sample PONG responses rather than generating a PONG for every poll, so low-rate channels do not become congested with heartbeat traffic.
- SUSPECT after 3 unanswered probes or measurable transport failure; DEAD after an additional configurable timeout.
- Session remains ACTIVE if any validated path remains usable. New data is reassigned automatically; no application reconnect or new VPN IP required.
- Never infer path success from local socket writability alone. Require remote response and/or authenticated delivered acknowledgements.

## 15. Scheduler and congestion control

### 15.1 Required per-path observations

`transport`, `interface`, `state`, `cell_mtu`, `srtt`, `rttvar`, `loss_ewma`, `delivery_rate`, `send_queue`, `in_flight`, `energy_cost_estimate`, `monetary_cost`, and `last_validated`.

Do not mistake carrier **capacity** for achievable application goodput. Queueing delay, reordering, CPU cost, cellular metering, and duplication overhead matter.

### 15.2 Baseline scheduling algorithm

**v1 MUST support:**

1. A per-physical-link token bucket or pacing budget. UDP/QUIC may use established congestion-control primitives; the overlay scheduler MUST NOT transmit faster than the selected carrier's congestion controller or configured limits allow.
2. Five-tuple hash / flow affinity for IP traffic; keep a flow on a preferred path for a bounded hysteresis interval to limit reordering.
3. Weighted path selection across independent flows based on measured delivery rate, RTT, loss, queueing, and user policy.
4. Immediate control-plane preference for low-latency validated paths; use redundant control probes when path health is uncertain.
5. Path failure migration without terminating the outer session.
6. A policy that avoids loading extremely slow paths (DNS/ICMP) with bulk traffic when faster paths are available.

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
    Capabilities() Capabilities // datagram/stream, request-response, cell MTU
    Open(ctx context.Context, endpoint Endpoint, underlay Underlay) error
    SendCell(ctx context.Context, cell []byte) error
    RecvCell(ctx context.Context) ([]byte, error)
    Stats() CarrierStats
    Close() error
}

type Capabilities struct {
    Bidirectional bool
    RequestResponseOnly bool
    MinCellMTU int
    MaxCellMTU int
    SupportsUnsolicitedDownlink bool
    HasNativeCongestionControl bool
}
```

`SendCell` MUST return either an explicit error or successful local enqueue; success does not imply remote receipt. The adapter MUST maintain bounded transmit and receive queues, expose backpressure, and avoid blocking the session event loop indefinitely. `Underlay` MUST identify an appropriate OS network interface or bound socket when the platform supports it. The adapter MUST keep its sockets outside the TUN routing loop.

### 16.1 UDP adapter (required)

- Send one cell per UDP datagram to the configured relay IP/port.
- Respect discovered/preset datagram MTU; initial conservative target: ~1200 bytes of total UDP payload, subsequently probed.
- Bind sockets to Wi-Fi and cellular separately when the OS permits and report failures independently.
- Carry ARC Noise, control, and data in the same envelope. Validate source association for a joined path.
- Implement pacing/congestion control at the path level; raw UDP without pacing is unacceptable for production.

### 16.2 QUIC adapter (optional but recommended)

- Use an ordinary TLS-authenticated QUIC connection to carry ARC cells in RFC 9221 DATAGRAM frames where available; a dedicated stream handles control or compatibility fallback.
- Outer QUIC security **does not** replace ARC session security because another path may use a completely different carrier.
- As multipath QUIC evolves, prefer its existing path management where it solves the same problem; do not reimplement it gratuitously. The runtime still needs heterogeneous non-QUIC adapters.
- Avoid redundant retransmission semantics on the same packet.

### 16.3 TLS/TCP adapter (required)

- Dial a configured relay endpoint with normal TLS 1.3 server identity verification and ALPN (provisionally `arc/1`).
- Carry length-prefixed cells over the resulting TLS byte stream.
- Expose delivery metrics conservatively: remote ACKs distinguish true overlay arrival from local stream-buffer success.
- Treat long-lived head-of-line delay as a scheduling cost, particularly for UDP application traffic encapsulated over TCP.

### 16.4 HTTPS / enterprise proxy adapter (optional)

- Support standards-based HTTP CONNECT where explicitly permitted and available. Consider RFC 9298 CONNECT-UDP or RFC 9484 CONNECT-IP for compatible proxy infrastructure.
- Do not assume arbitrary HTTP endpoints are relays. Authenticate both proxy access and ARC relay identity.
- Frame cells across the approved stream or datagram mechanism. HTTP proxy support is a compatibility layer, not a pretext to ignore network policies.

### 16.5 DNS request/response adapter (experimental, feature-gated)

**Model:** Client issues queries for a subdomain delegated to the operator's authoritative DNS service. That authoritative endpoint can receive upstream encoded cells and supply downstream encoded cells as DNS answers, when permitted by the resolver and network.

- Requires an operator-controlled DNS zone, explicit authorization to use the network's DNS facility in this way, and a reachable authoritative service.
- Query type for the experiment: `TXT` under a configurable dedicated zone.
- Each question name is constructed as `<nonce>.<b32-label-1>.[<b32-label-2>...]._arc.<zone>`, where `<nonce>` is 13 lowercase no-padding base32 characters encoding 8 random bytes, and the remaining labels are a lowercase no-padding base32 encoding of the entire cell divided into labels of **at most 50 ASCII characters**. The example configured zone `example.net` therefore yields names ending in `._arc.example.net`. The entire DNS name MUST remain within DNS length limits; `SendCell` MUST reject cells too large for the current zone suffix and label budget.
- Authoritative responses MUST contain exactly one TXT RR in the successful response, with TXT character-strings concatenated in wire order. Its ASCII content is exactly `A1:` followed by the unpadded base64url encoding of one downlink cell, or exactly `A1:-` when no downlink cell is queued. An unavailable path or unauthenticated request should produce an appropriate DNS error/empty reply, not content for another session. The client MUST reject malformed or ambiguous answers and must not assume TXT data from intermediaries remains unchanged.
- Each request MUST have a unique name even when repeating a poll, so caching does not cause accidental stale responses. The authoritative response SHOULD use TTL=0 but **MUST NOT** assume recursive resolvers honor this precisely.
- DNS is inherently request/response here. If no upstream application data is pending, send a **newly encrypted DATA/PING packet**, carried through ordinary cells, at an adaptive, conservatively rate-limited interval to collect queued downlink cells. The authenticated packet MUST fit the channel by cell fragmentation; if no suitable one-cell PING fits the DNS name budget, treat this transport as ineffective. Never use unauthenticated empty polls; the encrypted PING identifies and authenticates the requesting session.
- Maintain strict per-client, per-resolver, and per-zone query budgets. Do not hammer public recursive resolvers, attempt to hide abnormal use, or assume that resolvers and captive portals will allow this behavior.
- Handle resolver rewriting, negative caching, TXT response truncation, transport changes, DNSSEC incompatibilities, and intermittent packet loss by declaring the path unusable rather than sending indefinitely.
- Expect poor efficiency: base32 expands bytes ~1.6×, DNS labels restrict query payload, each ARC packet may need many cells, and downstream progress may require client polling. The DNS path SHOULD normally be control-only when a better path exists.

**Protocol mapping note:** The above defines a workable *experimental adapter*, not a guarantee that a DNS query will reach the authoritative relay. A production adapter needs interoperable explicit answer grammars, truncation behavior, and golden fixtures before its experimental flag is removed.

### 16.6 ICMP Echo adapter (experimental, feature-gated)

- On platforms permitting appropriately privileged ICMP Echo operations, carry one cell in an Echo Request's data field to a **relay host under the operator's control**; a cooperating Echo responder returns the next downlink cell inside an Echo Reply.
- Support IPv4 ICMP Echo (RFC 792) and, only when implemented/tested, IPv6 Echo (RFC 4443).
- The implementation MUST distinguish an ordinary kernel-generated echo reply (which simply echoes the request payload) from an ARC-aware reply. ARC reassembly plus authenticated session headers provide the definitive test; a naive ping response is **not** proof of a usable ARC path.
- The relay may require raw-socket/ICMP privileges and OS firewall configuration to implement custom payload replies. Client OS VPN APIs may not expose needed ICMP privileges. Detect unsupported platforms and disable this adapter cleanly.
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
- Account separately for virtual IP MTU, ARC packet overhead, 18-byte carrier cell overhead, and actual path MTU.
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
    interoperability-vectors.json
  cmd/
    arc-client/                # Linux CLI and TUN daemon
    arc-relay/                 # Session terminator + egress
    arc-lab/                   # Impairment scenarios / replay harness
  internal/
    wire/                      # Header, TLV, cell parser + encoders
    crypto/                    # Noise handshake, explicit nonce AEAD, epochs
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
    network-namespace/
    performance/
  deploy/
    dev-relay/
    production-hardening/
```

### Recommended concurrency model

One actor/event loop owns each session's immutable identity and mutable state (keys, replay windows, datagram IDs, paths). Adapter I/O goroutines push bounded events to this actor. Packet encode/encrypt may run in parallel **only** after centrally atomically assigning `(epoch, packet_number)` pairs. Incoming decrypt may run in parallel but replay admission and key-epoch transitions must be race-safe.

Never let one blocked DNS/ICMP carrier stall the session actor. Use backpressure and per-path bounded queues.

## 20. Build stages with acceptance gates

### Stage A — Wire, crypto, single path

**Implement:** Header/cell encoding and validation; Noise XX handshake; pinned relay key; AUTH/RESULT; replay window; epoch derivation; UDP carrier; Linux TUN; one Linux relay with controlled IPv4 egress; TUN loop avoidance.

**Exit criteria:** Two independent processes can exchange IP traffic through a relay; key pin failures are fatal; forged/replayed DATA packets never reach TUN; restart requires new Session ID; malformed input passes fuzzing without panic or unbounded allocation.

### Stage B — Two paths and state continuity

**Implement:** Separate underlays, path state machine, PATH_JOIN/challenge/accept, telemetry, flow-pinned weighted scheduler, failover, per-path queues, congestion/pacing hooks, metrics dashboard.

**Exit criteria:** Concurrent traffic over two independently rate-limited links improves aggregate multi-flow goodput over the faster link alone in an appropriate test; unplugging one link leaves VPN-assigned IP and session intact; prevalidated remaining path resumes forwarding without a full handshake.

### Stage C — TCP and HTTP compatibility

**Implement:** TLS/TCP cell stream adapter; stream backpressure; authenticated TLS server validation; controlled HTTP CONNECT compatibility experiment.

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
| Churn | Wi-Fi disappears while cellular remains | Same Session ID and VPN IP; no new app-facing network configuration |
| NAT rebinding | Source UDP address changes | New path validation before data forwarding |
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

A **companion JSON file** (`ARC-v1-Wire-Fixtures.json`) and its Python generator (`generate_arc_fixtures.py`) provide deterministic envelope, cell, frame, and standalone AEAD examples. These are codec fixtures, not substitute Noise XX handshakes.

Before declaring ARC/1 on-wire formats frozen, add deterministic fixtures for:

1. Exact 40-byte ARC header encoding for known field values.
2. Exact 18-byte cell header and byte-for-byte fragment reassembly.
3. Every TLV type, including lengths, `IP_FRAGMENT` offset/length validation, and unknown extension behavior.
4. Noise XX handshake using a vetted framework's published deterministic test vectors, including server-key mismatch rejection.
5. Explicit ChaCha20-Poly1305 encryption/decryption with fixed traffic keys, epoch 0, packet 0, authenticated header, and tag-failure mutation cases.
6. HKDF key-update vectors and out-of-order epoch acceptance/rejection.
7. Cross-language client↔relay interop, including changes from UDP to TLS/TCP mid-session.
8. DNS encoding of a known cell and parsing of multi-string TXT response, including case normalization and negative caching fixtures.
9. ICMP request/response framing on a controlled test host and proof that ordinary echo replies are not accepted as ARC reply data.

**Do not invent cryptographic expected outputs by hand.** Generate them with a vetted implementation, check with at least one independent implementation, and commit them as checked-in fixtures.

## 24. Open questions and deferred design decisions

**O1 — One relay versus multi-relay:** v1 binds a session to one logical relay. Geographic relay selection and mid-session relay migration require authentication, NAT state continuity, and likely a network of coordinated relays; defer.

**O2 — Are two overlay fragmentation layers worth the overhead?** They simplify heterogeneous carriers but add header bytes and reassembly complexity. Profile on fast links; consider a negotiated direct-cell fast path in v2.

**O3 — Flow-aware vs packet striping:** v1 uses flow affinity. Controlled single-flow striping with reordering buffers and limited duplication should be a benchmarked extension.

**O4 — Loss estimation:** Overlay ACK measurements must distinguish latency and receiver delivery from kernel/QUIC/TCP buffer acceptance; need a carefully sampled measurement design.

**O5 — DNS adapter viability:** Which resolvers pass queries, honor suffix/QTYPE, and permit bidirectional data with acceptable performance? It may be useful only for control-plane survival.

**O6 — ICMP availability:** Which target OS versions permit custom ICMP payload send/receive from a VPN extension without elevated privileges? Disable where unsupported.

**O7 — Authentication and gateway trust:** Finalize short-lived credential issuance, per-device revocation, relay identity rotation, tenant boundaries, and operator privacy policy before open beta.

**O8 — Remote rendering:** A future opt-in SDK can reduce transferred information by changing the *representation of a task*, not just compressing bytes. That requires its own security, privacy, and application-consistency specification.

**O9 — Resource policy:** Battery, metered-cellular caps, cost, and operator traffic restrictions must be configurable. A throughput-only objective will be wrong in many situations.

**O10 — Licensing/IP strategy:** Investigate existing multipath VPN implementations, MASQUE, transport libraries, and cryptographic implementations before claiming novelty or distributing adapted code.

## 25. Immediate engineering backlog

Ordered, each item independently demonstrable:

- [ ] Define `wire` parser/serializer with zero-copy bounded parsing and negative corpus.
- [ ] Define `cell` parser/reassembly with per-peer quota and timeout.
- [ ] Integrate vetted Noise XX and pin relay static identity.
- [ ] Implement ARC DATA AEAD, global packet-number allocator, epoch rollover, and anti-replay window.
- [ ] Implement AUTH/RESULT and session state actor.
- [ ] Implement IP_FRAGMENT split/reassembly and dedup.
- [ ] Build Linux UDP client/relay with a TUN device and a single leased IPv4 address.
- [ ] Implement relay IPv4 policy, egress SNAT, DNS-forwarding config, and anti-spoof checks.
- [ ] Add path join/challenge/accept and multi-interface UDP sockets.
- [ ] Add active telemetry and flow-affinity weighted scheduling.
- [ ] Build network namespace + `tc netem` benchmark harness and result exporter.
- [ ] Add TLS/TCP adapter and mid-session transport migration test.
- [ ] Add feature-gated DNS test-zone adapter; prove behavior under resolver constraints.
- [ ] Add feature-gated ICMP adapter only for supported, authorized platforms.
- [ ] Implement production auth/operations; security review; long soak; mobile platform integration.

## 26. Standards and technical references

Normative or useful reference materials, verified as relevant as of document date:

- **RFC 2119 / RFC 8174:** Requirement keywords — https://www.rfc-editor.org/rfc/rfc2119 and https://www.rfc-editor.org/rfc/rfc8174
- **Noise Protocol Framework:** Standard handshake patterns and `Noise_XX_25519_ChaChaPoly_SHA256` — https://noiseprotocol.org/noise.html
- **RFC 8439:** ChaCha20-Poly1305 — https://www.rfc-editor.org/rfc/rfc8439
- **RFC 5869:** HKDF — https://www.rfc-editor.org/rfc/rfc5869
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

**First concrete milestone:** Two Linux machines exchange IP traffic through an ARC relay over one UDP path using the defined authenticated packet, cell, and frame formats. **Second:** simultaneously use two independent paths without changing Session ID or virtual IP address. **Third:** make the exact same core session engine run over TLS/TCP, followed by DNS and ICMP in an authorized laboratory.

**Document maturity warning:** This specification is sufficiently concrete to start a reference implementation and generate interoperability fixtures. It is *not* a completed or security-audited Internet standard. Freeze wire bytes only after independent interop tests and cryptographic review.
