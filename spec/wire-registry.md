# ARC/1 wire registry (spec 0.2)

A quick reference for every on-wire code point and constant. The protocol document (`ARC-v1-Protocol-and-Implementation-Handoff.md`) is normative; section numbers below point into it. All values are provisional until the first interop test.

## Packet types (§7, §8)

| Type | Name | Size | Layout |
|---|---|---|---|
| `0x01` | `HANDSHAKE_INIT` | 122 | `type`, `version=0x01`, `sender_cid[8]`, `cookie[16]`, `noise_msg1[96]` |
| `0x02` | `HANDSHAKE_RESP` | 81 | `type`, `dest_cid[8]`, `noise_msg2[72]` (payload: `relay_cid[8]`, `reset_token[16]`) |
| `0x03` | `COOKIE_REPLY` | 25 | `type`, `dest_cid[8]`, `cookie[16]` |
| `0x04` | `DATA` | 37–16384 | `type`, `epoch_low`, `dest_cid[8]`, `packet_number:u64`, `ciphertext‖tag[16]` |
| `0x05` | `STATELESS_RESET` | 25 | `type`, `cid[8]`, `reset_token[16]` |
| `0x10` | `CELL` | 19–16384 | `type`, `flags=0`, `assoc_id[8]`, `cell_packet_id:u32`, `total_len:u16`, `offset:u16`, `chunk` |

All other type values are reserved: drop them silently.

## Frame types (§10.1)

| Type | Name | Value size | Ack-eliciting |
|---|---|---|---|
| `0x00` | `PADDING` | any (all zero bytes) | no |
| `0x01` | `AUTH` | 1–4096 | yes |
| `0x02` | `AUTH_RESULT` | 28 | yes |
| `0x03` | `IP_PACKET` | 20+ (equals the IP declared length) | yes |
| `0x04` | `IP_FRAGMENT` | 13+ | yes |
| `0x05` | `NEW_PATH` | 28 | yes |
| `0x06` | `PATH_JOIN` | 8 | yes |
| `0x07` | `PATH_CHALLENGE` | 8 | yes |
| `0x08` | `PATH_RESPONSE` | 8 | yes |
| `0x09` | `PATH_ABANDON` | 6 | yes |
| `0x0A` | `PING` | 0 | yes |
| `0x0B` | `ACK` | 21 + 8·n (n ≤ 32) | no |
| `0x0C` | `CLOSE` | 2 | no |
| `0x0D` | `ERROR` | 2 | yes |
| `0x0E` | `IP_DATAGRAM` | 28+ (`datagram_id:u64` + IP packet) | yes |
| `0x0F` | `REDUNDANCY` | 5 (`seq:u32; mode:u8`, mode 0 or 1) | yes |
| `0x10` | `FEC_REPAIR` | 9+ (`first32:u32; stride:u8; k:u8; m:u8; index:u8` + symbol) | yes |
| `0x11` | `FEC` | 5 (`seq:u32; mode:u8`, mode 0–2) | yes |
| `0x12` | `STREAM_OPEN` | 10 or 22 (`stream_id:u32; port:u16; addr[4 or 16]`) | yes |
| `0x13` | `STREAM` | 13+ (`stream_id:u32; offset:u64; flags:u8` + data; flags bit 0 `FIN`) | yes |
| `0x14` | `MAX_STREAM_DATA` | 12 (`stream_id:u32; max:u64`) | yes |
| `0x15` | `MAX_DATA` | 8 (`max:u64`) | yes |
| `0x16` | `STREAM_RESET` | 14 (`stream_id:u32; code:u16; final:u64`) | yes |
| `0x17` | `DIAGNOSTICS_OPEN` | 4 (`stream_id:u32`) | yes |
| `0x18` | `ENROLLED` | 10–41 (`device_id[8]; len:u8; name`, name 1–32 bytes) | yes |
| `0x19` | `INVITE_REQUEST` | 8 (`request_id[8]`) | yes |
| `0x1A` | `INVITE` | 37 (`request_id[8]; status:u8; invite_id[8]; secret[16]; expires:u32`) | yes |
| `0x1B` | `DEVICES_REQUEST` | 8 (`request_id[8]`) | yes |
| `0x1C` | `DEVICES` | 10 + n × (33 + len) (`request_id[8]; status:u8; n:u8;` n × `device_id[8]; parent[8]; created:u32; last_seen:u32; key[8]; u8 len; name`) | yes |
| `0x1D` | `REVOKE_REQUEST` | 17 (`request_id[8]; device_id[8]; flags:u8`) | yes |
| `0x1E` | `REVOKE_RESULT` | 9 (`request_id[8]; status:u8`) | yes |
| `0x1F`–`0x7F` | reserved, required | — | reject the packet |
| `0x80` | `SCHEDULE` | 5 (`interval_ms:u16; floor_ms:u16; window:u8`) | yes |
| `0x81`–`0xFF` | extensions, ignorable | — | ignore |

`IP_DATAGRAM` and `REDUNDANCY` are sent only when `AUTH_RESULT` advertises features bit 0 (§11.1), and `FEC_REPAIR` and `FEC` only with bit 1 (§11.2), which also allows `IP_DATAGRAM`. The stream frames (`0x12`–`0x16`) are sent only with bit 2 (§11.3), and `DIAGNOSTICS_OPEN` only with bit 3, which also allows `0x13`–`0x16` for the upload (§11.4). Stream IDs are never 0, and stream offsets and limits stay below 2^62. `ENROLLED` is sent only with a successful `AUTH_RESULT` answering an enrollment credential (§9.2), so clients that authenticate with tokens never receive it. `INVITE_REQUEST` is sent only with bit 4, and `INVITE` only in answer to it; `request_id` is never zero, and a refusing `INVITE` has every field but `request_id` and `status` zero. `DEVICES_REQUEST` and `REVOKE_REQUEST` are sent only with bit 5, and `DEVICES` and `REVOKE_RESULT` only in answer to them; their `request_id` is never zero, a refusing `DEVICES` lists no devices, `DEVICES` lists at most 16, and `REVOKE_REQUEST` names a nonzero device and sets only flags bit 0. `SCHEDULE` (`dns-lifeline.md` §4.4.2) declares a request/response carrier's polling schedule: `interval_ms` while active, `floor_ms` at the keepalive floor, and `window` the number of polls in flight; it is in the ignorable extension range so a relay predating it drops the frame rather than the packet, and a relay that never receives one assumes the conservative `window = 1` at its own floor.

## AUTH_RESULT features (§10.1)

| Bit | Name | Meaning |
|---|---|---|
| 0 | `REDUNDANCY` | relay accepts `IP_DATAGRAM` and `REDUNDANCY` (§11.1) |
| 1 | `FEC` | relay accepts `IP_DATAGRAM`, `FEC_REPAIR` and `FEC` (§11.2) |
| 2 | `STREAMS` | relay accepts `STREAM_OPEN` and carries streams to TCP destinations (§11.3) |
| 3 | `DIAGNOSTICS` | relay accepts `DIAGNOSTICS_OPEN`, keeping clients' diagnostics uploads (§11.4) |
| 4 | `INVITES` | the session's device may ask for invites to its account with `INVITE_REQUEST` (§10.1) |
| 5 | `DEVICES` | the session's device may list and revoke its account's devices with `DEVICES_REQUEST` and `REVOKE_REQUEST` (§10.1) |

Other bits are sent as zero and ignored on receipt.

## Error / close codes (§10.1)

`0 NO_ERROR` · `1 MALFORMED` · `2 AUTH_FAILED` · `3 UNAUTHORIZED` · `4 PATH_UNAVAILABLE` · `5 CAPACITY` · `6 UNSUPPORTED` · `7 SESSION_EXPIRED` · `8 PROTOCOL_VIOLATION` · `9 CONNECT_FAILED` · `10 ABORTED` · `11 INVITE_USED` · `12 INVITE_EXPIRED` · `13 REVOKED` (9 and 10 in `STREAM_RESET`; 11 and 12 refuse an enrollment, in `AUTH_RESULT.status` and `CLOSE`; 13 refuses or closes a revoked device's sessions, in `AUTH_RESULT.status` and `CLOSE`)

## Cryptography (§8.6, §9, §13, §14.7)

| Item | Value |
|---|---|
| Handshake | `Noise_IK_25519_ChaChaPoly_SHA256` |
| Prologue | `"ARC/1" ‖ version ‖ sender_cid` |
| DATA nonce | `u32_be(path_id) ‖ u64_le(packet_number)` |
| DATA AAD | the 18 header bytes |
| Rekey | Noise `REKEY` (encrypt 32 zero bytes at nonce 2^64−1, keep the first 32 bytes) |
| Cookie | `HMAC-SHA256(secret, "ARC/1 cookie" ‖ src_ip ‖ u16 src_port ‖ sender_cid)[0:16]` |
| Reset token | `HMAC-SHA256(reset_secret, "ARC/1 reset" ‖ cid)[0:16]` |

## Constants and defaults

| Name | Value | § |
|---|---|---|
| Max ARC packet | 16,384 B | 7 |
| DATA overhead per full TUN packet | 37 B | 17.4 |
| Default TUN MTU | 1280 | 17.4 |
| Initial max UDP payload | 1232 | 16.1 |
| Handshake timeout / retransmission | 10 s / 1 s doubling | 9.2 |
| Cookie secret rotation | 120 s | 9.3 |
| `REKEY_AFTER_TIME` / `REKEY_AFTER_PACKETS` | 120 s / 2^32 | 13 |
| `KEY_OVERLAP` | 60 s | 13 |
| Failed-decryption limit | 2^36 | 13 |
| Minimum replay window | 4,096 per path and direction | 13 |
| `max_ack_delay` | 25 ms | 10.2 |
| Max outstanding `NEW_PATH` slots | 8 | 14.3 |
| Anti-amplification factor | 3× | 14.4 |
| Keepalive | 10 s idle | 14.6 |
| Suspend grace | 120 s | 9.4 |
| IP reassembly | 1,024 datagrams / 8 MiB / 5 s / 8,192 completed IDs | 11 |
| Datagram dedup window (redundancy) | ≥ 65,000 IDs (reference: 65,472) | 11.1 |
| Redundancy `auto` thresholds | on at ≥ 1% loss, off below 0.4% | 11.1 |
| Cell reassembly (bound association) | 64 packets / 256 KiB / 10 s (a slow carrier bounds its packet size instead: `dns-lifeline.md` §2.4) | 12.1 |
| Cell reassembly (unbound association) | 4 packets / 16 KiB; handshake replies only (`dns-lifeline.md` §4.2.2) | 12.1 |
| DNS downlink cell | sized to the question: 168 B full-name, up to 409 B with EDNS(0) | 16.5, `dns-lifeline.md` §2.2.2 |
| DNS uplink cell | from the zone suffix: 136 B at `_arc.example.net` | 16.5 |
