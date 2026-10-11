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
| `0x0E`–`0x7F` | reserved, required | — | reject the packet |
| `0x80`–`0xFF` | extensions, ignorable | — | ignore |

## Error / close codes (§10.1)

`0 NO_ERROR` · `1 MALFORMED` · `2 AUTH_FAILED` · `3 UNAUTHORIZED` · `4 PATH_UNAVAILABLE` · `5 CAPACITY` · `6 UNSUPPORTED` · `7 SESSION_EXPIRED` · `8 PROTOCOL_VIOLATION`

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
| Cell reassembly (bound association) | 64 packets / 256 KiB / 10 s | 12.1 |
| Cell reassembly (unbound association) | 4 packets / 16 KiB | 12.1 |
| DNS downlink cell | ≤ 280 B | 16.5 |
