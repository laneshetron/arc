"""Generate deterministic ARC/1 v0.2 wire fixtures.

Every expected cryptographic output below comes from the `cryptography`
package (ChaCha20-Poly1305, HMAC-SHA256); nothing is written by hand.
Handshake packets carry dummy Noise bytes: they test packet framing only,
not Noise IK. Run with --check to verify the committed JSON is current.
"""
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

OUT = Path(__file__).resolve().with_name("ARC-v1-Wire-Fixtures.json")

# Packet types (spec section 7).
HANDSHAKE_INIT, HANDSHAKE_RESP, COOKIE_REPLY, DATA, STATELESS_RESET, CELL = 1, 2, 3, 4, 5, 0x10

# Frame types (spec section 10.1).
F = dict(PADDING=0x00, AUTH=0x01, AUTH_RESULT=0x02, IP_PACKET=0x03, IP_FRAGMENT=0x04,
         NEW_PATH=0x05, PATH_JOIN=0x06, PATH_CHALLENGE=0x07, PATH_RESPONSE=0x08,
         PATH_ABANDON=0x09, PING=0x0A, ACK=0x0B, CLOSE=0x0C, ERROR=0x0D)

CLIENT_CID = bytes.fromhex("c1c2c3c4c5c6c7c8")
RELAY_CID = bytes.fromhex("a1a2a3a4a5a6a7a8")


def handshake_init(sender_cid, cookie, noise_msg1):
    assert len(cookie) == 16 and len(noise_msg1) == 96
    return bytes([HANDSHAKE_INIT, 1]) + sender_cid + cookie + noise_msg1


def handshake_resp(dest_cid, noise_msg2):
    assert len(noise_msg2) == 72
    return bytes([HANDSHAKE_RESP]) + dest_cid + noise_msg2


def data_header(epoch_low, dest_cid, packet_number):
    return struct.pack("!BB8sQ", DATA, epoch_low, dest_cid, packet_number)


def frame(ftype, value):
    return struct.pack("!BH", ftype, len(value)) + value


def nonce(path_id, packet_number):
    return struct.pack("!I", path_id) + struct.pack("<Q", packet_number)


def noise_rekey(key):
    # Noise REKEY(k) = ENCRYPT(k, maxnonce, zerolen, zeros[32])[0:32].
    return ChaCha20Poly1305(key).encrypt(b"\x00" * 4 + struct.pack("<Q", 2**64 - 1), b"\x00" * 32, b"")[:32]


def cell(assoc_id, cell_packet_id, packet, offset, n):
    return struct.pack("!BB8sIHH", CELL, 0, assoc_id, cell_packet_id, len(packet), offset) + packet[offset:offset + n]


def ipv4_packet(payload):
    # Minimal IPv4/UDP-shaped packet; only version and total length matter to the codec.
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                      bytes([10, 77, 0, 2]), bytes([192, 0, 2, 1]))
    return hdr + payload


def ack_value(path_id, largest, ack_delay_us, first_range, ranges):
    v = struct.pack("!IQIIB", path_id, largest, ack_delay_us, first_range, len(ranges))
    for gap, length in ranges:
        v += struct.pack("!II", gap, length)
    return v


def ack_intervals(largest, first_range, ranges):
    out = [[largest - first_range, largest]]
    smallest = largest - first_range
    for gap, length in ranges:
        hi = smallest - gap - 2
        lo = hi - length
        assert lo >= 0
        out.append([lo, hi])
        smallest = lo
    return out


def build():
    fixtures = {
        "fixture_version": 2,
        "spec": "arc-v1-spec 0.2",
        "warning": "Handshake packets contain dummy Noise bytes and are not valid Noise IK messages. "
                   "AEAD keys are standalone deterministic examples, not Noise-derived traffic keys.",
        "format_notes": "Lowercase hex. Multibyte fields are big-endian except the packet number "
                        "inside the AEAD nonce, which is uint64 little-endian.",
    }

    # --- Packets -------------------------------------------------------------
    init = handshake_init(CLIENT_CID, b"\x00" * 16, bytes(range(96)))
    init_cookie = handshake_init(CLIENT_CID, bytes(range(0xE0, 0xF0)), bytes(range(96)))
    resp = handshake_resp(CLIENT_CID, bytes(range(0x80, 0x80 + 72)))
    cookie_reply = bytes([COOKIE_REPLY]) + CLIENT_CID + bytes(range(0xE0, 0xF0))
    reset = bytes([STATELESS_RESET]) + RELAY_CID + bytes(range(0x30, 0x40))
    assert (len(init), len(resp), len(cookie_reply), len(reset)) == (122, 81, 25, 25)
    fixtures["packets"] = {
        "handshake_init": {"sender_cid_hex": CLIENT_CID.hex(), "cookie_hex": "00" * 16,
                           "noise_msg1_hex": bytes(range(96)).hex(), "packet_hex": init.hex()},
        "handshake_init_with_cookie": {"sender_cid_hex": CLIENT_CID.hex(),
                                       "cookie_hex": bytes(range(0xE0, 0xF0)).hex(),
                                       "noise_msg1_hex": bytes(range(96)).hex(),
                                       "packet_hex": init_cookie.hex()},
        "handshake_resp": {"dest_cid_hex": CLIENT_CID.hex(),
                           "noise_msg2_hex": bytes(range(0x80, 0x80 + 72)).hex(), "packet_hex": resp.hex()},
        "cookie_reply": {"dest_cid_hex": CLIENT_CID.hex(), "cookie_hex": bytes(range(0xE0, 0xF0)).hex(),
                         "packet_hex": cookie_reply.hex()},
        "stateless_reset": {"cid_hex": RELAY_CID.hex(), "reset_token_hex": bytes(range(0x30, 0x40)).hex(),
                            "packet_hex": reset.hex()},
        "noise_prologue_hex": (b"ARC/1" + init[1:10]).hex(),
    }

    # --- Frames --------------------------------------------------------------
    ip = ipv4_packet(b"hello arc")
    auth_result = struct.pack("!BIBHIIIQ", 0, 0x0A4D0002, 16, 1280, 0x0A4D0001, 10000, 120000, 0)
    assert len(auth_result) == 28
    new_path = struct.pack("!I", 1) + bytes.fromhex("b1b2b3b4b5b6b7b8") + bytes(range(0x40, 0x50))
    ack_ranges = [(1, 3), (0, 0)]
    ack = ack_value(1, 100, 1500, 4, ack_ranges)
    frames = [
        ("PADDING", F["PADDING"], b"\x00" * 4, {"length": 4}),
        ("AUTH", F["AUTH"], b"test-credential", {"credential_hex": b"test-credential".hex()}),
        ("AUTH_RESULT", F["AUTH_RESULT"], auth_result,
         {"status": 0, "ipv4": "10.77.0.2", "prefix4": 16, "tun_mtu": 1280, "dns_ipv4": "10.77.0.1",
          "keepalive_ms": 10000, "idle_ms": 120000, "features": 0}),
        ("IP_PACKET", F["IP_PACKET"], ip, {"ip_packet_hex": ip.hex()}),
        ("IP_FRAGMENT", F["IP_FRAGMENT"], struct.pack("!QHH", 42, len(ip), 8) + ip[8:20],
         {"datagram_id": 42, "total_len": len(ip), "offset": 8, "data_hex": ip[8:20].hex()}),
        ("NEW_PATH", F["NEW_PATH"], new_path,
         {"path_id": 1, "cid_hex": "b1b2b3b4b5b6b7b8", "reset_token_hex": bytes(range(0x40, 0x50)).hex()}),
        ("PATH_JOIN", F["PATH_JOIN"], bytes.fromhex("d1d2d3d4d5d6d7d8"), {"cid_hex": "d1d2d3d4d5d6d7d8"}),
        ("PATH_CHALLENGE", F["PATH_CHALLENGE"], bytes.fromhex("1122334455667788"), {"data_hex": "1122334455667788"}),
        ("PATH_RESPONSE", F["PATH_RESPONSE"], bytes.fromhex("1122334455667788"), {"data_hex": "1122334455667788"}),
        ("PATH_ABANDON", F["PATH_ABANDON"], struct.pack("!IH", 1, 4), {"path_id": 1, "code": 4}),
        ("PING", F["PING"], b"", {}),
        ("ACK", F["ACK"], ack,
         {"path_id": 1, "largest": 100, "ack_delay_us": 1500, "first_range": 4,
          "ranges": [list(r) for r in ack_ranges],
          "intervals": ack_intervals(100, 4, ack_ranges)}),
        ("CLOSE", F["CLOSE"], struct.pack("!H", 0), {"code": 0}),
        ("ERROR", F["ERROR"], struct.pack("!H", 6), {"code": 6}),
        ("UNKNOWN_EXTENSION", 0x9F, b"\xAA\xBB", {"ignorable": True}),
    ]
    fixtures["frames"] = [
        dict(name=name, type=t, frame_hex=frame(t, v).hex(), fields=fields) for name, t, v, fields in frames
    ]
    assert fixtures["frames"][11]["fields"]["intervals"] == [[96, 100], [90, 93], [88, 88]]

    # --- DATA packet protection ---------------------------------------------
    key = bytes(range(32))
    path_id, pn = 7, 5
    plaintext = frame(F["ACK"], ack_value(7, 4, 250, 4, [])) + frame(F["PING"], b"") + frame(F["IP_PACKET"], ip)
    hdr = data_header(0, RELAY_CID, pn)
    assert len(hdr) == 18
    n = nonce(path_id, pn)
    ct = ChaCha20Poly1305(key).encrypt(n, plaintext, hdr)
    assert ChaCha20Poly1305(key).decrypt(n, ct, hdr) == plaintext
    for i in range(len(hdr)):  # every header byte is authenticated
        mutated = bytearray(hdr)
        mutated[i] ^= 1
        try:
            ChaCha20Poly1305(key).decrypt(n, ct, bytes(mutated))
            raise AssertionError("mutated header authenticated")
        except InvalidTag:
            pass
    try:  # the path ID is bound through the nonce
        ChaCha20Poly1305(key).decrypt(nonce(path_id + 1, pn), ct, hdr)
        raise AssertionError("wrong path_id authenticated")
    except InvalidTag:
        pass
    fixtures["data_aead"] = {
        "cipher": "ChaCha20-Poly1305", "key_hex": key.hex(), "path_id": path_id, "epoch_low": 0,
        "dest_cid_hex": RELAY_CID.hex(), "packet_number": pn, "nonce_hex": n.hex(),
        "header_hex": hdr.hex(), "plaintext_hex": plaintext.hex(),
        "ciphertext_and_tag_hex": ct.hex(), "packet_hex": (hdr + ct).hex(),
        "negative_tests": "Flipping any header bit, or decrypting with path_id 8, MUST fail authentication.",
    }

    # --- Noise REKEY ---------------------------------------------------------
    k1 = noise_rekey(key)
    k2 = noise_rekey(k1)
    fixtures["rekey"] = {"epoch0_key_hex": key.hex(), "epoch1_key_hex": k1.hex(), "epoch2_key_hex": k2.hex()}

    # --- Cookie and stateless reset token -----------------------------------
    cookie_secret = b"\x42" * 32
    src_ip, src_port = bytes([192, 0, 2, 1]), 4433
    cookie = hmac.new(cookie_secret, b"ARC/1 cookie" + src_ip + struct.pack("!H", src_port) + CLIENT_CID,
                      hashlib.sha256).digest()[:16]
    reset_secret = b"\x24" * 32
    token = hmac.new(reset_secret, b"ARC/1 reset" + RELAY_CID, hashlib.sha256).digest()[:16]
    fixtures["cookie"] = {"cookie_secret_hex": cookie_secret.hex(), "src_ip": "192.0.2.1", "src_port": src_port,
                          "sender_cid_hex": CLIENT_CID.hex(), "cookie_hex": cookie.hex()}
    fixtures["reset_token"] = {"reset_secret_hex": reset_secret.hex(), "cid_hex": RELAY_CID.hex(),
                               "reset_token_hex": token.hex()}

    # --- Cells ---------------------------------------------------------------
    assoc = bytes.fromhex("5a5b5c5d5e5f6061")
    c1 = cell(assoc, 9, init, 0, 64)
    c2 = cell(assoc, 9, init, 64, len(init) - 64)
    assert c1[18:] + c2[18:] == init
    fixtures["cells"] = {"assoc_id_hex": assoc.hex(), "cell_packet_id": 9, "packet_hex": init.hex(),
                         "cells_hex": [c1.hex(), c2.hex()]}

    # --- Invalid inputs (each MUST be rejected) ------------------------------
    good_data = hdr + ct
    fixtures["invalid_packets"] = [
        {"name": "empty", "hex": ""},
        {"name": "unknown type", "hex": "09" + good_data[1:].hex()},
        {"name": "init too short", "hex": init[:-1].hex()},
        {"name": "init too long", "hex": (init + b"\x00").hex()},
        {"name": "init unknown version", "hex": (init[:1] + b"\x02" + init[2:]).hex()},
        {"name": "resp wrong size", "hex": resp[:-1].hex()},
        {"name": "cookie reply wrong size", "hex": (cookie_reply + b"\x00").hex()},
        {"name": "reset wrong size", "hex": reset[:-1].hex()},
        {"name": "data below minimum", "hex": good_data[:36].hex()},
        {"name": "data above maximum", "hex": (hdr + b"\x00" * (16384 - 18 + 1)).hex()},
    ]
    fixtures["invalid_cells"] = [
        {"name": "nonzero flags", "hex": (c1[:1] + b"\x01" + c1[2:]).hex()},
        {"name": "empty chunk", "hex": c1[:18].hex()},
        {"name": "chunk past total_len", "hex": c1[:14].hex() + "0019" + "0000" + "00" * 26},
        {"name": "total_len below minimum", "hex": c1[:14].hex() + "0018" + "0000" + "00" * 4},
        {"name": "total_len above maximum", "hex": c1[:14].hex() + "4001" + "0000" + "00" * 4},
    ]
    fixtures["invalid_frames"] = [
        {"name": "truncated header", "hex": "0a00"},
        {"name": "length past end", "hex": "0a0001"},
        {"name": "unknown required type", "hex": "7f0000"},
        {"name": "nonzero padding", "hex": "00000101"},
        {"name": "empty auth", "hex": "010000"},
        {"name": "auth_result wrong size", "hex": "02001b" + "00" * 27},
        {"name": "auth_result failure with nonzero fields",
         "hex": frame(2, struct.pack("!BIBHIIIQ", 2, 1, 0, 0, 0, 0, 0, 0)).hex()},
        {"name": "auth_result success with small mtu",
         "hex": frame(2, struct.pack("!BIBHIIIQ", 0, 1, 16, 1279, 0, 0, 0, 0)).hex()},
        {"name": "auth_result nonzero features",
         "hex": frame(2, struct.pack("!BIBHIIIQ", 0, 1, 16, 1280, 0, 0, 0, 1)).hex()},
        {"name": "ip_packet length mismatch", "hex": frame(3, ip + b"\x00").hex()},
        {"name": "ip_packet bad version", "hex": frame(3, b"\x55" + ip[1:]).hex()},
        {"name": "ip_fragment empty data", "hex": frame(4, struct.pack("!QHH", 1, 100, 0)).hex()},
        {"name": "ip_fragment past total_len", "hex": frame(4, struct.pack("!QHH", 1, 30, 20) + b"\x00" * 11).hex()},
        {"name": "ip_fragment total_len too small", "hex": frame(4, struct.pack("!QHH", 1, 19, 0) + b"\x00").hex()},
        {"name": "path_join wrong size", "hex": "06000700000000000000"},
        {"name": "ping with value", "hex": "0a000100"},
        {"name": "ack length mismatch", "hex": frame(0x0B, ack_value(1, 10, 0, 0, [(0, 0)])[:-1]).hex()},
        {"name": "ack first_range underflow", "hex": frame(0x0B, ack_value(1, 3, 0, 4, [])).hex()},
        {"name": "ack range underflow", "hex": frame(0x0B, ack_value(1, 10, 0, 2, [(7, 0)])).hex()},
        {"name": "ack too many ranges", "hex": frame(0x0B, ack_value(1, 2**40, 0, 0, [(0, 0)] * 33)).hex()},
    ]
    return fixtures


def main():
    text = json.dumps(build(), indent=2) + "\n"
    if "--check" in sys.argv:
        if OUT.read_text() != text:
            sys.exit(f"{OUT.name} is stale; run {Path(__file__).name}")
        print(f"{OUT.name} is up to date")
        return
    OUT.write_text(text)
    print(OUT, len(text), "bytes")


if __name__ == "__main__":
    main()
