"""Generate small deterministic ARC/1 codec fixtures from the handoff draft.
The AEAD example checks packet framing, not the complete Noise handshake.
"""
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

OUT = Path(__file__).resolve().with_name('ARC-v1-Wire-Fixtures.json')
SID = bytes(range(16))

def header(kind, epoch, path_id, packet_no, payload_length):
    result = struct.pack('!2sBBBB16sIIQH', b'AR', 1, kind, 0, 0, SID, epoch, path_id, packet_no, payload_length)
    assert len(result) == 40
    return result

def cell(cell_id, complete, offset, n):
    h = struct.pack('!2sBBQHHH', b'AC', 1, 0, cell_id, len(complete), offset, n)
    assert len(h) == 18
    return h + complete[offset:offset+n]

raw_hs = header(1, 0, 0, 0, 3) + bytes.fromhex('aabbcc')
cid = 0x0102030405060708
c1 = cell(cid, raw_hs, 0, 20)
c2 = cell(cid, raw_hs, 20, len(raw_hs)-20)
assert c1[18:] + c2[18:] == raw_hs
ping = bytes.fromhex('0800081122334455667788')
assert len(ping) == 11
key = bytes(range(32))
pn = 5
nonce = b'\x00' * 4 + struct.pack('<Q', pn)
h = header(2, 0, 7, pn, len(ping)+16)
ct = ChaCha20Poly1305(key).encrypt(nonce, ping, h)
assert ChaCha20Poly1305(key).decrypt(nonce, ct, h) == ping
mutated = bytearray(h)
mutated[26] ^= 1  # path ID is AEAD-authenticated
try:
    ChaCha20Poly1305(key).decrypt(nonce, ct, bytes(mutated))
    raise AssertionError('altered path unexpectedly authenticated')
except Exception as exc:
    assert exc.__class__.__name__ == 'InvalidTag'
# RFC5869 HKDF-Extract zero salt and RFC5869 HKDF-Expand with app label.
prk = hmac.HMAC(b'\x00'*32, hashes.SHA256())
prk.update(key)
prk = prk.finalize()
info = b'ARC/1 traffic update' + struct.pack('!I', 1)
newkey = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(prk)

j = {
 'fixture_version': 1,
 'spec': 'draft-arc-transport-00 / ARC/1',
 'warning': 'The sample HANDSHAKE envelope contains dummy Noise bytes; it is not a valid Noise handshake. The AEAD key is a standalone deterministic example, not a Noise-derived traffic key.',
 'format_notes': 'All hex strings use lowercase; all multibyte header fields use network byte order, except AEAD nonce packet number uses uint64_le.',
 'envelope': {
   'session_id_hex': SID.hex(), 'kind': 1, 'packet_number': 0,
   'dummy_handshake_payload_hex': 'aabbcc',
   'header_hex': raw_hs[:40].hex(), 'packet_hex': raw_hs.hex(),
 },
 'cell_fragmentation': {
   'cell_packet_id_hex': '0102030405060708', 'source_packet_hex': raw_hs.hex(),
   'first_cell_hex': c1.hex(), 'second_cell_hex': c2.hex(),
   'reassembled_packet_hex': (c1[18:]+c2[18:]).hex(),
 },
 'ping_frame': {
   'type_hex': '08', 'value_nonce_hex': '1122334455667788',
   'frame_hex': ping.hex(),
 },
 'data_aead': {
   'cipher': 'ChaCha20-Poly1305',
   'key_hex': key.hex(), 'nonce_hex': nonce.hex(),
   'epoch': 0, 'path_id': 7, 'packet_number': 5,
   'aad_header_hex': h.hex(), 'plaintext_frames_hex': ping.hex(),
   'ciphertext_and_tag_hex': ct.hex(), 'packet_hex': (h+ct).hex(),
   'negative_test': 'flip any authenticated header byte (e.g., path_id offset 26) and decryption MUST fail',
 },
 'key_update': {
   'old_key_hex': key.hex(), 'epoch_to': 1, 'salt_hex': ('00'*32),
   'info_hex': info.hex(), 'hkdf_extract_prk_hex': prk.hex(),
   'next_key_hex': newkey.hex(),
 },
}
OUT.write_text(json.dumps(j, indent=2) + '\n')
print(str(OUT), OUT.stat().st_size, 'bytes')
print('Header',len(h),'cell headers',len(c1)-20,len(c2)-(len(raw_hs)-20),'AEAD ciphertext',len(ct))
