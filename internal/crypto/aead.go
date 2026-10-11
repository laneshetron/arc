package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/laneshetron/arc/internal/wire"
)

// ErrAuth is returned when a DATA packet fails authentication.
var ErrAuth = errors.New("crypto: packet authentication failed")

// AEAD protects DATA packets under one directional key (§8.6).
type AEAD struct {
	c cipher.AEAD
}

func NewAEAD(key [32]byte) *AEAD {
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err) // unreachable: the key length is fixed
	}
	return &AEAD{c: c}
}

// Nonce returns u32_be(path_id) || u64_le(packet_number).
func Nonce(pathID uint32, pn uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint32(n[0:4], pathID)
	binary.LittleEndian.PutUint64(n[4:12], pn)
	return n
}

// SealData appends a complete DATA packet (header and ciphertext) to dst.
// The caller owns packet-number uniqueness; SealData panics on the
// reserved packet number.
func (a *AEAD) SealData(dst []byte, h wire.DataHeader, pathID uint32, plaintext []byte) []byte {
	if h.PacketNumber > wire.MaxPacketNumber {
		panic("crypto: reserved packet number")
	}
	start := len(dst)
	dst = h.Append(dst)
	n := Nonce(pathID, h.PacketNumber)
	return a.c.Seal(dst, n[:], plaintext, dst[start:])
}

// OpenData authenticates and decrypts a DATA packet's ciphertext, appending
// the plaintext to dst. aad is the raw 18-byte header from wire.ParseData.
func (a *AEAD) OpenData(dst []byte, h wire.DataHeader, aad []byte, pathID uint32, ciphertext []byte) ([]byte, error) {
	n := Nonce(pathID, h.PacketNumber)
	out, err := a.c.Open(dst, n[:], ciphertext, aad)
	if err != nil {
		return dst, ErrAuth
	}
	return out, nil
}

// Rekey derives the next epoch's key with Noise REKEY: the first 32 bytes
// of ENCRYPT(k, 2^64-1, empty, 32 zero bytes) (§13).
func Rekey(key [32]byte) [32]byte {
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], ^uint64(0))
	var zeros [32]byte
	out := c.Seal(nil, nonce[:], zeros[:], nil)
	var next [32]byte
	copy(next[:], out[:32])
	return next
}
