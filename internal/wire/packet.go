package wire

import (
	"encoding/binary"
	"fmt"
)

// PacketType is the first byte of every ARC packet (§7).
type PacketType uint8

const (
	TypeHandshakeInit  PacketType = 0x01
	TypeHandshakeResp  PacketType = 0x02
	TypeCookieReply    PacketType = 0x03
	TypeData           PacketType = 0x04
	TypeStatelessReset PacketType = 0x05
	TypeCell           PacketType = 0x10
)

func (t PacketType) String() string {
	switch t {
	case TypeHandshakeInit:
		return "HANDSHAKE_INIT"
	case TypeHandshakeResp:
		return "HANDSHAKE_RESP"
	case TypeCookieReply:
		return "COOKIE_REPLY"
	case TypeData:
		return "DATA"
	case TypeStatelessReset:
		return "STATELESS_RESET"
	case TypeCell:
		return "CELL"
	}
	return fmt.Sprintf("PacketType(%#02x)", uint8(t))
}

// PeekType returns the type of the packet in b and checks that its length is
// valid for that type. It does not validate the packet's contents.
func PeekType(b []byte) (PacketType, error) {
	if len(b) == 0 {
		return 0, errEmpty
	}
	if len(b) > MaxPacketSize {
		return 0, errPacketLen
	}
	t := PacketType(b[0])
	var ok bool
	switch t {
	case TypeHandshakeInit:
		ok = len(b) == HandshakeInitLen
	case TypeHandshakeResp:
		ok = len(b) == HandshakeRespLen
	case TypeCookieReply:
		ok = len(b) == CookieReplyLen
	case TypeStatelessReset:
		ok = len(b) == StatelessResetLen
	case TypeData:
		ok = len(b) >= MinDataLen
	case TypeCell:
		ok = len(b) > CellHeaderLen
	default:
		return 0, errUnknownPacket
	}
	if !ok {
		return 0, errPacketLen
	}
	return t, nil
}

func expectType(b []byte, want PacketType) error {
	t, err := PeekType(b)
	if err != nil {
		return err
	}
	if t != want {
		return errPacketType
	}
	return nil
}

// HandshakeInit is the client's first handshake packet (§8.1).
type HandshakeInit struct {
	Version   uint8
	SenderCID CID
	Cookie    [CookieLen]byte
	NoiseMsg1 [NoiseMsg1Len]byte
}

func ParseHandshakeInit(b []byte) (HandshakeInit, error) {
	var p HandshakeInit
	if err := expectType(b, TypeHandshakeInit); err != nil {
		return p, err
	}
	if b[1] != Version1 {
		return p, errUnknownVersion
	}
	p.Version = b[1]
	copy(p.SenderCID[:], b[2:10])
	copy(p.Cookie[:], b[10:26])
	copy(p.NoiseMsg1[:], b[26:])
	return p, nil
}

func (p *HandshakeInit) Append(b []byte) []byte {
	b = append(b, byte(TypeHandshakeInit), p.Version)
	b = append(b, p.SenderCID[:]...)
	b = append(b, p.Cookie[:]...)
	return append(b, p.NoiseMsg1[:]...)
}

// Prologue returns the Noise prologue for this handshake (§9.1).
func (p *HandshakeInit) Prologue() []byte {
	b := append([]byte("ARC/1"), p.Version)
	return append(b, p.SenderCID[:]...)
}

// HandshakeResp is the relay's handshake response (§8.2).
type HandshakeResp struct {
	DestCID   CID
	NoiseMsg2 [NoiseMsg2Len]byte
}

func ParseHandshakeResp(b []byte) (HandshakeResp, error) {
	var p HandshakeResp
	if err := expectType(b, TypeHandshakeResp); err != nil {
		return p, err
	}
	copy(p.DestCID[:], b[1:9])
	copy(p.NoiseMsg2[:], b[9:])
	return p, nil
}

func (p *HandshakeResp) Append(b []byte) []byte {
	b = append(b, byte(TypeHandshakeResp))
	b = append(b, p.DestCID[:]...)
	return append(b, p.NoiseMsg2[:]...)
}

// CookieReply asks the client to retry its handshake with a cookie (§8.3).
type CookieReply struct {
	DestCID CID
	Cookie  [CookieLen]byte
}

func ParseCookieReply(b []byte) (CookieReply, error) {
	var p CookieReply
	if err := expectType(b, TypeCookieReply); err != nil {
		return p, err
	}
	copy(p.DestCID[:], b[1:9])
	copy(p.Cookie[:], b[9:])
	return p, nil
}

func (p *CookieReply) Append(b []byte) []byte {
	b = append(b, byte(TypeCookieReply))
	b = append(b, p.DestCID[:]...)
	return append(b, p.Cookie[:]...)
}

// StatelessReset tells the client its session no longer exists (§8.5).
type StatelessReset struct {
	CID   CID
	Token Token
}

func ParseStatelessReset(b []byte) (StatelessReset, error) {
	var p StatelessReset
	if err := expectType(b, TypeStatelessReset); err != nil {
		return p, err
	}
	copy(p.CID[:], b[1:9])
	copy(p.Token[:], b[9:])
	return p, nil
}

func (p *StatelessReset) Append(b []byte) []byte {
	b = append(b, byte(TypeStatelessReset))
	b = append(b, p.CID[:]...)
	return append(b, p.Token[:]...)
}

// DataHeader is the cleartext header of a DATA packet (§8.4). The 18
// encoded header bytes are the AEAD associated data.
type DataHeader struct {
	EpochLow     uint8
	DestCID      CID
	PacketNumber uint64
}

// ParseData splits a DATA packet into its header, the raw header bytes (the
// AEAD associated data), and the ciphertext including the tag. Both slices
// alias b.
func ParseData(b []byte) (h DataHeader, aad, ciphertext []byte, err error) {
	if err = expectType(b, TypeData); err != nil {
		return h, nil, nil, err
	}
	h.EpochLow = b[1]
	copy(h.DestCID[:], b[2:10])
	h.PacketNumber = binary.BigEndian.Uint64(b[10:18])
	if h.PacketNumber > MaxPacketNumber {
		return DataHeader{}, nil, nil, errPacketNumber
	}
	return h, b[:DataHeaderLen], b[DataHeaderLen:], nil
}

func (h *DataHeader) Append(b []byte) []byte {
	b = append(b, byte(TypeData), h.EpochLow)
	b = append(b, h.DestCID[:]...)
	return binary.BigEndian.AppendUint64(b, h.PacketNumber)
}
