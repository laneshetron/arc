// Package wire encodes and decodes ARC/1 packets, frames, and cells
// (spec/ARC-v1-Protocol-and-Implementation-Handoff.md, §7–§12).
//
// Parsers validate every length and reserved field before returning, never
// allocate in proportion to attacker-controlled lengths, and return values
// that alias the input buffer where a field is variable-length. Encoders
// append to a caller-provided slice. The package performs no cryptography:
// a DATA packet's ciphertext is opaque here.
package wire

// CID is a connection ID: an opaque value chosen by a packet's receiver.
type CID [8]byte

// Token is a stateless reset token.
type Token [16]byte

// AssocID groups the cells of one constrained-carrier association.
type AssocID [8]byte

const (
	Version1 = 0x01

	MaxPacketSize     = 16384
	HandshakeInitLen  = 122
	HandshakeRespLen  = 81
	CookieReplyLen    = 25
	StatelessResetLen = 25
	DataHeaderLen     = 18
	AEADTagLen        = 16
	FrameHeaderLen    = 3
	MinDataLen        = DataHeaderLen + FrameHeaderLen + AEADTagLen
	NoiseMsg1Len      = 96
	NoiseMsg2Len      = 72
	CookieLen         = 16

	CellHeaderLen   = 18
	MinCellTotalLen = 25

	// MaxPacketNumber is the largest usable packet number; 2^64-1 is
	// reserved by Noise REKEY (§8.6).
	MaxPacketNumber = 1<<64 - 2
)

// parseError is a static, allocation-free error so that dropping hostile
// input stays cheap.
type parseError struct {
	msg         string
	unsupported bool
}

func (e *parseError) Error() string { return "wire: " + e.msg }

func (e *parseError) Is(target error) bool {
	if e.unsupported {
		return target == ErrUnsupported
	}
	return target == ErrMalformed
}

var (
	// ErrMalformed matches every error caused by invalid encoding.
	ErrMalformed = &parseError{msg: "malformed"}
	// ErrUnsupported matches errors caused by well-formed input that uses
	// an unknown version, packet type, or required frame type.
	ErrUnsupported = &parseError{msg: "unsupported", unsupported: true}
)

func malformed(msg string) error   { return &parseError{msg: msg} }
func unsupported(msg string) error { return &parseError{msg: msg, unsupported: true} }

var (
	errEmpty          = malformed("empty input")
	errUnknownPacket  = unsupported("unknown packet type")
	errUnknownVersion = unsupported("unknown version")
	errPacketLen      = malformed("invalid packet length")
	errPacketType     = malformed("unexpected packet type")
	errPacketNumber   = malformed("reserved packet number")
)
