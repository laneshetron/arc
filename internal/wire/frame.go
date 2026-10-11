package wire

import (
	"encoding/binary"
	"fmt"
)

// FrameType identifies a TLV frame inside a decrypted DATA payload (§10.1).
type FrameType uint8

const (
	FramePadding       FrameType = 0x00
	FrameAuth          FrameType = 0x01
	FrameAuthResult    FrameType = 0x02
	FrameIPPacket      FrameType = 0x03
	FrameIPFragment    FrameType = 0x04
	FrameNewPath       FrameType = 0x05
	FramePathJoin      FrameType = 0x06
	FramePathChallenge FrameType = 0x07
	FramePathResponse  FrameType = 0x08
	FramePathAbandon   FrameType = 0x09
	FramePing          FrameType = 0x0A
	FrameAck           FrameType = 0x0B
	FrameClose         FrameType = 0x0C
	FrameError         FrameType = 0x0D

	// Frame types at or above FirstExtensionFrame are optional extensions
	// that receivers may ignore; unknown types below it are required.
	FirstExtensionFrame FrameType = 0x80
)

var frameNames = [...]string{
	"PADDING", "AUTH", "AUTH_RESULT", "IP_PACKET", "IP_FRAGMENT", "NEW_PATH", "PATH_JOIN",
	"PATH_CHALLENGE", "PATH_RESPONSE", "PATH_ABANDON", "PING", "ACK", "CLOSE", "ERROR",
}

func (t FrameType) String() string {
	if int(t) < len(frameNames) {
		return frameNames[t]
	}
	return fmt.Sprintf("FrameType(%#02x)", uint8(t))
}

// AckEliciting reports whether a packet containing this frame type must be
// acknowledged (§10.1).
func (t FrameType) AckEliciting() bool {
	switch t {
	case FramePadding, FrameAck, FrameClose:
		return false
	}
	return true
}

// ErrorCode is shared by CLOSE, ERROR, and PATH_ABANDON frames.
type ErrorCode uint16

const (
	CodeNoError           ErrorCode = 0
	CodeMalformed         ErrorCode = 1
	CodeAuthFailed        ErrorCode = 2
	CodeUnauthorized      ErrorCode = 3
	CodePathUnavailable   ErrorCode = 4
	CodeCapacity          ErrorCode = 5
	CodeUnsupported       ErrorCode = 6
	CodeSessionExpired    ErrorCode = 7
	CodeProtocolViolation ErrorCode = 8
)

const (
	MaxCredentialLen = 4096
	MinTunMTU        = 1280
	MaxAckRanges     = 32

	authResultLen   = 28
	newPathLen      = 28
	ipFragmentFixed = 12
	ackFixed        = 21
)

// Frame is one decoded frame. Variable-length fields alias the buffer the
// frame was parsed from.
type Frame interface {
	Type() FrameType
	appendValue(b []byte) []byte
}

type Padding struct{ Len int }

type Auth struct{ Credential []byte }

type AuthResult struct {
	Status      uint8
	IPv4        [4]byte
	Prefix4     uint8
	TunMTU      uint16
	DNSv4       [4]byte
	KeepaliveMS uint32
	IdleMS      uint32
	Features    uint64
}

type IPPacket struct{ Packet []byte }

type IPFragment struct {
	DatagramID uint64
	TotalLen   uint16
	Offset     uint16
	Data       []byte
}

type NewPath struct {
	PathID     uint32
	CID        CID
	ResetToken Token
}

type PathJoin struct{ CID CID }

type PathChallenge struct{ Data [8]byte }

type PathResponse struct{ Data [8]byte }

type PathAbandon struct {
	PathID uint32
	Code   ErrorCode
}

type Ping struct{}

// Ack acknowledges packet numbers in one path's number space (§10.2).
type Ack struct {
	PathID         uint32
	Largest        uint64
	AckDelayMicros uint32
	FirstRange     uint32
	Ranges         []AckRange
}

// AckRange is one additional (gap, length) block of an ACK frame.
type AckRange struct {
	Gap    uint32
	Length uint32
}

// PacketRange is an inclusive range of acknowledged packet numbers.
type PacketRange struct{ Lo, Hi uint64 }

type CloseFrame struct{ Code ErrorCode }

type ErrorFrame struct{ Code ErrorCode }

// Unknown is an extension frame (type >= 0x80) that the receiver may ignore.
type Unknown struct {
	FrameType FrameType
	Value     []byte
}

func (Padding) Type() FrameType       { return FramePadding }
func (Auth) Type() FrameType          { return FrameAuth }
func (AuthResult) Type() FrameType    { return FrameAuthResult }
func (IPPacket) Type() FrameType      { return FrameIPPacket }
func (IPFragment) Type() FrameType    { return FrameIPFragment }
func (NewPath) Type() FrameType       { return FrameNewPath }
func (PathJoin) Type() FrameType      { return FramePathJoin }
func (PathChallenge) Type() FrameType { return FramePathChallenge }
func (PathResponse) Type() FrameType  { return FramePathResponse }
func (PathAbandon) Type() FrameType   { return FramePathAbandon }
func (Ping) Type() FrameType          { return FramePing }
func (Ack) Type() FrameType           { return FrameAck }
func (CloseFrame) Type() FrameType    { return FrameClose }
func (ErrorFrame) Type() FrameType    { return FrameError }
func (u Unknown) Type() FrameType     { return u.FrameType }

// AppendFrame appends the TLV encoding of f to b. It panics if the encoded
// value exceeds 65535 bytes, which no valid ARC packet can contain.
func AppendFrame(b []byte, f Frame) []byte {
	start := len(b)
	b = append(b, byte(f.Type()), 0, 0)
	b = f.appendValue(b)
	n := len(b) - start - FrameHeaderLen
	if n > 0xFFFF {
		panic("wire: frame value exceeds 65535 bytes")
	}
	binary.BigEndian.PutUint16(b[start+1:], uint16(n))
	return b
}

func (p Padding) appendValue(b []byte) []byte {
	for range p.Len {
		b = append(b, 0)
	}
	return b
}

func (a Auth) appendValue(b []byte) []byte { return append(b, a.Credential...) }

func (r AuthResult) appendValue(b []byte) []byte {
	b = append(b, r.Status)
	b = append(b, r.IPv4[:]...)
	b = append(b, r.Prefix4)
	b = binary.BigEndian.AppendUint16(b, r.TunMTU)
	b = append(b, r.DNSv4[:]...)
	b = binary.BigEndian.AppendUint32(b, r.KeepaliveMS)
	b = binary.BigEndian.AppendUint32(b, r.IdleMS)
	return binary.BigEndian.AppendUint64(b, r.Features)
}

func (p IPPacket) appendValue(b []byte) []byte { return append(b, p.Packet...) }

func (f IPFragment) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, f.DatagramID)
	b = binary.BigEndian.AppendUint16(b, f.TotalLen)
	b = binary.BigEndian.AppendUint16(b, f.Offset)
	return append(b, f.Data...)
}

func (p NewPath) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, p.PathID)
	b = append(b, p.CID[:]...)
	return append(b, p.ResetToken[:]...)
}

func (p PathJoin) appendValue(b []byte) []byte      { return append(b, p.CID[:]...) }
func (p PathChallenge) appendValue(b []byte) []byte { return append(b, p.Data[:]...) }
func (p PathResponse) appendValue(b []byte) []byte  { return append(b, p.Data[:]...) }

func (p PathAbandon) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, p.PathID)
	return binary.BigEndian.AppendUint16(b, uint16(p.Code))
}

func (Ping) appendValue(b []byte) []byte { return b }

func (a Ack) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, a.PathID)
	b = binary.BigEndian.AppendUint64(b, a.Largest)
	b = binary.BigEndian.AppendUint32(b, a.AckDelayMicros)
	b = binary.BigEndian.AppendUint32(b, a.FirstRange)
	b = append(b, byte(len(a.Ranges)))
	for _, r := range a.Ranges {
		b = binary.BigEndian.AppendUint32(b, r.Gap)
		b = binary.BigEndian.AppendUint32(b, r.Length)
	}
	return b
}

func (c CloseFrame) appendValue(b []byte) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(c.Code))
}

func (e ErrorFrame) appendValue(b []byte) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(e.Code))
}

func (u Unknown) appendValue(b []byte) []byte { return append(b, u.Value...) }

// AppendIntervals appends the acknowledged packet ranges, highest first.
// The ranges of a parsed Ack are known to be valid.
func (a *Ack) AppendIntervals(dst []PacketRange) ([]PacketRange, error) {
	if uint64(a.FirstRange) > a.Largest {
		return dst, errAckRange
	}
	smallest := a.Largest - uint64(a.FirstRange)
	dst = append(dst, PacketRange{smallest, a.Largest})
	for _, r := range a.Ranges {
		// hi = smallest - gap - 2; lo = hi - length (RFC 9000 §19.3.1).
		if smallest < uint64(r.Gap)+2 {
			return dst, errAckRange
		}
		hi := smallest - uint64(r.Gap) - 2
		if hi < uint64(r.Length) {
			return dst, errAckRange
		}
		smallest = hi - uint64(r.Length)
		dst = append(dst, PacketRange{smallest, hi})
	}
	return dst, nil
}

var (
	errNoFrames         = malformed("payload contains no frames")
	errFrameHeader      = malformed("truncated frame header")
	errFrameLen         = malformed("frame length exceeds payload")
	errUnknownFrame     = unsupported("unknown required frame type")
	errFrameSize        = malformed("invalid frame value length")
	errPadding          = malformed("nonzero padding")
	errAuthResultFields = malformed("AUTH_RESULT failure with nonzero fields")
	errAuthResultMTU    = malformed("AUTH_RESULT tun_mtu below minimum")
	errAuthResultFeat   = malformed("AUTH_RESULT unknown features")
	errIPVersion        = malformed("IP_PACKET has unknown IP version")
	errIPLength         = malformed("IP_PACKET length does not match IP header")
	errFragmentRange    = malformed("IP_FRAGMENT range invalid")
	errAckRange         = malformed("ACK range underflow")
)

// ParseFrames decodes every frame in a decrypted DATA payload and appends
// them to dst. It validates the whole payload before returning, so a
// packet with any invalid or unknown required frame is rejected as a unit
// (§10). Returned frames alias p.
func ParseFrames(dst []Frame, p []byte) ([]Frame, error) {
	if len(p) == 0 {
		return dst, errNoFrames
	}
	start := len(dst)
	for len(p) > 0 {
		f, n, err := ParseFrame(p)
		if err != nil {
			return dst[:start], err
		}
		dst = append(dst, f)
		p = p[n:]
	}
	return dst, nil
}

// ParseFrame decodes the first frame in p and returns it with the number of
// bytes consumed.
func ParseFrame(p []byte) (Frame, int, error) {
	if len(p) < FrameHeaderLen {
		return nil, 0, errFrameHeader
	}
	t := FrameType(p[0])
	n := int(binary.BigEndian.Uint16(p[1:3]))
	if len(p)-FrameHeaderLen < n {
		return nil, 0, errFrameLen
	}
	v := p[FrameHeaderLen : FrameHeaderLen+n]
	f, err := parseValue(t, v)
	if err != nil {
		return nil, 0, err
	}
	return f, FrameHeaderLen + n, nil
}

func parseValue(t FrameType, v []byte) (Frame, error) {
	switch t {
	case FramePadding:
		for _, c := range v {
			if c != 0 {
				return nil, errPadding
			}
		}
		return Padding{Len: len(v)}, nil

	case FrameAuth:
		if len(v) == 0 || len(v) > MaxCredentialLen {
			return nil, errFrameSize
		}
		return Auth{Credential: v}, nil

	case FrameAuthResult:
		return parseAuthResult(v)

	case FrameIPPacket:
		if err := validateIPPacket(v); err != nil {
			return nil, err
		}
		return IPPacket{Packet: v}, nil

	case FrameIPFragment:
		if len(v) <= ipFragmentFixed {
			return nil, errFrameSize
		}
		f := IPFragment{
			DatagramID: binary.BigEndian.Uint64(v[0:8]),
			TotalLen:   binary.BigEndian.Uint16(v[8:10]),
			Offset:     binary.BigEndian.Uint16(v[10:12]),
			Data:       v[ipFragmentFixed:],
		}
		if f.TotalLen < 20 || int(f.Offset)+len(f.Data) > int(f.TotalLen) {
			return nil, errFragmentRange
		}
		return f, nil

	case FrameNewPath:
		if len(v) != newPathLen {
			return nil, errFrameSize
		}
		var f NewPath
		f.PathID = binary.BigEndian.Uint32(v[0:4])
		copy(f.CID[:], v[4:12])
		copy(f.ResetToken[:], v[12:28])
		return f, nil

	case FramePathJoin, FramePathChallenge, FramePathResponse:
		if len(v) != 8 {
			return nil, errFrameSize
		}
		var d [8]byte
		copy(d[:], v)
		switch t {
		case FramePathJoin:
			return PathJoin{CID: CID(d)}, nil
		case FramePathChallenge:
			return PathChallenge{Data: d}, nil
		default:
			return PathResponse{Data: d}, nil
		}

	case FramePathAbandon:
		if len(v) != 6 {
			return nil, errFrameSize
		}
		return PathAbandon{
			PathID: binary.BigEndian.Uint32(v[0:4]),
			Code:   ErrorCode(binary.BigEndian.Uint16(v[4:6])),
		}, nil

	case FramePing:
		if len(v) != 0 {
			return nil, errFrameSize
		}
		return Ping{}, nil

	case FrameAck:
		return parseAck(v)

	case FrameClose, FrameError:
		if len(v) != 2 {
			return nil, errFrameSize
		}
		code := ErrorCode(binary.BigEndian.Uint16(v))
		if t == FrameClose {
			return CloseFrame{Code: code}, nil
		}
		return ErrorFrame{Code: code}, nil
	}

	if t >= FirstExtensionFrame {
		return Unknown{FrameType: t, Value: v}, nil
	}
	return nil, errUnknownFrame
}

func parseAuthResult(v []byte) (Frame, error) {
	if len(v) != authResultLen {
		return nil, errFrameSize
	}
	var r AuthResult
	r.Status = v[0]
	copy(r.IPv4[:], v[1:5])
	r.Prefix4 = v[5]
	r.TunMTU = binary.BigEndian.Uint16(v[6:8])
	copy(r.DNSv4[:], v[8:12])
	r.KeepaliveMS = binary.BigEndian.Uint32(v[12:16])
	r.IdleMS = binary.BigEndian.Uint32(v[16:20])
	r.Features = binary.BigEndian.Uint64(v[20:28])
	if r.Status != 0 {
		for _, c := range v[1:] {
			if c != 0 {
				return nil, errAuthResultFields
			}
		}
		return r, nil
	}
	if r.TunMTU < MinTunMTU {
		return nil, errAuthResultMTU
	}
	if r.Features != 0 {
		return nil, errAuthResultFeat
	}
	return r, nil
}

// validateIPPacket checks the IP version and that the packet's declared
// length matches the frame length (§10.1).
func validateIPPacket(v []byte) error {
	if len(v) == 0 {
		return errFrameSize
	}
	switch v[0] >> 4 {
	case 4:
		if len(v) < 20 || int(binary.BigEndian.Uint16(v[2:4])) != len(v) {
			return errIPLength
		}
	case 6:
		if len(v) < 40 || int(binary.BigEndian.Uint16(v[4:6]))+40 != len(v) {
			return errIPLength
		}
	default:
		return errIPVersion
	}
	return nil
}

func parseAck(v []byte) (Frame, error) {
	if len(v) < ackFixed {
		return nil, errFrameSize
	}
	count := int(v[20])
	if count > MaxAckRanges || len(v) != ackFixed+8*count {
		return nil, errFrameSize
	}
	a := Ack{
		PathID:         binary.BigEndian.Uint32(v[0:4]),
		Largest:        binary.BigEndian.Uint64(v[4:12]),
		AckDelayMicros: binary.BigEndian.Uint32(v[12:16]),
		FirstRange:     binary.BigEndian.Uint32(v[16:20]),
	}
	if count > 0 {
		a.Ranges = make([]AckRange, count)
		for i := range a.Ranges {
			o := ackFixed + 8*i
			a.Ranges[i] = AckRange{
				Gap:    binary.BigEndian.Uint32(v[o : o+4]),
				Length: binary.BigEndian.Uint32(v[o+4 : o+8]),
			}
		}
	}
	var buf [MaxAckRanges + 1]PacketRange
	if _, err := a.AppendIntervals(buf[:0]); err != nil {
		return nil, err
	}
	return a, nil
}
