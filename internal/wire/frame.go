package wire

import (
	"encoding/binary"
	"fmt"
	"net/netip"
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
	FrameIPDatagram    FrameType = 0x0E
	FrameRedundancy    FrameType = 0x0F
	FrameFECRepair     FrameType = 0x10
	FrameFEC           FrameType = 0x11
	FrameStreamOpen    FrameType = 0x12
	FrameStream        FrameType = 0x13
	FrameMaxStreamData FrameType = 0x14
	FrameMaxData       FrameType = 0x15
	FrameStreamReset   FrameType = 0x16
	FrameDiagOpen      FrameType = 0x17
	FrameEnrolled      FrameType = 0x18
	FrameInviteRequest FrameType = 0x19
	FrameInvite        FrameType = 0x1A

	// Frame types at or above FirstExtensionFrame are optional extensions
	// that receivers may ignore; unknown types below it are required.
	FirstExtensionFrame FrameType = 0x80
)

var frameNames = [...]string{
	"PADDING", "AUTH", "AUTH_RESULT", "IP_PACKET", "IP_FRAGMENT", "NEW_PATH", "PATH_JOIN",
	"PATH_CHALLENGE", "PATH_RESPONSE", "PATH_ABANDON", "PING", "ACK", "CLOSE", "ERROR",
	"IP_DATAGRAM", "REDUNDANCY", "FEC_REPAIR", "FEC", "STREAM_OPEN", "STREAM", "MAX_STREAM_DATA",
	"MAX_DATA", "STREAM_RESET", "DIAGNOSTICS_OPEN", "ENROLLED",
	"INVITE_REQUEST", "INVITE",
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
	// Stream reset codes (§11.3).
	CodeConnectFailed ErrorCode = 9  // the relay could not connect to the destination
	CodeAborted       ErrorCode = 10 // the TCP connection failed or was reset
	// Enrollment refusals (§9.2), in AUTH_RESULT and CLOSE.
	CodeInviteUsed    ErrorCode = 11 // another device redeemed the invite
	CodeInviteExpired ErrorCode = 12
)

const (
	MaxCredentialLen = 4096
	MinTunMTU        = 1280
	MaxAckRanges     = 32

	authResultLen   = 28
	newPathLen      = 28
	ipFragmentFixed = 12
	ipDatagramFixed = 8
	redundancyLen   = 5
	fecRepairFixed  = 8
	fecLen          = 5
	streamFixed     = 13
	maxStreamData   = 12
	maxDataLen      = 8
	streamResetLen  = 14
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

// IPDatagram is an IP packet with a datagram ID, so that copies sent on
// several paths are delivered once (§11.1). IDs share the IP_FRAGMENT space.
type IPDatagram struct {
	DatagramID uint64
	Packet     []byte
}

// Features bits in AUTH_RESULT (§10.1).
const (
	// FeatureRedundancy: the relay accepts IP_DATAGRAM and REDUNDANCY.
	FeatureRedundancy uint64 = 1 << 0
	// FeatureFEC: the relay accepts FEC_REPAIR and FEC (§11.2).
	FeatureFEC uint64 = 1 << 1
	// FeatureStreams: the relay accepts STREAM_OPEN and carries streams to
	// TCP destinations (§11.3).
	FeatureStreams uint64 = 1 << 2
	// FeatureDiagnostics: the relay accepts DIAGNOSTICS_OPEN and keeps what
	// the client uploads on the stream for its operator (§11.4).
	FeatureDiagnostics uint64 = 1 << 3
	// FeatureInvites: the session's device may ask for invites to its
	// account with INVITE_REQUEST (self-service-accounts.md §3.6).
	FeatureInvites uint64 = 1 << 4
)

// MaxStreamOffset bounds stream offsets and flow control limits, so that
// offset plus length never overflows (§11.3).
const MaxStreamOffset = 1<<62 - 1

// StreamOpen asks the relay to connect stream ID to a TCP destination
// (§11.3). Client to relay only.
type StreamOpen struct {
	ID  uint32
	Dst netip.AddrPort
}

// DiagOpen opens stream ID as an upload of the client's diagnostics to
// the relay's operator, instead of a connection (§11.4). Client to relay
// only.
type DiagOpen struct {
	ID uint32
}

// Enrolled tells a client that enrolled with an invite the device it
// became: its ID and the name the relay chose (§9.2). Relay to client
// only, and only after an enrollment credential.
type Enrolled struct {
	DeviceID [8]byte
	Name     string
}

// MaxDeviceName is the longest device name in ENROLLED.
const MaxDeviceName = 32

// InviteRequest asks the relay for an invite to the session's account
// (§10.1). The client picks RequestID at random, keeps it until answered,
// and repeats the request with it: the relay answers a repeat with the
// same invite. Client to relay only, with FeatureInvites.
type InviteRequest struct {
	RequestID [8]byte
}

// Invite answers an InviteRequest: with Status 0, the invite's ID, its
// secret and its expiry (Unix seconds); otherwise a code (CAPACITY,
// INVITE_EXPIRED, UNAUTHORIZED) and every other field zero. Relay to
// client only.
type Invite struct {
	RequestID [8]byte
	Status    ErrorCode
	ID        [8]byte
	Secret    [16]byte
	Expires   uint32
}

// Stream carries bytes of a stream starting at Offset. Fin marks the end of
// the sender's data at Offset+len(Data).
type Stream struct {
	ID     uint32
	Offset uint64
	Fin    bool
	Data   []byte
}

// MaxStreamData raises the number of bytes the peer may send on a stream:
// offsets below Max.
type MaxStreamData struct {
	ID  uint32
	Max uint64
}

// MaxData raises the total the peer may send across all streams.
type MaxData struct{ Max uint64 }

// StreamReset abandons a stream in both directions. Final is the size of
// what the sender sent on it, for connection flow control.
type StreamReset struct {
	ID    uint32
	Code  ErrorCode
	Final uint64
}

// FECRepair is one forward-error-correction repair symbol (§11.2) for the
// block of K datagrams with IDs First, First+Stride, ..., of which only
// the low 32 bits travel. Data is as long as the block's longest datagram.
type FECRepair struct {
	First32 uint32
	Stride  uint8
	K, M    uint8
	Index   uint8
	Data    []byte
}

// FECMode is the forward error correction a client asks the relay to
// apply to downlink traffic (§11.2).
type FECMode uint8

const (
	FECOff    FECMode = 0
	FECAuto   FECMode = 1 // sized from the relay's measured downlink loss
	FECAlways FECMode = 2 // at least one repair per block even without loss
)

// FEC sets the downlink FEC mode. Seq orders requests, as for REDUNDANCY.
type FEC struct {
	Seq  uint32
	Mode FECMode
}

// RedundancyMode selects how the relay sends downlink IP traffic (§11.1).
type RedundancyMode uint8

const (
	RedundancyNone      RedundancyMode = 0 // primary path only
	RedundancyDuplicate RedundancyMode = 1 // primary and a second path
)

// Redundancy asks the relay to change its downlink redundancy. Seq orders
// requests, since a retransmitted old request may arrive after a new one.
type Redundancy struct {
	Seq  uint32
	Mode RedundancyMode
}

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
func (IPDatagram) Type() FrameType    { return FrameIPDatagram }
func (Redundancy) Type() FrameType    { return FrameRedundancy }
func (FECRepair) Type() FrameType     { return FrameFECRepair }
func (FEC) Type() FrameType           { return FrameFEC }
func (StreamOpen) Type() FrameType    { return FrameStreamOpen }
func (Stream) Type() FrameType        { return FrameStream }
func (MaxStreamData) Type() FrameType { return FrameMaxStreamData }
func (MaxData) Type() FrameType       { return FrameMaxData }
func (StreamReset) Type() FrameType   { return FrameStreamReset }
func (DiagOpen) Type() FrameType      { return FrameDiagOpen }
func (Enrolled) Type() FrameType      { return FrameEnrolled }
func (InviteRequest) Type() FrameType { return FrameInviteRequest }
func (Invite) Type() FrameType        { return FrameInvite }
func (u Unknown) Type() FrameType     { return u.FrameType }

// AppendFrame appends the TLV encoding of f to b. It panics if the encoded
// value exceeds 65535 bytes, which no valid ARC packet can contain.
// AppendIPPacket appends an IP_PACKET frame carrying pkt. It is
// AppendFrame(b, IPPacket{Packet: pkt}) without converting to the Frame
// interface, which would allocate on the per-packet path.
func AppendIPPacket(b, pkt []byte) []byte {
	if len(pkt) > 0xFFFF {
		panic("wire: frame value exceeds 65535 bytes")
	}
	b = append(b, byte(FrameIPPacket), byte(len(pkt)>>8), byte(len(pkt)))
	return append(b, pkt...)
}

// AppendIPDatagram appends an IP_DATAGRAM frame, like AppendIPPacket.
func AppendIPDatagram(b []byte, id uint64, pkt []byte) []byte {
	n := ipDatagramFixed + len(pkt)
	if n > 0xFFFF {
		panic("wire: frame value exceeds 65535 bytes")
	}
	b = append(b, byte(FrameIPDatagram), byte(n>>8), byte(n))
	b = binary.BigEndian.AppendUint64(b, id)
	return append(b, pkt...)
}

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

func (d IPDatagram) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, d.DatagramID)
	return append(b, d.Packet...)
}

func (r Redundancy) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, r.Seq)
	return append(b, byte(r.Mode))
}

func (r FECRepair) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, r.First32)
	b = append(b, r.Stride, r.K, r.M, r.Index)
	return append(b, r.Data...)
}

func (f FEC) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, f.Seq)
	return append(b, byte(f.Mode))
}

func (o StreamOpen) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, o.ID)
	b = binary.BigEndian.AppendUint16(b, o.Dst.Port())
	return append(b, o.Dst.Addr().AsSlice()...)
}

func (o DiagOpen) appendValue(b []byte) []byte {
	return binary.BigEndian.AppendUint32(b, o.ID)
}

func (e Enrolled) appendValue(b []byte) []byte {
	b = append(b, e.DeviceID[:]...)
	b = append(b, byte(len(e.Name)))
	return append(b, e.Name...)
}

func (r InviteRequest) appendValue(b []byte) []byte { return append(b, r.RequestID[:]...) }

func (i Invite) appendValue(b []byte) []byte {
	b = append(b, i.RequestID[:]...)
	b = append(b, byte(i.Status))
	b = append(b, i.ID[:]...)
	b = append(b, i.Secret[:]...)
	return binary.BigEndian.AppendUint32(b, i.Expires)
}

func (f Stream) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, f.ID)
	b = binary.BigEndian.AppendUint64(b, f.Offset)
	var flags byte
	if f.Fin {
		flags = 1
	}
	return append(append(b, flags), f.Data...)
}

func (m MaxStreamData) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, m.ID)
	return binary.BigEndian.AppendUint64(b, m.Max)
}

func (m MaxData) appendValue(b []byte) []byte { return binary.BigEndian.AppendUint64(b, m.Max) }

func (r StreamReset) appendValue(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, r.ID)
	b = binary.BigEndian.AppendUint16(b, uint16(r.Code))
	return binary.BigEndian.AppendUint64(b, r.Final)
}

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
	errRedundancyMode   = malformed("REDUNDANCY unknown mode")
	errFECRepair        = malformed("FEC_REPAIR geometry invalid")
	errFECMode          = malformed("FEC unknown mode")
	errStreamOpen       = malformed("STREAM_OPEN destination invalid")
	errStreamID         = malformed("stream ID zero")
	errEnrolledName     = malformed("ENROLLED device name invalid")
	errInviteFields     = malformed("INVITE refusal with nonzero fields")
	errInviteRequestID  = malformed("invite request_id zero")
	errStreamFlags      = malformed("STREAM unknown flags")
	errStreamOffset     = malformed("stream offset or limit too large")
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
		if err := ValidateIPPacket(v); err != nil {
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

	case FrameIPDatagram:
		if len(v) < ipDatagramFixed {
			return nil, errFrameSize
		}
		if err := ValidateIPPacket(v[ipDatagramFixed:]); err != nil {
			return nil, err
		}
		return IPDatagram{DatagramID: binary.BigEndian.Uint64(v), Packet: v[ipDatagramFixed:]}, nil

	case FrameRedundancy:
		if len(v) != redundancyLen {
			return nil, errFrameSize
		}
		r := Redundancy{Seq: binary.BigEndian.Uint32(v), Mode: RedundancyMode(v[4])}
		if r.Mode > RedundancyDuplicate {
			return nil, errRedundancyMode
		}
		return r, nil

	case FrameFECRepair:
		if len(v) <= fecRepairFixed {
			return nil, errFrameSize
		}
		r := FECRepair{First32: binary.BigEndian.Uint32(v), Stride: v[4], K: v[5], M: v[6], Index: v[7], Data: v[fecRepairFixed:]}
		if r.Stride < 1 || r.Stride > 16 || r.K < 1 || r.K > 64 || r.M < 1 || r.M > 32 || r.Index >= r.M {
			return nil, errFECRepair
		}
		return r, nil

	case FrameFEC:
		if len(v) != fecLen {
			return nil, errFrameSize
		}
		f := FEC{Seq: binary.BigEndian.Uint32(v), Mode: FECMode(v[4])}
		if f.Mode > FECAlways {
			return nil, errFECMode
		}
		return f, nil

	case FrameStreamOpen:
		if len(v) != 10 && len(v) != 22 {
			return nil, errFrameSize
		}
		addr, _ := netip.AddrFromSlice(v[6:])
		o := StreamOpen{ID: binary.BigEndian.Uint32(v), Dst: netip.AddrPortFrom(addr, binary.BigEndian.Uint16(v[4:6]))}
		if o.ID == 0 {
			return nil, errStreamID
		}
		if o.Dst.Port() == 0 || addr.IsUnspecified() {
			return nil, errStreamOpen
		}
		return o, nil

	case FrameDiagOpen:
		if len(v) != 4 {
			return nil, errFrameSize
		}
		o := DiagOpen{ID: binary.BigEndian.Uint32(v)}
		if o.ID == 0 {
			return nil, errStreamID
		}
		return o, nil

	case FrameEnrolled:
		if len(v) < 10 || int(v[8]) != len(v)-9 || len(v)-9 > MaxDeviceName {
			return nil, errFrameSize
		}
		e := Enrolled{DeviceID: [8]byte(v[:8]), Name: string(v[9:])}
		if !validDeviceName(e.Name) {
			return nil, errEnrolledName
		}
		return e, nil

	case FrameInviteRequest:
		if len(v) != 8 {
			return nil, errFrameSize
		}
		if [8]byte(v) == [8]byte{} {
			return nil, errInviteRequestID
		}
		return InviteRequest{RequestID: [8]byte(v)}, nil

	case FrameInvite:
		if len(v) != 37 {
			return nil, errFrameSize
		}
		i := Invite{RequestID: [8]byte(v[:8]), Status: ErrorCode(v[8]), ID: [8]byte(v[9:17]), Secret: [16]byte(v[17:33]),
			Expires: binary.BigEndian.Uint32(v[33:37])}
		if i.RequestID == [8]byte{} {
			return nil, errInviteRequestID
		}
		if i.Status != 0 && (i.ID != [8]byte{} || i.Secret != [16]byte{} || i.Expires != 0) {
			return nil, errInviteFields
		}
		return i, nil

	case FrameStream:
		if len(v) < streamFixed {
			return nil, errFrameSize
		}
		f := Stream{ID: binary.BigEndian.Uint32(v), Offset: binary.BigEndian.Uint64(v[4:12]), Fin: v[12] == 1,
			Data: v[streamFixed:]}
		switch {
		case f.ID == 0:
			return nil, errStreamID
		case v[12] > 1:
			return nil, errStreamFlags
		case f.Offset+uint64(len(f.Data)) > MaxStreamOffset:
			return nil, errStreamOffset
		}
		return f, nil

	case FrameMaxStreamData:
		if len(v) != maxStreamData {
			return nil, errFrameSize
		}
		m := MaxStreamData{ID: binary.BigEndian.Uint32(v), Max: binary.BigEndian.Uint64(v[4:])}
		if m.ID == 0 {
			return nil, errStreamID
		}
		if m.Max > MaxStreamOffset {
			return nil, errStreamOffset
		}
		return m, nil

	case FrameMaxData:
		if len(v) != maxDataLen {
			return nil, errFrameSize
		}
		m := MaxData{Max: binary.BigEndian.Uint64(v)}
		if m.Max > MaxStreamOffset {
			return nil, errStreamOffset
		}
		return m, nil

	case FrameStreamReset:
		if len(v) != streamResetLen {
			return nil, errFrameSize
		}
		r := StreamReset{ID: binary.BigEndian.Uint32(v), Code: ErrorCode(binary.BigEndian.Uint16(v[4:6])),
			Final: binary.BigEndian.Uint64(v[6:])}
		if r.ID == 0 {
			return nil, errStreamID
		}
		if r.Final > MaxStreamOffset {
			return nil, errStreamOffset
		}
		return r, nil

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
	return r, nil // undefined Features bits are ignored
}

// ValidateIPPacket checks the IP version and that the packet's declared
// length matches the frame length (§10.1).
func ValidateIPPacket(v []byte) error {
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

// validDeviceName: letters, digits, '.', '_' and '-', not "." or "..".
func validDeviceName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
