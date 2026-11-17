// Package invite encodes the invite string an ARC relay hands out and the
// enrollment credential a client redeems it with
// (spec/self-service-accounts.md §3.3–3.4).
package invite

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Prefix begins every invite string.
const Prefix = "arc1:"

// Carrier bits.
const (
	CarrierUDP   = 1 << 0
	CarrierTLS   = 1 << 1 // raw ARC after TLS
	CarrierFront = 1 << 2 // HTTP/1.1 upgrade first (spec §16.3)
)

// Fingerprints, by their number in an invite: 0 is none.
var Fingerprints = []string{"", "chrome", "edge", "safari", "ios", "firefox"}

// MaxServerName is the longest server name an invite holds.
const MaxServerName = 253

// An Invite is everything a client needs to reach a relay and redeem one
// single-use secret.
type Invite struct {
	Carriers    uint8
	Addr        netip.Addr // the relay's address, for every carrier
	UDPPort     uint16
	TLSPort     uint16
	FrontPort   uint16
	RelayKey    [32]byte // the relay's static public key, pinned
	ID          [8]byte
	Secret      [16]byte
	Fingerprint string // the -tls-fingerprint choice, or ""
	ServerName  string // TLS: the cover host; front: the front's own domain
}

// Validate checks the rules both sides apply (§3.3).
func (v *Invite) Validate() error {
	switch {
	case v.Carriers == 0 || v.Carriers&^(CarrierUDP|CarrierTLS|CarrierFront) != 0:
		return errors.New("invite: no carriers, or unknown ones")
	case v.Carriers&CarrierTLS != 0 && v.Carriers&CarrierFront != 0:
		return errors.New("invite: TLS and front carriers are exclusive")
	case v.Carriers&(CarrierTLS|CarrierFront) != 0 && v.ServerName == "":
		return errors.New("invite: a TLS or front carrier needs a server name")
	case len(v.ServerName) > MaxServerName:
		return errors.New("invite: server name too long")
	case !v.Addr.IsValid() || v.Addr.Zone() != "":
		return errors.New("invite: no relay address")
	case v.Carriers&CarrierUDP != 0 && v.UDPPort == 0,
		v.Carriers&CarrierTLS != 0 && v.TLSPort == 0,
		v.Carriers&CarrierFront != 0 && v.FrontPort == 0:
		return errors.New("invite: a carrier without a port")
	}
	if fingerprintNumber(v.Fingerprint) < 0 {
		return fmt.Errorf("invite: unknown fingerprint %q", v.Fingerprint)
	}
	return nil
}

func fingerprintNumber(name string) int {
	for i, f := range Fingerprints {
		if f == name {
			return i
		}
	}
	return -1
}

// String encodes v; it panics if v is invalid.
func (v *Invite) String() string {
	if err := v.Validate(); err != nil {
		panic(err)
	}
	b := []byte{1, v.Carriers}
	if a := v.Addr.Unmap(); a.Is4() {
		b = append(b, 4)
		b = append(b, a.AsSlice()...)
	} else {
		b = append(b, 6)
		b = append(b, a.AsSlice()...)
	}
	for _, p := range []struct {
		bit  uint8
		port uint16
	}{{CarrierUDP, v.UDPPort}, {CarrierTLS, v.TLSPort}, {CarrierFront, v.FrontPort}} {
		if v.Carriers&p.bit != 0 {
			b = binary.BigEndian.AppendUint16(b, p.port)
		}
	}
	b = append(b, v.RelayKey[:]...)
	b = append(b, v.ID[:]...)
	b = append(b, v.Secret[:]...)
	b = append(b, byte(fingerprintNumber(v.Fingerprint)), byte(len(v.ServerName)))
	b = append(b, v.ServerName...)
	b = binary.BigEndian.AppendUint16(b, crc16(b))
	return Prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Parse decodes an invite string, ignoring surrounding white space.
func Parse(s string) (*Invite, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Prefix) {
		return nil, errors.New("invite: not an arc1: invite")
	}
	b, err := base64.RawURLEncoding.DecodeString(s[len(Prefix):])
	if err != nil {
		return nil, errors.New("invite: not valid base64url")
	}
	if len(b) < 2 || crc16(b[:len(b)-2]) != binary.BigEndian.Uint16(b[len(b)-2:]) {
		return nil, errors.New("invite: checksum mismatch (mistyped or truncated?)")
	}
	r := reader{b: b[:len(b)-2]}
	if r.u8() != 1 {
		return nil, errors.New("invite: unsupported version")
	}
	v := &Invite{Carriers: r.u8()}
	switch r.u8() {
	case 4:
		v.Addr = netip.AddrFrom4([4]byte(r.bytes(4)))
	case 6:
		v.Addr = netip.AddrFrom16([16]byte(r.bytes(16)))
	default:
		return nil, errors.New("invite: unknown address family")
	}
	if v.Carriers&CarrierUDP != 0 {
		v.UDPPort = r.u16()
	}
	if v.Carriers&CarrierTLS != 0 {
		v.TLSPort = r.u16()
	}
	if v.Carriers&CarrierFront != 0 {
		v.FrontPort = r.u16()
	}
	copy(v.RelayKey[:], r.bytes(32))
	copy(v.ID[:], r.bytes(8))
	copy(v.Secret[:], r.bytes(16))
	fp := int(r.u8())
	v.ServerName = string(r.bytes(int(r.u8())))
	if r.err || len(r.b) != 0 {
		return nil, errors.New("invite: wrong length")
	}
	if fp >= len(Fingerprints) {
		return nil, errors.New("invite: unknown fingerprint")
	}
	v.Fingerprint = Fingerprints[fp]
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return v, nil
}

type reader struct {
	b   []byte
	err bool
}

func (r *reader) bytes(n int) []byte {
	if r.err || len(r.b) < n {
		r.err = true
		return make([]byte, n)
	}
	p := r.b[:n]
	r.b = r.b[n:]
	return p
}

func (r *reader) u8() uint8   { return r.bytes(1)[0] }
func (r *reader) u16() uint16 { return binary.BigEndian.Uint16(r.bytes(2)) }

// crc16 is CRC-16/CCITT-FALSE (polynomial 0x1021, initial 0xFFFF).
func crc16(b []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, c := range b {
		crc ^= uint16(c) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// NewToken returns a fresh device token: 32 random bytes, base64url
// without padding, 43 ASCII characters (§3.4).
func NewToken() []byte {
	var b [32]byte
	rand.Read(b[:])
	return []byte(base64.RawURLEncoding.EncodeToString(b[:]))
}

// enrollMagic begins an enrollment credential. Its leading zero byte
// cannot begin a token, which is printable ASCII.
const enrollMagic = "\x00ARC-ENROLL1"

// MaxDeviceName is the longest device name.
const MaxDeviceName = 32

// An Enrollment is what an enrolling client sends in AUTH in place of a
// token: the invite it redeems, the token it registers, and the name it
// proposes for the device.
type Enrollment struct {
	ID     [8]byte
	Secret [16]byte
	Token  []byte
	Name   string
}

// Credential encodes e as an AUTH credential.
func (e *Enrollment) Credential() []byte {
	b := append([]byte(enrollMagic), e.ID[:]...)
	b = append(b, e.Secret[:]...)
	b = append(b, byte(len(e.Token)))
	b = append(b, e.Token...)
	b = append(b, byte(len(e.Name)))
	return append(b, e.Name...)
}

// IsEnrollment reports whether an AUTH credential is an enrollment.
func IsEnrollment(credential []byte) bool { return bytes.HasPrefix(credential, []byte(enrollMagic)) }

// ParseEnrollment decodes an enrollment credential. It checks the
// layout only; the token's and name's syntax are the relay's to judge.
func ParseEnrollment(credential []byte) (*Enrollment, error) {
	if !IsEnrollment(credential) {
		return nil, errors.New("invite: not an enrollment credential")
	}
	r := reader{b: credential[len(enrollMagic):]}
	e := &Enrollment{}
	copy(e.ID[:], r.bytes(8))
	copy(e.Secret[:], r.bytes(16))
	e.Token = bytes.Clone(r.bytes(int(r.u8())))
	e.Name = string(r.bytes(int(r.u8())))
	if r.err || len(r.b) != 0 || len(e.Token) == 0 || len(e.Name) > MaxDeviceName {
		return nil, errors.New("invite: malformed enrollment credential")
	}
	return e, nil
}
