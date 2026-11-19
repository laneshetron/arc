// Package beacon encodes and verifies the signed TXT record a DNS lifeline
// deployment publishes, which tells a client where its relays are
// (spec/dns-lifeline.md §3).
//
// The record is read before any session exists, so its trust comes entirely
// from an Ed25519 key the client holds out of band: a beacon that verifies
// was published by the deployment, and one that does not is discarded.
package beacon

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Version is the record version this package reads and writes.
const Version = 1

// Prefix begins every record's TXT content.
const Prefix = "B1:"

// Limits from the frozen grammar (§3.1). A field added beyond these would
// change the published size limits in §3.2, so they are checked rather
// than merely documented.
const (
	MaxRelays = 4
	MaxNames  = 4
	MaxZones  = 2
	MaxName   = 253 // a DNS name in presentation form
)

// EndpointKind says which transport an endpoint speaks (§3.5).
type EndpointKind uint8

const (
	// KindUDP is the relay's UDP carrier.
	KindUDP EndpointKind = 0
	// KindTLS is raw ARC after TLS (§16.3).
	KindTLS EndpointKind = 1
	// KindFront is the authenticated HTTP upgrade inside an HTTPS front
	// (§16.4). Its endpoint carries a domain, which the client presents as
	// the cover name.
	KindFront EndpointKind = 2
)

func (k EndpointKind) String() string {
	switch k {
	case KindUDP:
		return "udp"
	case KindTLS:
		return "tls"
	case KindFront:
		return "front"
	}
	return fmt.Sprintf("EndpointKind(%d)", uint8(k))
}

// Endpoint is one way to reach a relay.
type Endpoint struct {
	Kind EndpointKind
	Port uint16
	// Domain is the front's cover domain, for KindFront only.
	Domain string
}

// Relay is one relay the operator vouches for.
type Relay struct {
	Addr      netip.Addr // IPv4; clients reach relays over IPv4 only
	Key       ed25519.PublicKey
	Endpoints []Endpoint
}

// Beacon is a decoded record.
type Beacon struct {
	// DNSAvailable is flags bit 0: the deployment offers a DNS carrier.
	DNSAvailable bool
	// Published is the operator's publish time, for replay ordering.
	Published time.Time
	// NotAfter is when the operator stops vouching for the record.
	NotAfter time.Time
	Relays   []Relay
	// Names are cover names the stream carriers may present.
	Names []string
	// Zones are the carrier zones a DNS carrier may use.
	Zones []string
}

var (
	errPrefix    = errors.New("beacon: not a B1: record")
	errBase64    = errors.New("beacon: not base64url")
	errShort     = errors.New("beacon: record too short")
	errVersion   = errors.New("beacon: unsupported version")
	errLength    = errors.New("beacon: wrong length")
	errLimits    = errors.New("beacon: too many relays, names or zones")
	errAddr      = errors.New("beacon: relay address is not IPv4")
	errEndpoint  = errors.New("beacon: bad endpoint")
	errSignature = errors.New("beacon: bad signature")
	errTime      = errors.New("beacon: not yet published, or expired")
)

// Suffix is the beacon's own query suffix, below which the record was
// published: "_arcb." plus the delegated zone, lowercased and without a
// trailing dot. It is what the signature is domain-separated over, so a
// record signed for one name verifies under no other (§3.1).
func Suffix(zone string) string {
	return "_arcb." + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

// signedMessage is the domain-separated input to the signature:
// "ARC/1 beacon" ‖ u8(len) ‖ suffix ‖ body.
func signedMessage(suffix string, body []byte) []byte {
	m := make([]byte, 0, 13+1+len(suffix)+len(body))
	m = append(m, "ARC/1 beacon"...)
	m = append(m, byte(len(suffix)))
	m = append(m, suffix...)
	return append(m, body...)
}

// Encode returns the TXT content for b: Prefix followed by the base64url of
// the body and its signature. suffix is Suffix(zone).
func Encode(b *Beacon, suffix string, key ed25519.PrivateKey) (string, error) {
	body, err := b.appendBody(nil)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, signedMessage(suffix, body))
	out := make([]byte, 0, len(body)+len(sig))
	out = append(out, body...)
	out = append(out, sig...)
	return Prefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// Decode parses and verifies a TXT record's content against key, and checks
// that it is vouched for at now. suffix is Suffix(zone), which the signature
// covers; a record published under another name or zone is refused.
func Decode(content, suffix string, key ed25519.PublicKey, now time.Time) (*Beacon, error) {
	content = strings.TrimSpace(content)
	if !strings.HasPrefix(content, Prefix) {
		return nil, errPrefix
	}
	raw, err := base64.RawURLEncoding.DecodeString(content[len(Prefix):])
	if err != nil {
		return nil, errBase64
	}
	if len(raw) < 1+1+4+4+1+1+1+64 {
		return nil, errShort
	}
	body, sig := raw[:len(raw)-ed25519.SignatureSize], raw[len(raw)-ed25519.SignatureSize:]
	if !ed25519.Verify(key, signedMessage(suffix, body), sig) {
		return nil, errSignature
	}
	b, err := parseBody(body)
	if err != nil {
		return nil, err
	}
	if !b.NotAfter.After(now) {
		return nil, fmt.Errorf("%w: not_after %s", errTime, b.NotAfter.UTC().Format(time.RFC3339))
	}
	return b, nil
}

func (b *Beacon) appendBody(dst []byte) ([]byte, error) {
	if len(b.Relays) < 1 || len(b.Relays) > MaxRelays {
		return nil, fmt.Errorf("%w: %d relays", errLimits, len(b.Relays))
	}
	if len(b.Names) > MaxNames || len(b.Zones) < 1 || len(b.Zones) > MaxZones {
		return nil, fmt.Errorf("%w: %d names, %d zones", errLimits, len(b.Names), len(b.Zones))
	}
	var flags byte
	if b.DNSAvailable {
		flags |= 1
	}
	dst = append(dst, Version, flags)
	dst = binary.BigEndian.AppendUint32(dst, uint32(b.Published.Unix()))
	dst = binary.BigEndian.AppendUint32(dst, uint32(b.NotAfter.Unix()))
	dst = append(dst, byte(len(b.Relays)))
	for _, r := range b.Relays {
		a := r.Addr.Unmap()
		if !a.Is4() {
			return nil, fmt.Errorf("%w: %s", errAddr, r.Addr)
		}
		if len(r.Key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: key length %d", errEndpoint, len(r.Key))
		}
		if len(r.Endpoints) < 1 || len(r.Endpoints) > 3 {
			return nil, fmt.Errorf("%w: %d endpoints", errEndpoint, len(r.Endpoints))
		}
		dst = append(dst, a.AsSlice()...)
		dst = append(dst, r.Key...)
		dst = append(dst, byte(len(r.Endpoints)))
		for _, e := range r.Endpoints {
			dst = append(dst, byte(e.Kind))
			dst = binary.BigEndian.AppendUint16(dst, e.Port)
			if e.Kind == KindFront {
				if e.Domain == "" || len(e.Domain) > MaxName {
					return nil, fmt.Errorf("%w: front domain %q", errEndpoint, e.Domain)
				}
				dst = append(dst, byte(len(e.Domain)))
				dst = append(dst, e.Domain...)
			}
		}
	}
	dst = append(dst, byte(len(b.Names)))
	for _, n := range b.Names {
		if n == "" || len(n) > MaxName {
			return nil, fmt.Errorf("%w: cover name %q", errEndpoint, n)
		}
		dst = append(dst, byte(len(n)))
		dst = append(dst, n...)
	}
	dst = append(dst, byte(len(b.Zones)))
	for _, z := range b.Zones {
		if z == "" || len(z) > MaxName {
			return nil, fmt.Errorf("%w: zone %q", errEndpoint, z)
		}
		dst = append(dst, byte(len(z)))
		dst = append(dst, z...)
	}
	return dst, nil
}

func parseBody(body []byte) (*Beacon, error) {
	if len(body) == 0 || body[0] != Version {
		return nil, errVersion
	}
	r := reader{b: body[1:]}
	b := &Beacon{}
	flags := r.u8()
	b.DNSAvailable = flags&1 != 0
	b.Published = time.Unix(int64(r.u32()), 0)
	b.NotAfter = time.Unix(int64(r.u32()), 0)
	nr := int(r.u8())
	if nr < 1 || nr > MaxRelays {
		return nil, errLimits
	}
	for range nr {
		addr, ok := netip.AddrFromSlice(r.bytes(4))
		if !ok {
			return nil, errAddr
		}
		key := ed25519.PublicKey(r.bytes(ed25519.PublicKeySize))
		ne := int(r.u8())
		if ne < 1 || ne > 3 {
			return nil, errEndpoint
		}
		rel := Relay{Addr: addr, Key: key}
		for range ne {
			kind := EndpointKind(r.u8())
			e := Endpoint{Kind: kind, Port: r.u16()}
			switch kind {
			case KindUDP, KindTLS:
			case KindFront:
				e.Domain = string(r.bytes(int(r.u8())))
				if e.Domain == "" {
					return nil, errEndpoint
				}
			default:
				return nil, errEndpoint
			}
			rel.Endpoints = append(rel.Endpoints, e)
		}
		b.Relays = append(b.Relays, rel)
	}
	nn := int(r.u8())
	if nn > MaxNames {
		return nil, errLimits
	}
	for range nn {
		n := string(r.bytes(int(r.u8())))
		if n == "" {
			return nil, errEndpoint
		}
		b.Names = append(b.Names, n)
	}
	nz := int(r.u8())
	if nz < 1 || nz > MaxZones {
		return nil, errLimits
	}
	for range nz {
		z := string(r.bytes(int(r.u8())))
		if z == "" {
			return nil, errEndpoint
		}
		b.Zones = append(b.Zones, z)
	}
	if r.err || !r.done() {
		return nil, errLength
	}
	return b, nil
}

// reader reads a byte slice without panicking on short input.
type reader struct {
	b    []byte
	err  bool
	read int
}

func (r *reader) bytes(n int) []byte {
	if r.err || n < 0 || len(r.b)-r.read < n {
		r.err = true
		return nil
	}
	p := r.b[r.read : r.read+n]
	r.read += n
	return p
}

// done reports whether every byte was consumed.
func (r *reader) done() bool { return r.read == len(r.b) }

func (r *reader) u8() byte {
	if p := r.bytes(1); p != nil {
		return p[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if p := r.bytes(2); p != nil {
		return binary.BigEndian.Uint16(p)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if p := r.bytes(4); p != nil {
		return binary.BigEndian.Uint32(p)
	}
	return 0
}
