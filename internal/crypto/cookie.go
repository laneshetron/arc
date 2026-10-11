package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// CookieRotation is how often the relay replaces its cookie secret (§9.3).
const CookieRotation = 120 * time.Second

// ComputeCookie returns HMAC-SHA256(secret, "ARC/1 cookie" || src_ip ||
// u16_be(src_port) || sender_cid)[0:16]. IPv4-mapped IPv6 addresses are
// treated as IPv4.
func ComputeCookie(secret [32]byte, src netip.AddrPort, senderCID wire.CID) [wire.CookieLen]byte {
	m := hmac.New(sha256.New, secret[:])
	m.Write([]byte("ARC/1 cookie"))
	m.Write(src.Addr().Unmap().AsSlice())
	m.Write(binary.BigEndian.AppendUint16(nil, src.Port()))
	m.Write(senderCID[:])
	var c [wire.CookieLen]byte
	copy(c[:], m.Sum(nil))
	return c
}

// CookieGenerator issues and verifies cookies under a rotating secret,
// accepting cookies made with the previous secret (§9.3).
type CookieGenerator struct {
	rand      io.Reader
	cur, prev [32]byte
	hasPrev   bool
	rotated   time.Time
}

// NewCookieGenerator creates a generator. A nil reader uses crypto/rand.
func NewCookieGenerator(r io.Reader, now time.Time) *CookieGenerator {
	if r == nil {
		r = rand.Reader
	}
	g := &CookieGenerator{rand: r, rotated: now}
	g.fill(&g.cur)
	return g
}

func (g *CookieGenerator) fill(k *[32]byte) {
	if _, err := io.ReadFull(g.rand, k[:]); err != nil {
		panic("crypto: random source failed: " + err.Error())
	}
}

func (g *CookieGenerator) rotate(now time.Time) {
	switch elapsed := now.Sub(g.rotated); {
	case elapsed >= 2*CookieRotation: // both secrets are stale
		g.fill(&g.cur)
		g.hasPrev, g.rotated = false, now
	case elapsed >= CookieRotation:
		g.prev, g.hasPrev = g.cur, true
		g.fill(&g.cur)
		g.rotated = g.rotated.Add(CookieRotation)
	}
}

// Make returns the cookie for a client address and sender CID.
func (g *CookieGenerator) Make(now time.Time, src netip.AddrPort, senderCID wire.CID) [wire.CookieLen]byte {
	g.rotate(now)
	return ComputeCookie(g.cur, src, senderCID)
}

// Verify checks a cookie in constant time against the current and previous
// secrets.
func (g *CookieGenerator) Verify(now time.Time, src netip.AddrPort, senderCID wire.CID, cookie [wire.CookieLen]byte) bool {
	g.rotate(now)
	want := ComputeCookie(g.cur, src, senderCID)
	ok := hmac.Equal(want[:], cookie[:])
	if g.hasPrev {
		old := ComputeCookie(g.prev, src, senderCID)
		ok = hmac.Equal(old[:], cookie[:]) || ok
	}
	return ok
}

// ResetToken returns HMAC-SHA256(secret, "ARC/1 reset" || cid)[0:16]
// (§14.7). The relay persists the secret so it can still produce tokens
// after a restart.
func ResetToken(secret [32]byte, cid wire.CID) wire.Token {
	m := hmac.New(sha256.New, secret[:])
	m.Write([]byte("ARC/1 reset"))
	m.Write(cid[:])
	var t wire.Token
	copy(t[:], m.Sum(nil))
	return t
}

// ResetTokenEqual compares reset tokens in constant time.
func ResetTokenEqual(a, b wire.Token) bool { return hmac.Equal(a[:], b[:]) }
