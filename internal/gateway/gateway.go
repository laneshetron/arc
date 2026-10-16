// Package gateway is the relay's view of the tunnel network (spec §17.2):
// it leases one virtual IPv4 address per session, authorizes clients, and
// routes packets from the relay's TUN interface to the session that owns
// the destination address.
package gateway

import (
	"crypto/subtle"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

var (
	ErrPoolExhausted = errors.New("gateway: address pool exhausted")
	ErrBadCredential = errors.New("gateway: unknown credential")
)

// Config describes the tunnel network.
type Config struct {
	// Network is the relay's own tunnel address and prefix, e.g.
	// 10.77.0.1/16. Clients are leased the other host addresses in it.
	Network   netip.Prefix
	TunMTU    uint16
	DNS       netip.Addr // resolver to hand to clients; zero for none
	Keepalive time.Duration
	Idle      time.Duration
	// Tokens are the accepted credentials. Production deployments need
	// short-lived, revocable credentials instead (spec O7).
	Tokens [][]byte
}

// Gateway leases addresses and maps them to sessions. Authorize and the
// routing methods may be called from different goroutines.
type Gateway struct {
	cfg Config

	mu     sync.Mutex
	next   netip.Addr
	leased map[netip.Addr]*session.RelaySession
	free   []netip.Addr
}

func New(cfg Config) (*Gateway, error) {
	if !cfg.Network.Addr().Is4() || cfg.Network.Bits() > 30 {
		return nil, errors.New("gateway: network must be an IPv4 prefix of /30 or larger")
	}
	return &Gateway{cfg: cfg, next: cfg.Network.Masked().Addr().Next(), leased: map[netip.Addr]*session.RelaySession{}}, nil
}

// Authorize implements session.Authorizer: it checks the credential and,
// on first authentication, leases an address.
func (g *Gateway) Authorize(credential, _ []byte, refresh bool) (wire.AuthResult, error) {
	if !g.validToken(credential) {
		return wire.AuthResult{}, ErrBadCredential
	}
	if refresh {
		return wire.AuthResult{}, nil
	}
	addr, err := g.lease()
	if err != nil {
		return wire.AuthResult{}, err
	}
	r := wire.AuthResult{
		IPv4:        addr.As4(),
		Prefix4:     uint8(g.cfg.Network.Bits()),
		TunMTU:      g.cfg.TunMTU,
		KeepaliveMS: uint32(g.cfg.Keepalive.Milliseconds()),
		IdleMS:      uint32(g.cfg.Idle.Milliseconds()),
	}
	if g.cfg.DNS.Is4() {
		r.DNSv4 = g.cfg.DNS.As4()
	}
	return r, nil
}

func (g *Gateway) validToken(credential []byte) bool {
	ok := 0
	for _, t := range g.cfg.Tokens {
		ok |= subtle.ConstantTimeCompare(t, credential)
	}
	return ok == 1
}

// lease reserves an address that is neither the relay's own, the network
// address, nor the broadcast address.
func (g *Gateway) lease() (netip.Addr, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n := len(g.free); n > 0 {
		a := g.free[n-1]
		g.free = g.free[:n-1]
		g.leased[a] = nil
		return a, nil
	}
	for g.cfg.Network.Contains(g.next) {
		a := g.next
		g.next = a.Next()
		if a == g.cfg.Network.Addr() || !g.cfg.Network.Contains(a.Next()) {
			continue // the relay itself, or the broadcast address
		}
		g.leased[a] = nil
		return a, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// Bind records the session that owns its leased address.
func (g *Gateway) Bind(s *session.RelaySession) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.leased[netip.AddrFrom4(s.Config().IPv4)] = s
}

// Release returns a closed session's address to the pool.
func (g *Gateway) Release(s *session.RelaySession) {
	a := netip.AddrFrom4(s.Config().IPv4)
	g.mu.Lock()
	defer g.mu.Unlock()
	if owner, ok := g.leased[a]; ok && owner == s {
		delete(g.leased, a)
		g.free = append(g.free, a)
	}
}

// Lookup returns the session leasing the packet's destination address, or
// nil. Packets for other addresses are not forwarded to any client (§17.2).
func (g *Gateway) Lookup(pkt []byte) *session.RelaySession {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.leased[dst]
}

// AllowDial reports whether the relay may connect a client's stream to dst
// (spec §11.3), applying the limits IP forwarding has: IPv4 only, no
// loopback, unspecified, multicast, broadcast, or link-local
// destinations, and nothing in the tunnel network except the relay's own
// address, which clients reach as IP traffic too.
func (g *Gateway) AllowDial(dst netip.AddrPort) bool {
	a := dst.Addr()
	switch {
	case !a.Is4() || dst.Port() == 0:
		return false
	case a.IsLoopback(), a.IsUnspecified(), a.IsMulticast(), a.IsLinkLocalUnicast(),
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return false
	case g.cfg.Network.Contains(a):
		return a == g.cfg.Network.Addr()
	}
	return true
}
