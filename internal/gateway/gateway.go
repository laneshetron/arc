// Package gateway is the relay's view of the tunnel network (spec §17.2):
// it leases one virtual IPv4 address per session, authorizes clients, and
// routes packets from the relay's TUN interface to the session that owns
// the destination address.
package gateway

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"slices"
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
	// Accounts hold the accepted credentials and isolate their clients
	// from one another. Production deployments need short-lived,
	// revocable credentials instead of static tokens (spec O7).
	Accounts []Account
	// Tokens is shorthand for accounts of one token each, with no relay
	// access, named token1, token2, ...
	Tokens [][]byte
}

// A lease is a tunnel address and the account it was leased to. The
// session is nil until the session is established.
type lease struct {
	account *Account
	session *session.RelaySession
}

// Gateway leases addresses and maps them to sessions. Authorize and the
// routing methods may be called from different goroutines.
type Gateway struct {
	cfg      Config
	accounts []Account

	mu     sync.Mutex
	next   netip.Addr
	leased map[netip.Addr]lease
	free   []netip.Addr
}

func New(cfg Config) (*Gateway, error) {
	if !cfg.Network.Addr().Is4() || cfg.Network.Bits() > 30 {
		return nil, errors.New("gateway: network must be an IPv4 prefix of /30 or larger")
	}
	accounts := slices.Clone(cfg.Accounts)
	for i, t := range cfg.Tokens {
		accounts = append(accounts, Account{Name: fmt.Sprintf("token%d", i+1), Tokens: [][]byte{t}})
	}
	if err := validate(accounts); err != nil {
		return nil, err
	}
	return &Gateway{cfg: cfg, accounts: accounts, next: cfg.Network.Masked().Addr().Next(), leased: map[netip.Addr]lease{}}, nil
}

// Tokens returns every account's tokens, for admission checks made
// before a session exists (the HTTPS front's upgrade).
func (g *Gateway) Tokens() [][]byte {
	var out [][]byte
	for _, a := range g.accounts {
		out = append(out, a.Tokens...)
	}
	return out
}

// Authorize implements session.Authorizer: it checks the credential and,
// on first authentication, leases an address to the credential's
// account. A lease keeps the account it was leased to: a refresh with
// another account's credential does not move it.
func (g *Gateway) Authorize(credential, _ []byte, refresh bool) (wire.AuthResult, error) {
	a := g.account(credential)
	if a == nil {
		return wire.AuthResult{}, ErrBadCredential
	}
	if refresh {
		return wire.AuthResult{}, nil
	}
	addr, err := g.lease(a)
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

// account returns the account holding credential, or nil. It compares
// every token, so its timing does not depend on which one matched.
func (g *Gateway) account(credential []byte) *Account {
	match := -1
	for i, a := range g.accounts {
		for _, t := range a.Tokens {
			match = subtle.ConstantTimeSelect(subtle.ConstantTimeCompare(t, credential), i, match)
		}
	}
	if match < 0 {
		return nil
	}
	return &g.accounts[match]
}

// lease reserves an address that is neither the relay's own, the network
// address, nor the broadcast address.
func (g *Gateway) lease(a *Account) (netip.Addr, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n := len(g.free); n > 0 {
		addr := g.free[n-1]
		g.free = g.free[:n-1]
		g.leased[addr] = lease{account: a}
		return addr, nil
	}
	for g.cfg.Network.Contains(g.next) {
		addr := g.next
		g.next = addr.Next()
		if addr == g.cfg.Network.Addr() || !g.cfg.Network.Contains(addr.Next()) {
			continue // the relay itself, or the broadcast address
		}
		g.leased[addr] = lease{account: a}
		return addr, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// Bind records the session that owns its leased address.
func (g *Gateway) Bind(s *session.RelaySession) {
	a := netip.AddrFrom4(s.Config().IPv4)
	g.mu.Lock()
	defer g.mu.Unlock()
	if l, ok := g.leased[a]; ok {
		l.session = s
		g.leased[a] = l
	}
}

// Release returns a closed session's address to the pool.
func (g *Gateway) Release(s *session.RelaySession) {
	a := netip.AddrFrom4(s.Config().IPv4)
	g.mu.Lock()
	defer g.mu.Unlock()
	if l, ok := g.leased[a]; ok && l.session == s {
		delete(g.leased, a)
		g.free = append(g.free, a)
	}
}

// AccountName returns the name of the account an address is leased to,
// or "" if it is not leased.
func (g *Gateway) AccountName(addr netip.Addr) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if l, ok := g.leased[addr]; ok {
		return l.account.Name
	}
	return ""
}

// Lookup returns the session leasing the packet's destination address, or
// nil. Packets for other addresses are not forwarded to any client
// (§17.2), and neither are packets from another account's client: the
// kernel routes client-to-client traffic back out of the TUN, and this is
// where the relay stops it crossing accounts. The relay's own address
// reaches every client, as replies and ICMP errors must.
func (g *Gateway) Lookup(pkt []byte) *session.RelaySession {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	g.mu.Lock()
	defer g.mu.Unlock()
	l, ok := g.leased[dst]
	if !ok {
		return nil
	}
	if g.cfg.Network.Contains(src) && src != g.cfg.Network.Addr() {
		if from, ok := g.leased[src]; !ok || from.account != l.account {
			return nil
		}
	}
	return l.session
}

// AllowForward reports whether the relay may write a client's packet to
// the TUN. The session already checked that the source is its lease
// (§11); this checks the destination against the lease's account: other
// accounts' addresses and the tunnel network's reserved addresses are
// refused, and the relay's own address needs RelayAccess. Packets leaving
// the tunnel network are always allowed.
func (g *Gateway) AllowForward(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if !g.cfg.Network.Contains(dst) {
		return true
	}
	return g.allowTunnel(netip.AddrFrom4([4]byte(pkt[12:16])), dst)
}

// allowTunnel reports whether the client leasing src may reach dst, an
// address in the tunnel network.
func (g *Gateway) allowTunnel(src, dst netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	from, ok := g.leased[src]
	if !ok {
		return false
	}
	if dst == g.cfg.Network.Addr() {
		return from.account.RelayAccess
	}
	to, ok := g.leased[dst]
	return ok && to.account == from.account
}

// AllowDial reports whether the relay may connect a stream from the
// client leasing src to dst (spec §11.3), applying the limits IP
// forwarding has: IPv4 only, no loopback, unspecified, multicast,
// broadcast, or link-local destinations, and in the tunnel network only
// what AllowForward allows. Split TCP terminates streams at the relay, so
// a stream to another client is refused even within an account.
func (g *Gateway) AllowDial(src netip.Addr, dst netip.AddrPort) bool {
	a := dst.Addr()
	switch {
	case !a.Is4() || dst.Port() == 0:
		return false
	case a.IsLoopback(), a.IsUnspecified(), a.IsMulticast(), a.IsLinkLocalUnicast(),
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return false
	case g.cfg.Network.Contains(a):
		return a == g.cfg.Network.Addr() && g.allowTunnel(src, a)
	}
	return true
}
