// Package gateway is the relay's view of the tunnel network (spec §17.2):
// it leases one virtual IPv4 address per session, authorizes clients, and
// routes packets from the relay's TUN interface to the session that owns
// the destination address.
package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

var (
	ErrPoolExhausted = errors.New("gateway: address pool exhausted")
	ErrBadCredential = errors.New("gateway: unknown credential")
	ErrWrongAccount  = errors.New("gateway: credential of another account")
	ErrWrongKey      = errors.New("gateway: credential bound to another device key")
	ErrRevoked       = errors.New("gateway: device revoked")
	// ErrNotServing: the relay does not hold the accounts lease, so it
	// cannot prove its accounts are current. It wraps session.ErrCapacity,
	// so the client is told the relay is full and retries.
	ErrNotServing = fmt.Errorf("gateway: not serving accounts: %w", session.ErrCapacity)
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
	// Gate, if set, is asked before every authorization: false refuses
	// it with ErrNotServing. A relay authenticating from an accounts
	// store passes its writer's Serving (self-service-accounts.md §3.2).
	Gate func() bool

	// HostAddrs are the relay host's own addresses outside the tunnel
	// network (its LAN or VPC address, say). Like the relay's tunnel
	// address, they are reachable only with RelayAccess, by IP forwarding
	// and by split TCP alike: the kernel would deliver either to the host
	// itself.
	HostAddrs []netip.Addr
	// Deny lists destinations no client may reach, by IP forwarding or by
	// split TCP: networks private to the operator, such as the relay's
	// VPC. HostAddrs take precedence, so an account with RelayAccess still
	// reaches the host's own address within a denied network.
	Deny []netip.Prefix
}

// A lease is a tunnel address and the account and device it was leased
// to. The session is nil until the session is established. A revoked
// lease's device no longer admits it; it is released when its session
// closes.
type lease struct {
	account *Account
	device  accounts.ID
	name    string // the device's
	session *session.RelaySession
	revoked bool
}

// A credential is what a token, by its hash, admits.
type credential struct {
	account *Account
	device  accounts.ID
	name    string
	key     []byte // the Noise static key it is bound to, if any
}

// A Revocation is a session the relay must close: its device was
// revoked, or the relay stopped serving accounts.
type Revocation struct {
	Session *session.RelaySession
	Code    wire.ErrorCode
	Err     error
}

// Gateway leases addresses and maps them to sessions. Authorize, Apply
// and the routing methods may be called from different goroutines.
type Gateway struct {
	cfg Config

	mu       sync.Mutex
	accounts map[accounts.ID]*Account // one per account for the gateway's life, updated in place
	creds    map[[32]byte]credential  // by token hash; replaced whole by Apply
	static   [][]byte                 // Config's plaintext tokens, for the front
	next     netip.Addr
	leased   map[netip.Addr]lease
	free     []netip.Addr
	revoke   []Revocation
	kick     chan struct{}
}

func New(cfg Config) (*Gateway, error) {
	if !cfg.Network.Addr().Is4() || cfg.Network.Bits() > 30 {
		return nil, errors.New("gateway: network must be an IPv4 prefix of /30 or larger")
	}
	accts := slices.Clone(cfg.Accounts)
	for i, t := range cfg.Tokens {
		accts = append(accts, Account{Name: fmt.Sprintf("token%d", i+1), Tokens: [][]byte{t}})
	}
	if err := validate(accts); err != nil {
		return nil, err
	}
	cfg.HostAddrs = slices.Clone(cfg.HostAddrs)
	for i, a := range cfg.HostAddrs {
		cfg.HostAddrs[i] = a.Unmap()
	}
	for _, p := range cfg.Deny {
		if !p.IsValid() || !p.Addr().Is4() {
			return nil, fmt.Errorf("gateway: deny prefix %v is not IPv4", p)
		}
	}
	g := &Gateway{cfg: cfg, accounts: map[accounts.ID]*Account{}, creds: map[[32]byte]credential{},
		next: cfg.Network.Masked().Addr().Next(), leased: map[netip.Addr]lease{}, kick: make(chan struct{}, 1)}
	for i := range accts {
		a := &accts[i]
		var id accounts.ID
		id[0], id[1], id[7] = byte(i>>8), byte(i), 0xff // static accounts' IDs, never random ones' concern
		g.accounts[id] = a
		for j, t := range a.Tokens {
			g.creds[accounts.TokenHash(t)] = credential{account: a, device: deviceID(id, j), name: fmt.Sprintf("token%d", j+1)}
			g.static = append(g.static, t)
		}
	}
	return g, nil
}

func deviceID(account accounts.ID, i int) accounts.ID {
	account[6] = byte(i + 1)
	return account
}

// Tokens returns the tokens of Config's accounts, for admission checks
// made before a session exists (the HTTPS front's upgrade). Accounts
// from Apply keep only token hashes, so they have none here.
func (g *Gateway) Tokens() [][]byte { return g.static }

// Apply replaces the gateway's accounts and devices with st's. An
// account keeps its *Account across calls (by ID), so leases, refreshes
// and isolation are unaffected. Leases whose device or account st no
// longer has are revoked: their sessions are queued for closing (see
// Revocations), and Bind refuses those not yet established.
func (g *Gateway) Apply(st *accounts.State) {
	g.mu.Lock()
	defer g.mu.Unlock()
	seen := map[accounts.ID]bool{}
	for _, ra := range st.Accounts {
		seen[ra.ID] = true
		a := g.accounts[ra.ID]
		if a == nil {
			a = &Account{}
			g.accounts[ra.ID] = a
		}
		a.Name, a.RelayAccess, a.Tokens = ra.Name, ra.RelayAccess, nil
	}
	for id := range g.accounts {
		if !seen[id] {
			delete(g.accounts, id)
		}
	}
	creds := map[[32]byte]credential{}
	devices := map[accounts.ID]bool{}
	for _, d := range st.Devices {
		creds[d.TokenHash] = credential{account: g.accounts[d.Account], device: d.ID, name: d.Name, key: d.Key}
		devices[d.ID] = true
	}
	g.creds, g.static = creds, nil
	for addr, l := range g.leased {
		if !l.revoked && !devices[l.device] {
			g.revokeLocked(addr, l, wire.CodeAuthFailed, ErrRevoked)
		}
	}
}

// Suspend revokes every lease, because the relay stopped serving
// accounts (it lost the accounts lease): every session is queued for
// closing with UNAUTHORIZED, and its client reconnects, to whichever
// relay serves the accounts.
func (g *Gateway) Suspend(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for addr, l := range g.leased {
		if !l.revoked {
			g.revokeLocked(addr, l, wire.CodeUnauthorized, fmt.Errorf("%w: %v", ErrNotServing, err))
		}
	}
}

func (g *Gateway) revokeLocked(addr netip.Addr, l lease, code wire.ErrorCode, err error) {
	l.revoked = true
	g.leased[addr] = l
	if l.session != nil {
		g.revoke = append(g.revoke, Revocation{Session: l.session, Code: code, Err: err})
		select {
		case g.kick <- struct{}{}:
		default:
		}
	}
}

// Revocations signals when sessions are queued for closing; TakeRevocations
// returns them.
func (g *Gateway) Revocations() <-chan struct{} { return g.kick }

// TakeRevocations returns and forgets the sessions queued for closing.
func (g *Gateway) TakeRevocations() []Revocation {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.revoke
	g.revoke = nil
	return r
}

// Authorize implements session.Authorizer: it checks the credential and,
// on first authentication, leases an address to the credential's
// account. A lease keeps the account it was leased to, so a refresh must
// present a credential of that same account.
//
// A credential bound to a device key admits only a client with that key
// (self-service-accounts.md §3.4).
func (g *Gateway) Authorize(token, clientStatic []byte, prior *wire.AuthResult) (wire.AuthResult, error) {
	if g.cfg.Gate != nil && !g.cfg.Gate() {
		return wire.AuthResult{}, ErrNotServing
	}
	hash := accounts.TokenHash(token)
	g.mu.Lock()
	c, ok := g.creds[hash]
	g.mu.Unlock()
	if !ok || c.account == nil {
		return wire.AuthResult{}, ErrBadCredential
	}
	if c.key != nil && !bytes.Equal(c.key, clientStatic) {
		return wire.AuthResult{}, ErrWrongKey
	}
	if prior != nil {
		g.mu.Lock()
		l, ok := g.leased[netip.AddrFrom4(prior.IPv4)]
		g.mu.Unlock()
		if !ok || l.account != c.account || l.revoked {
			return wire.AuthResult{}, ErrWrongAccount
		}
		return wire.AuthResult{}, nil
	}
	addr, err := g.lease(c)
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

// lease reserves an address that is neither the relay's own, the network
// address, nor the broadcast address.
func (g *Gateway) lease(c credential) (netip.Addr, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	l := lease{account: c.account, device: c.device, name: c.name}
	if n := len(g.free); n > 0 {
		addr := g.free[n-1]
		g.free = g.free[:n-1]
		g.leased[addr] = l
		return addr, nil
	}
	for g.cfg.Network.Contains(g.next) {
		addr := g.next
		g.next = addr.Next()
		if addr == g.cfg.Network.Addr() || !g.cfg.Network.Contains(addr.Next()) {
			continue // the relay itself, or the broadcast address
		}
		g.leased[addr] = l
		return addr, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// Bind records the session that owns its leased address. It returns
// false if the lease was revoked after it was granted (its device was
// revoked, or the relay stopped serving), and the caller closes s.
func (g *Gateway) Bind(s *session.RelaySession) bool {
	a := netip.AddrFrom4(s.Config().IPv4)
	g.mu.Lock()
	defer g.mu.Unlock()
	l, ok := g.leased[a]
	if !ok || l.revoked {
		return false
	}
	l.session = s
	g.leased[a] = l
	return true
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

// DeviceName returns the name of the device an address is leased to, or
// "" if it is not leased.
func (g *Gateway) DeviceName(addr netip.Addr) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.leased[addr].name
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
	if !ok || l.revoked {
		return nil
	}
	if g.cfg.Network.Contains(src) && src != g.cfg.Network.Addr() {
		if from, ok := g.leased[src]; !ok || from.account != l.account {
			return nil
		}
	}
	return l.session
}

// AllowForward reports whether the relay may write a packet from session s
// to the TUN. The session already checked that the packet's source is its
// lease (§11), so the policy follows the session's lease, not the packet:
// see allowForward.
func (g *Gateway) AllowForward(s *session.RelaySession, pkt []byte) bool {
	from := netip.AddrFrom4(s.Config().IPv4)
	return !g.isRevoked(from) && g.allowForward(from, pkt)
}

// isRevoked reports whether the lease of addr is revoked, or gone.
func (g *Gateway) isRevoked(addr netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	l, ok := g.leased[addr]
	return !ok || l.revoked
}

// allowForward applies AllowForward's policy to a packet from the client
// leasing from. In the tunnel network, other accounts' addresses and the
// reserved addresses are refused, and the relay's own address needs
// RelayAccess; elsewhere, allowDst decides.
func (g *Gateway) allowForward(from netip.Addr, pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if g.cfg.Network.Contains(dst) {
		return g.allowTunnel(from, dst)
	}
	return g.allowDst(from, dst)
}

// AllowDial reports whether the relay may connect a stream from session s
// to dst (spec §11.3), under the policy IP forwarding has. Split TCP
// terminates streams at the relay, so a stream to another client is
// refused even within an account.
func (g *Gateway) AllowDial(s *session.RelaySession, dst netip.AddrPort) bool {
	from := netip.AddrFrom4(s.Config().IPv4)
	return !g.isRevoked(from) && g.allowDial(from, dst)
}

func (g *Gateway) allowDial(from netip.Addr, dst netip.AddrPort) bool {
	a := dst.Addr()
	switch {
	case !a.Is4() || dst.Port() == 0:
		return false
	case g.cfg.Network.Contains(a):
		return a == g.cfg.Network.Addr() && g.allowTunnel(from, a)
	}
	return g.allowDst(from, a)
}

// allowDst reports whether the client leasing from may reach dst, an IPv4
// address outside the tunnel network: never loopback, unspecified,
// multicast, broadcast, or link-local addresses (cloud metadata services
// among them), the relay host's own addresses only with RelayAccess, and
// nothing in Deny.
func (g *Gateway) allowDst(from, dst netip.Addr) bool {
	switch {
	case dst.IsLoopback(), dst.IsUnspecified(), dst.IsMulticast(), dst.IsLinkLocalUnicast(),
		dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return false
	case slices.Contains(g.cfg.HostAddrs, dst):
		g.mu.Lock()
		defer g.mu.Unlock()
		l, ok := g.leased[from]
		return ok && l.account.RelayAccess
	}
	for _, p := range g.cfg.Deny {
		if p.Contains(dst) {
			return false
		}
	}
	return true
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
