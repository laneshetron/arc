// Package gateway is the relay's view of the tunnel network (spec §17.2):
// it leases one virtual IPv4 address per session, authorizes clients, and
// routes packets from the relay's TUN interface to the session that owns
// the destination address.
package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/invite"
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

	// Enrollment refusals (self-service-accounts.md §3.4). An unknown
	// invite, or a wrong secret, is refused like a wrong token.
	ErrUnknownInvite = fmt.Errorf("%w: unknown invite", ErrBadCredential)
	ErrInviteUsed    = errors.New("gateway: invite already redeemed by another device")
	ErrInviteExpired = errors.New("gateway: invite expired")
	ErrDeviceCap     = fmt.Errorf("gateway: account at its device cap: %w", session.ErrCapacity)
)

// maxEnrolling bounds the enrollments waiting for their commits, or for
// their clients to hear the outcome. Each invite has at most one commit
// in flight.
const maxEnrolling = 64

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
	// It is called with the gateway locked, so it must not block or call
	// into the Gateway.
	Gate func() bool
	// Commit, if set, commits a change to the accounts store, which the
	// gateway applies (Apply) before Commit returns: a relay
	// authenticating from a store passes its writer's Commit. Without
	// it, the gateway refuses enrollment credentials.
	Commit func(ctx context.Context, change func(*accounts.State) error) error
	// Now is the clock for invite expiry; nil uses time.Now.
	Now func() time.Time
	// InviteKey, with Commit, lets key-bound devices of accounts that
	// allow it mint invites (self-service-accounts.md §3.6): the relay
	// secret their IDs and secrets are derived from. Without it, no
	// device is offered invites.
	InviteKey []byte
	// Log, if set, records each invite a device mints.
	Log *slog.Logger

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
	mint    bool   // the device may mint invites
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

	st         *accounts.State // the last applied, for enrollments; nil with static accounts
	enrolling  map[enrollKey]*enrollment
	minting    map[accounts.ID]*minting // by device: at most one commit in flight each
	committing int                      // minting commits not yet done
}

// A minting is a device's invite request waiting for its commit.
type minting struct {
	request accounts.ID
	started time.Time
	done    bool
	err     error
}

// maxMinting bounds the minting commits in flight.
const maxMinting = 64

// An enrollment is a redemption waiting for its commit, keyed by what
// makes a repeat of it the same redemption.
type enrollKey struct {
	invite accounts.ID
	token  [32]byte // hash
	key    [32]byte // the client's Noise static key
}

type enrollment struct {
	started time.Time
	done    bool
	err     error
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
	g := &Gateway{cfg: cfg, accounts: map[accounts.ID]*Account{}, creds: map[[32]byte]credential{}, enrolling: map[enrollKey]*enrollment{}, minting: map[accounts.ID]*minting{},
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
		creds[d.TokenHash] = credential{account: g.accounts[d.Account], device: d.ID, name: d.Name, key: d.Key,
			mint: len(g.cfg.InviteKey) == accounts.InviteKeySize && g.cfg.Commit != nil && st.MayMint(d)}
		devices[d.ID] = true
	}
	g.logMintedLocked(st)
	g.creds, g.static, g.st = creds, nil, st
	for addr, l := range g.leased {
		if !l.revoked && !devices[l.device] {
			g.revokeLocked(addr, l, wire.CodeAuthFailed, ErrRevoked)
		}
	}
}

// logMintedLocked logs the invites devices minted that st has and the
// last applied state lacks: the audit of minting follows the state the
// relay adopts, so a mint whose write was confirmed only later (say, by
// resolving an indeterminate write) is logged too, as are mints by
// another relay before this one took over.
func (g *Gateway) logMintedLocked(st *accounts.State) {
	if g.st == nil || g.cfg.Log == nil {
		return
	}
	for _, i := range st.Invites {
		if i.By.IsZero() || g.st.InviteByID(i.ID) != nil {
			continue
		}
		account, device := "", ""
		if a := st.AccountByID(i.Account); a != nil {
			account = a.Name
		}
		if d := st.DeviceByID(i.By); d != nil {
			device = d.Name
		}
		g.cfg.Log.Info("invite minted", "account", account, "device", device, "invite", i.ID.String(), "expires", i.Expires)
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
func (g *Gateway) Authorize(credential, clientStatic []byte, prior *wire.AuthResult) (wire.AuthResult, error) {
	a, err := g.AuthorizeSession(credential, clientStatic, prior)
	return a.Result, err
}

// AuthorizeSession is the session.Authorizer: Authorize, and for an
// enrollment credential (self-service-accounts.md §3.4) the device it
// enrolled, for ENROLLED. An enrollment's commit runs apart from the
// caller, the relay's session loop: until it is done, the AUTH is left
// unanswered (session.ErrAuthPending), and the client's repeat of it
// gets the answer.
func (g *Gateway) AuthorizeSession(credential, clientStatic []byte, prior *wire.AuthResult) (session.Authorization, error) {
	// One lock from the gate to the lease, so that an Apply or Suspend
	// either comes first, and refuses, or comes after, and revokes the
	// lease this grants.
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfg.Gate != nil && !g.cfg.Gate() {
		return session.Authorization{}, ErrNotServing
	}
	if invite.IsEnrollment(credential) {
		return g.enrollLocked(credential, clientStatic, prior)
	}
	r, err := g.authorizeLocked(credential, clientStatic, prior)
	return session.Authorization{Result: r}, err
}

func (g *Gateway) authorizeLocked(token, clientStatic []byte, prior *wire.AuthResult) (wire.AuthResult, error) {
	hash := accounts.TokenHash(token)
	c, ok := g.creds[hash]
	if testHookAuthorize != nil {
		testHookAuthorize()
	}
	if !ok || c.account == nil {
		return wire.AuthResult{}, ErrBadCredential
	}
	if c.key != nil && !bytes.Equal(c.key, clientStatic) {
		return wire.AuthResult{}, ErrWrongKey
	}
	if prior != nil {
		l, ok := g.leased[netip.AddrFrom4(prior.IPv4)]
		if !ok || l.account != c.account || l.revoked {
			return wire.AuthResult{}, ErrWrongAccount
		}
		return wire.AuthResult{}, nil
	}
	addr, err := g.leaseLocked(c)
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
	if c.mint {
		r.Features |= wire.FeatureInvites
	}
	return r, nil
}

// testHookAuthorize, if set, runs in Authorize between finding the
// credential and leasing an address.
var testHookAuthorize func()

// leaseLocked reserves an address that is neither the relay's own, the
// network address, nor the broadcast address.
func (g *Gateway) leaseLocked(c credential) (netip.Addr, error) {
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

func (g *Gateway) now() time.Time {
	if g.cfg.Now != nil {
		return g.cfg.Now()
	}
	return time.Now()
}

// enrollLocked authorizes an enrollment credential: a repeat of a
// redemption already made is authorized as the device's token; a new one
// starts its commit and is pending.
func (g *Gateway) enrollLocked(credential, clientStatic []byte, prior *wire.AuthResult) (session.Authorization, error) {
	e, err := invite.ParseEnrollment(credential)
	if err != nil || g.st == nil || g.cfg.Commit == nil || len(clientStatic) != 32 {
		return session.Authorization{}, ErrUnknownInvite
	}
	now := g.now()
	g.sweepEnrolling(now)
	i, err := g.st.CheckInvite(accounts.ID(e.ID), e.Secret[:])
	if err != nil {
		return session.Authorization{}, ErrUnknownInvite
	}
	key := enrollKey{invite: i.ID, token: accounts.TokenHash(e.Token), key: [32]byte(clientStatic)}
	if d := g.st.RedeemedBy(i, e.Token, clientStatic); d != nil {
		// Made: the client authenticates as the device, and hears which.
		delete(g.enrolling, key)
		r, err := g.authorizeLocked(e.Token, clientStatic, prior)
		if err != nil {
			return session.Authorization{}, err
		}
		return session.Authorization{Result: r, Enrolled: &wire.Enrolled{DeviceID: d.ID, Name: d.Name}}, nil
	}
	if p := g.enrolling[key]; p != nil {
		if !p.done {
			return session.Authorization{}, session.ErrAuthPending
		}
		delete(g.enrolling, key)
		if p.err != nil {
			return session.Authorization{}, g.enrollError(p.err, i)
		}
	}
	switch {
	case !i.Redeemed.IsZero():
		return session.Authorization{}, g.enrollError(accounts.ErrInviteUsed, i)
	case !now.Before(i.Expires):
		return session.Authorization{}, g.enrollError(accounts.ErrInviteExpired, i)
	case prior != nil:
		return session.Authorization{}, ErrWrongAccount
	}
	// One commit per invite at a time: only one redemption can succeed,
	// so another device's waits for the outcome instead of taking a slot
	// (someone holding an invite can't fill the slots with new keys).
	// Finished ones for the invite are dropped; repeated, they are
	// decided afresh, against the invite as the store now has it.
	for k, o := range g.enrolling {
		if k.invite != i.ID {
			continue
		}
		if !o.done {
			return session.Authorization{}, session.ErrAuthPending
		}
		delete(g.enrolling, k)
	}
	if len(g.enrolling) >= maxEnrolling {
		return session.Authorization{}, fmt.Errorf("gateway: too many enrollments in progress: %w", session.ErrCapacity)
	}
	p := &enrollment{started: now}
	g.enrolling[key] = p
	token, static := e.Token, [32]byte(clientStatic)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := g.cfg.Commit(ctx, func(st *accounts.State) error {
			_, err := accounts.Redeem(st, accounts.ID(e.ID), e.Secret[:], token, static[:], e.Name, now)
			return err
		})
		g.mu.Lock()
		p.done, p.err = true, err
		g.mu.Unlock()
	}()
	return session.Authorization{}, session.ErrAuthPending
}

// enrollError is how the client hears a redemption refused.
func (g *Gateway) enrollError(err error, i *accounts.Invite) error {
	account := ""
	if a := g.st.AccountByID(i.Account); a != nil {
		account = a.Name
	}
	switch {
	case errors.Is(err, accounts.ErrInviteUsed):
		return &session.AuthError{Code: wire.CodeInviteUsed, Err: fmt.Errorf("%w (invite %v, account %s)", ErrInviteUsed, i.ID, account)}
	case errors.Is(err, accounts.ErrInviteExpired):
		return &session.AuthError{Code: wire.CodeInviteExpired, Err: fmt.Errorf("%w (invite %v, account %s)", ErrInviteExpired, i.ID, account)}
	case errors.Is(err, accounts.ErrInviteUnknown):
		return ErrUnknownInvite
	case errors.Is(err, accounts.ErrDeviceCap):
		return fmt.Errorf("%w (account %s)", ErrDeviceCap, account)
	}
	// Not committed (the store is unreachable, say): the client retries.
	return fmt.Errorf("gateway: enrollment not committed: %v: %w", err, session.ErrCapacity)
}

// sweepEnrolling forgets finished enrollments whose clients never came
// back for the answer.
func (g *Gateway) sweepEnrolling(now time.Time) {
	for k, p := range g.enrolling {
		if p.done && now.Sub(p.started) > 5*time.Minute {
			delete(g.enrolling, k)
		}
	}
}

// MintInvite answers a session's INVITE_REQUEST (self-service-accounts.md
// §3.6), as session.RelayConfig.Invites: an invite to the session's
// account, minted by a commit that runs apart from the caller, the
// relay's session loop. Until the commit is done, and while the relay is
// not serving, the request is left unanswered (false), and the client's
// repeat of it gets the answer. A repeat of a request already minted is
// answered with the same invite, from the store's record.
func (g *Gateway) MintInvite(s *session.RelaySession, req wire.InviteRequest) (wire.Invite, bool) {
	return g.mint(netip.AddrFrom4(s.Config().IPv4), s, req)
}

// mint is MintInvite for the session s leasing addr.
func (g *Gateway) mint(addr netip.Addr, s *session.RelaySession, req wire.InviteRequest) (wire.Invite, bool) {
	refuse := func(code wire.ErrorCode) (wire.Invite, bool) { return wire.Invite{Status: code}, true }
	g.mu.Lock()
	defer g.mu.Unlock()
	l, ok := g.leased[addr]
	if !ok || l.session != s || l.revoked || g.st == nil || g.cfg.Commit == nil {
		return refuse(wire.CodeUnauthorized)
	}
	if g.cfg.Gate != nil && !g.cfg.Gate() {
		return wire.Invite{}, false
	}
	now := g.now()
	g.sweepMinting(now)
	device, request := l.device, accounts.ID(req.RequestID)
	if p := g.minting[device]; p != nil {
		if !p.done {
			return wire.Invite{}, false // this request's commit, or another of the device's
		}
		delete(g.minting, device)
		if p.request == request && p.err != nil && mintRefusal(p.err) != 0 {
			return refuse(mintRefusal(p.err))
		}
	}
	// The committed state decides: a repeat is answered from its
	// record, a refusal at once; anything else is minted.
	i, secret, minted, err := accounts.MintInvite(g.st.Clone(), g.cfg.InviteKey, device, request, now)
	switch {
	case err != nil && mintRefusal(err) != 0:
		return refuse(mintRefusal(err))
	case err != nil:
		return wire.Invite{}, false
	case !minted:
		return wire.Invite{ID: i.ID, Secret: secret, Expires: uint32(i.Expires.Unix())}, true
	case g.committing >= maxMinting:
		return wire.Invite{}, false
	}
	p := &minting{request: request, started: now}
	g.minting[device] = p
	g.committing++
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := g.cfg.Commit(ctx, func(st *accounts.State) error {
			_, _, minted, err := accounts.MintInvite(st, g.cfg.InviteKey, device, request, now)
			if err == nil && !minted {
				return errNoChange
			}
			return err
		})
		if errors.Is(err, errNoChange) {
			err = nil
		}
		// Apply, given the committed state, logs the mint.
		g.mu.Lock()
		p.done, p.err = true, err
		g.committing--
		g.mu.Unlock()
	}()
	return wire.Invite{}, false
}

// errNoChange ends a commit with nothing to write.
var errNoChange = errors.New("gateway: nothing to commit")

// mintRefusal is the INVITE status for a minting error, or 0 for one the
// client should retry (the store unreachable, say).
func mintRefusal(err error) wire.ErrorCode {
	switch {
	case errors.Is(err, accounts.ErrNotPermitted):
		return wire.CodeUnauthorized
	case errors.Is(err, accounts.ErrInviteExpired), errors.Is(err, accounts.ErrInviteKeyChanged):
		return wire.CodeInviteExpired
	case errors.Is(err, accounts.ErrDeviceCap), errors.Is(err, accounts.ErrInviteCap), errors.Is(err, accounts.ErrLineageFull):
		return wire.CodeCapacity
	}
	return 0
}

// sweepMinting forgets finished requests whose clients never came back
// for the answer.
func (g *Gateway) sweepMinting(now time.Time) {
	for k, p := range g.minting {
		if p.done && now.Sub(p.started) > 5*time.Minute {
			delete(g.minting, k)
		}
	}
}
