package session

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/wire"
)

// Authorizer validates a client credential. On first authentication it
// returns the session configuration to send in AUTH_RESULT, including the
// leased address. On a refresh (§9.4) only the verdict matters: the session
// keeps its configuration, so an Authorizer that leases addresses must not
// lease another. A non-nil error or a nonzero Status rejects the client.
type Authorizer func(credential, clientStatic []byte, refresh bool) (wire.AuthResult, error)

// RelayConfig configures a relay endpoint.
type RelayConfig struct {
	Static      crypto.StaticKey
	ResetSecret [32]byte // persist across restarts (§14.7)
	Authorize   Authorizer

	// Cookies are required once this many handshakes are pending
	// (default 64), or always if AlwaysRequireCookie is set (§9.3).
	CookieThreshold     int
	AlwaysRequireCookie bool
	MaxPending          int // default 4096; INITs beyond this are dropped
	ResetsPerSecond     int // stateless reset rate limit; default 100
	IdleTimeout         time.Duration
	Rand                io.Reader
}

// RelayDatagram is an outgoing packet for a client address.
type RelayDatagram struct {
	Addr netip.AddrPort
	Data []byte
}

// RelayEvent is reported by Relay.PollEvent: one of SessionEstablished,
// SessionIP, or SessionClosed.
type RelayEvent interface{ relayEvent() }

type SessionEstablished struct{ Session *RelaySession }

// SessionIP carries an IP packet from a client whose source address has
// been checked against the session's lease.
type SessionIP struct {
	Session *RelaySession
	Packet  []byte
}

type SessionClosed struct {
	Session *RelaySession
	Err     error
}

func (SessionEstablished) relayEvent() {}
func (SessionIP) relayEvent()          {}
func (SessionClosed) relayEvent()      {}

// RelayStats counts relay-wide events.
type RelayStats struct {
	Handshakes        uint64 // HANDSHAKE_INITs that cost Diffie-Hellman operations
	HandshakeFailures uint64
	CookiesSent       uint64
	RespRetransmits   uint64
	ResetsSent        uint64
	SpoofedDropped    uint64
	Migrations        uint64 // validated address changes on existing paths
}

type initKey struct {
	addr netip.AddrPort
	cid  wire.CID
	msg1 [wire.NoiseMsg1Len]byte
}

// Relay terminates ARC sessions arriving on its carriers. It is not safe
// for concurrent use.
type Relay struct {
	cfg      RelayConfig
	cookies  *crypto.CookieGenerator
	sessions map[wire.CID]*RelaySession // every live relay CID, all paths
	live     []*RelaySession            // each live session once, oldest first
	inits    map[initKey]*RelaySession
	pending  int

	resetTokens float64
	resetRefill time.Time

	out    []RelayDatagram
	events []RelayEvent
	stats  RelayStats
}

// RelaySession is one client's session on the relay.
type RelaySession struct {
	relay        *Relay
	state        State
	conn         *conn
	clientStatic []byte
	credential   []byte
	result       wire.AuthResult
	created      time.Time
	resp         []byte
	initKey      initKey
	nextPathID   uint32
	lastUplink   *path // where the client most recently sent from
}

func NewRelay(cfg RelayConfig, now time.Time) *Relay {
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.CookieThreshold == 0 {
		cfg.CookieThreshold = 64
	}
	if cfg.MaxPending == 0 {
		cfg.MaxPending = 4096
	}
	if cfg.ResetsPerSecond == 0 {
		cfg.ResetsPerSecond = 100
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	return &Relay{
		cfg:         cfg,
		cookies:     crypto.NewCookieGenerator(cfg.Rand, now),
		sessions:    make(map[wire.CID]*RelaySession),
		inits:       make(map[initKey]*RelaySession),
		resetTokens: float64(cfg.ResetsPerSecond),
		resetRefill: now,
	}
}

func (r *Relay) Stats() RelayStats { return r.stats }

// Sessions returns the number of live sessions, including pending ones.
func (r *Relay) Sessions() int { return len(r.live) }

// HandlePacket processes one packet received from a client address.
func (r *Relay) HandlePacket(now time.Time, from netip.AddrPort, b []byte) {
	t, err := wire.PeekType(b)
	if err != nil {
		return
	}
	switch t {
	case wire.TypeHandshakeInit:
		r.handleInit(now, from, b)
	case wire.TypeData:
		r.handleData(now, from, b)
	}
}

func (r *Relay) handleInit(now time.Time, from netip.AddrPort, b []byte) {
	init, err := wire.ParseHandshakeInit(b)
	if err != nil {
		return
	}
	key := initKey{addr: from, cid: init.SenderCID, msg1: init.NoiseMsg1}
	if s := r.inits[key]; s != nil {
		// A retransmitted INIT: resend the cached response without new DH.
		r.stats.RespRetransmits++
		r.out = append(r.out, RelayDatagram{Addr: from, Data: s.resp})
		return
	}
	if r.pending >= r.cfg.MaxPending {
		return
	}
	if r.cfg.AlwaysRequireCookie || r.pending >= r.cfg.CookieThreshold {
		if !r.cookies.Verify(now, from, init.SenderCID, init.Cookie) {
			reply := wire.CookieReply{DestCID: init.SenderCID, Cookie: r.cookies.Make(now, from, init.SenderCID)}
			r.stats.CookiesSent++
			r.out = append(r.out, RelayDatagram{Addr: from, Data: reply.Append(nil)})
			return
		}
	}

	relayCID, ok := r.newCID()
	if !ok {
		return
	}
	r.stats.Handshakes++
	res, err := crypto.RespondHandshake(crypto.RelayConfig{Static: r.cfg.Static, Rand: r.cfg.Rand},
		&init, relayCID, crypto.ResetToken(r.cfg.ResetSecret, relayCID))
	if err != nil {
		r.stats.HandshakeFailures++
		return
	}
	s := &RelaySession{
		relay:        r,
		state:        StateAuthenticating,
		clientStatic: res.ClientStatic,
		created:      now,
		resp:         res.Resp.Append(nil),
		initKey:      key,
		nextPathID:   1,
	}
	s.conn = newConn(res.Keys, now)
	s.conn.primary, s.conn.emit = s.primary, s.emit
	p0 := newPath(0, relayCID, init.SenderCID, now)
	// The handshake round trip validated the client's address.
	p0.joined, p0.validated, p0.addr = true, true, from
	s.conn.addPath(p0)
	s.lastUplink = p0
	r.sessions[relayCID] = s
	r.live = append(r.live, s)
	r.inits[key] = s
	r.pending++
	r.out = append(r.out, RelayDatagram{Addr: from, Data: s.resp})
}

func (r *Relay) newCID() (wire.CID, bool) {
	var cid wire.CID
	for range 4 {
		if _, err := io.ReadFull(r.cfg.Rand, cid[:]); err != nil {
			return cid, false
		}
		if _, taken := r.sessions[cid]; !taken {
			return cid, true
		}
	}
	return cid, false
}

func (r *Relay) handleData(now time.Time, from netip.AddrPort, b []byte) {
	h, aad, ct, err := wire.ParseData(b)
	if err != nil {
		return
	}
	s := r.sessions[h.DestCID]
	if s == nil {
		r.maybeReset(now, from, h.DestCID, len(b))
		return
	}
	p := s.conn.byCID[h.DestCID]
	frames, err := s.conn.open(now, p, h, aad, ct)
	if err == ErrIntegrityLimit {
		r.closeSession(now, s, err, false)
		return
	}
	if err != nil {
		return
	}
	s.onAddress(now, p, from, len(b))

	for _, f := range frames {
		switch f := f.(type) {
		case wire.Auth:
			if !s.onAuth(now, f.Credential) {
				return
			}
		case wire.Ack:
			s.conn.onAck(now, &f)
		case wire.IPPacket:
			s.deliver(f.Packet, true)
		case wire.IPFragment:
			if s.state == StateActive {
				if pkt := s.conn.receiveFragment(now, f); pkt != nil {
					s.deliver(pkt, false)
				}
			}
		case wire.PathJoin:
			if !s.onJoin(now, p, f) {
				return
			}
		case wire.PathChallenge:
			s.conn.transmit(now, p, []wire.Frame{wire.PathResponse{Data: f.Data}})
		case wire.PathResponse:
			s.onResponse(now, p, from, f)
		case wire.PathAbandon:
			if q := s.conn.path(f.PathID); q != nil && q.joined && s.joinedPaths() > 1 {
				s.removePath(q)
			}
		case wire.CloseFrame:
			r.closeSession(now, s, &PeerClosedError{Code: f.Code}, false)
			return
		}
	}
	s.conn.flush(now)
}

// onAddress tracks where an authenticated packet came from. A new path
// learns its address; a validated path seeing a new address starts
// validating it without moving the downlink (§14.5).
func (s *RelaySession) onAddress(now time.Time, p *path, from netip.AddrPort, n int) {
	if p.joined && p.validated {
		s.lastUplink = p
	}
	switch {
	case !p.validated:
		if p.addr != from {
			p.addr, p.recvBytes, p.sentBytes = from, 0, 0
		}
		p.recvBytes += n
	case from == p.addr:
		return
	case p.candActive && from == p.cand:
		p.candRecv += n
		if now.Sub(p.candSentAt) >= p.rtt.pto() {
			s.challengeCandidate(now, p)
		}
	default:
		p.cand, p.candActive, p.candRecv, p.candSent = from, true, n, 0
		if _, err := io.ReadFull(s.relay.cfg.Rand, p.candChallenge[:]); err != nil {
			p.candActive = false
			return
		}
		s.challengeCandidate(now, p)
	}
}

func (s *RelaySession) challengeCandidate(now time.Time, p *path) {
	p.candSentAt = now
	s.conn.transmitTo(now, p, []wire.Frame{wire.PathChallenge{Data: p.candChallenge}}, true)
}

// onJoin handles PATH_JOIN on a slot path and reports whether the session
// survives.
func (s *RelaySession) onJoin(now time.Time, p *path, f wire.PathJoin) bool {
	if p.id == 0 || s.state != StateActive {
		return true
	}
	if p.joined {
		if p.remoteCID != f.CID {
			s.conn.queue(wire.PathAbandon{PathID: p.id, Code: wire.CodeProtocolViolation})
			s.removePath(p)
		}
		return true // a retransmitted JOIN; the challenge is already pending
	}
	if _, err := io.ReadFull(s.relay.cfg.Rand, p.challenge[:]); err != nil {
		return true
	}
	p.remoteCID, p.joined = f.CID, true
	p.control = append(p.control, wire.PathChallenge{Data: p.challenge})
	s.issueSlots()
	return true
}

func (s *RelaySession) onResponse(now time.Time, p *path, from netip.AddrPort, f wire.PathResponse) {
	switch {
	case !p.validated && p.joined && f.Data == p.challenge && from == p.addr:
		p.validated = true
		p.control = slices.DeleteFunc(p.control, pathBound)
		s.conn.probe(now, p)
	case p.candActive && f.Data == p.candChallenge && from == p.cand:
		p.addr, p.candActive = from, false
		s.relay.stats.Migrations++
	}
}

// issueSlots keeps spare NEW_PATH slots outstanding (§14.3).
func (s *RelaySession) issueSlots() {
	r := s.relay
	spare := 0
	for _, p := range s.conn.paths {
		if !p.joined {
			spare++
		}
	}
	for spare < spareSlots && len(s.conn.paths) < maxPaths {
		cid, ok := r.newCID()
		if !ok {
			return
		}
		p := newPath(s.nextPathID, cid, wire.CID{}, time.Time{})
		s.nextPathID++
		token := crypto.ResetToken(r.cfg.ResetSecret, cid)
		s.conn.addPath(p)
		r.sessions[cid] = s
		s.conn.queue(wire.NewPath{PathID: p.id, CID: cid, ResetToken: token})
		spare++
	}
}

func (s *RelaySession) removePath(p *path) {
	s.conn.removePath(p)
	delete(s.relay.sessions, p.localCID)
	if s.lastUplink == p {
		s.lastUplink = nil
	}
}

// primary picks the downlink path: the path the client most recently sent
// on while it is healthy, otherwise the best healthy path (§15.2).
func (s *RelaySession) primary(now time.Time) *path {
	if s.lastUplink != nil && s.lastUplink.healthy(now, s.conn.keepalive) {
		return s.lastUplink
	}
	return s.conn.bestPath(now)
}

// maybeReset answers a DATA packet for an unknown CID with a rate-limited
// stateless reset (§14.7).
func (r *Relay) maybeReset(now time.Time, to netip.AddrPort, cid wire.CID, triggerLen int) {
	if triggerLen <= wire.StatelessResetLen {
		return
	}
	rate := float64(r.cfg.ResetsPerSecond)
	r.resetTokens = min(rate, r.resetTokens+now.Sub(r.resetRefill).Seconds()*rate)
	r.resetRefill = now
	if r.resetTokens < 1 {
		return
	}
	r.resetTokens--
	reset := wire.StatelessReset{CID: cid, Token: crypto.ResetToken(r.cfg.ResetSecret, cid)}
	r.stats.ResetsSent++
	r.out = append(r.out, RelayDatagram{Addr: to, Data: reset.Append(nil)})
}

// onAuth handles an AUTH frame and reports whether the session survives.
func (s *RelaySession) onAuth(now time.Time, credential []byte) bool {
	r := s.relay
	if s.state == StateActive && bytes.Equal(credential, s.credential) {
		s.conn.queue(s.result) // duplicate AUTH: repeat the answer
		return true
	}
	result, err := r.cfg.Authorize(credential, s.clientStatic, s.state == StateActive)
	if err != nil || result.Status != 0 {
		failure := wire.AuthResult{Status: uint8(wire.CodeAuthFailed)}
		s.conn.transmit(now, s.conn.path(0), []wire.Frame{failure, wire.CloseFrame{Code: wire.CodeAuthFailed}})
		r.closeSession(now, s, ErrAuthFailed, false)
		return false
	}
	s.credential = bytes.Clone(credential)
	if s.state == StateActive {
		s.conn.queue(s.result) // refresh: the lease is unchanged
		return true
	}
	s.result = result
	s.state = StateActive
	r.leavePending(s)
	s.conn.queue(result)
	s.conn.probeSize = int(result.TunMTU) + dataOverhead
	if result.KeepaliveMS > 0 {
		s.conn.keepalive = time.Duration(result.KeepaliveMS) * time.Millisecond
	}
	s.conn.probe(now, s.conn.path(0))
	s.issueSlots()
	r.events = append(r.events, SessionEstablished{Session: s})
	return true
}

// deliver checks a client packet's inner source address against the lease
// (§11) and reports it.
func (s *RelaySession) deliver(pkt []byte, mustCopy bool) {
	if s.state != StateActive {
		return
	}
	if len(pkt) < 20 || pkt[0]>>4 != 4 || [4]byte(pkt[12:16]) != s.result.IPv4 {
		s.relay.stats.SpoofedDropped++
		return
	}
	if mustCopy {
		pkt = copyBytes(pkt)
	}
	s.relay.events = append(s.relay.events, SessionIP{Session: s, Packet: pkt})
}

func (r *Relay) leavePending(s *RelaySession) {
	if _, ok := r.inits[s.initKey]; ok {
		delete(r.inits, s.initKey)
		r.pending--
	}
}

func (r *Relay) closeSession(now time.Time, s *RelaySession, err error, notify bool) {
	if s.state == StateClosed {
		return
	}
	if notify {
		if p := s.primary(now); p != nil {
			s.conn.transmit(now, p, []wire.Frame{wire.CloseFrame{Code: wire.CodeNoError}})
		}
	}
	r.leavePending(s)
	for _, p := range s.conn.paths {
		delete(r.sessions, p.localCID)
	}
	r.live = slices.DeleteFunc(r.live, func(q *RelaySession) bool { return q == s })
	s.state = StateClosed
	r.events = append(r.events, SessionClosed{Session: s, Err: err})
}

// emit sends a packet to the path's address, or to its candidate address,
// enforcing the 3x anti-amplification limit toward any address that has
// not been validated (§14.4).
func (s *RelaySession) emit(p *path, b []byte, toCandidate bool) {
	to := p.addr
	switch {
	case toCandidate:
		if p.candSent+len(b) > amplificationFactor*p.candRecv {
			s.conn.stats.AmplificationDrops++
			return
		}
		p.candSent += len(b)
		to = p.cand
	case !p.validated:
		if p.sentBytes+len(b) > amplificationFactor*p.recvBytes {
			s.conn.stats.AmplificationDrops++
			return
		}
		p.sentBytes += len(b)
	}
	s.relay.out = append(s.relay.out, RelayDatagram{Addr: to, Data: b})
}

func (s *RelaySession) State() State            { return s.state }
func (s *RelaySession) Config() wire.AuthResult { return s.result }
func (s *RelaySession) ClientStatic() []byte    { return s.clientStatic }
func (s *RelaySession) Stats() Stats            { return s.conn.stats }

// Paths describes the session's joined paths.
func (s *RelaySession) Paths(now time.Time) []PathInfo { return s.conn.pathInfo(now) }

// Addr returns the client address of the current downlink path.
func (s *RelaySession) Addr(now time.Time) netip.AddrPort {
	if p := s.primary(now); p != nil {
		return p.addr
	}
	return netip.AddrPort{}
}

// SendIP tunnels one IP packet to the client. The packet is copied.
func (s *RelaySession) SendIP(now time.Time, pkt []byte) error {
	switch {
	case s.state == StateClosed:
		return ErrClosed
	case s.state != StateActive:
		return ErrNotActive
	case len(pkt) > int(s.result.TunMTU):
		return ErrPacketTooLarge
	}
	if err := wire.ValidateIPPacket(pkt); err != nil {
		return err
	}
	return s.conn.sendIP(now, pkt)
}

// Close ends the session, telling the client.
func (s *RelaySession) Close(now time.Time) { s.relay.closeSession(now, s, ErrClosed, true) }

// Tick runs expired timers for every session.
func (r *Relay) Tick(now time.Time) {
	for _, s := range slices.Clone(r.live) {
		switch {
		case s.state == StateAuthenticating && !now.Before(s.created.Add(HandshakeTimeout)):
			r.closeSession(now, s, ErrAuthFailed, false)
		case !now.Before(s.conn.lastRecv().Add(r.cfg.IdleTimeout)):
			r.closeSession(now, s, ErrIdleTimeout, false)
		default:
			for _, p := range slices.Clone(s.conn.paths) {
				if p.joined && !now.Before(p.lastRecv.Add(PathTimeout)) && s.joinedPaths() > 1 {
					s.removePath(p)
				}
			}
			s.conn.onTimers(now)
		}
	}
}

func (s *RelaySession) joinedPaths() int {
	n := 0
	for _, p := range s.conn.paths {
		if p.joined {
			n++
		}
	}
	return n
}

// NextDeadline returns when Tick should next be called, or zero if no
// timer is pending.
func (r *Relay) NextDeadline() time.Time {
	var d time.Time
	for _, s := range r.live {
		d = earliest(d, s.conn.nextDeadline(), s.conn.lastRecv().Add(r.cfg.IdleTimeout))
		if s.state == StateAuthenticating {
			d = earliest(d, s.created.Add(HandshakeTimeout))
		}
		if s.joinedPaths() > 1 {
			for _, p := range s.conn.paths {
				if p.joined {
					d = earliest(d, p.lastRecv.Add(PathTimeout))
				}
			}
		}
	}
	return d
}

// PollTransmit returns the next outgoing datagram.
func (r *Relay) PollTransmit() (RelayDatagram, bool) {
	if len(r.out) == 0 {
		return RelayDatagram{}, false
	}
	d := r.out[0]
	r.out = r.out[1:]
	return d, true
}

// PollEvent returns the next event.
func (r *Relay) PollEvent() (RelayEvent, bool) {
	if len(r.events) == 0 {
		return nil, false
	}
	e := r.events[0]
	r.events = r.events[1:]
	return e, true
}
