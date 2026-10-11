package session

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/wire"
)

// Authorizer validates a client credential and returns the session
// configuration to send in AUTH_RESULT, including the leased address. A
// non-nil error or a nonzero Status rejects the client.
type Authorizer func(credential, clientStatic []byte) (wire.AuthResult, error)

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
	sessions map[wire.CID]*RelaySession
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
	addr         netip.AddrPort
	clientStatic []byte
	credential   []byte
	result       wire.AuthResult
	created      time.Time
	resp         []byte
	initKey      initKey
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
func (r *Relay) Sessions() int { return len(r.sessions) }

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
		addr:         from,
		clientStatic: res.ClientStatic,
		created:      now,
		resp:         res.Resp.Append(nil),
		initKey:      key,
	}
	s.conn = newConn(res.Keys, newPath(0, relayCID, init.SenderCID, now), now, s.emit)
	r.sessions[relayCID] = s
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
	frames, err := s.conn.open(now, s.conn.path0, h, aad, ct)
	if err == ErrIntegrityLimit {
		r.closeSession(now, s, err, false)
		return
	}
	if err != nil {
		return
	}
	// The downlink stays on the validated address. Validating a changed
	// address (NAT rebinding, §14.5) arrives with multipath support.
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
		case wire.CloseFrame:
			r.closeSession(now, s, &PeerClosedError{Code: f.Code}, false)
			return
		}
	}
	s.conn.flush(now)
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
	result, err := r.cfg.Authorize(credential, s.clientStatic)
	if err != nil || result.Status != 0 {
		failure := wire.AuthResult{Status: uint8(wire.CodeAuthFailed)}
		s.conn.transmit(now, s.conn.path0, []wire.Frame{failure, wire.CloseFrame{Code: wire.CodeAuthFailed}})
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
		s.conn.transmit(now, s.conn.path0, []wire.Frame{wire.CloseFrame{Code: wire.CodeNoError}})
	}
	r.leavePending(s)
	delete(r.sessions, s.conn.path0.localCID)
	s.state = StateClosed
	r.events = append(r.events, SessionClosed{Session: s, Err: err})
}

func (s *RelaySession) emit(_ *path, b []byte) {
	s.relay.out = append(s.relay.out, RelayDatagram{Addr: s.addr, Data: b})
}

func (s *RelaySession) State() State            { return s.state }
func (s *RelaySession) Config() wire.AuthResult { return s.result }
func (s *RelaySession) ClientStatic() []byte    { return s.clientStatic }
func (s *RelaySession) Addr() netip.AddrPort    { return s.addr }
func (s *RelaySession) Stats() Stats            { return s.conn.stats }

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
	s.conn.sendIP(now, pkt)
	return nil
}

// Close ends the session, telling the client.
func (s *RelaySession) Close(now time.Time) { s.relay.closeSession(now, s, ErrClosed, true) }

// Tick runs expired timers for every session.
func (r *Relay) Tick(now time.Time) {
	for _, s := range r.sessions {
		switch {
		case s.state == StateAuthenticating && !now.Before(s.created.Add(HandshakeTimeout)):
			r.closeSession(now, s, ErrAuthFailed, false)
		case !now.Before(s.conn.path0.lastRecv.Add(r.cfg.IdleTimeout)):
			r.closeSession(now, s, ErrIdleTimeout, false)
		default:
			s.conn.onTimers(now)
		}
	}
}

// NextDeadline returns when Tick should next be called, or zero if no
// timer is pending.
func (r *Relay) NextDeadline() time.Time {
	var d time.Time
	for _, s := range r.sessions {
		d = earliest(d, s.conn.nextDeadline(), s.conn.path0.lastRecv.Add(r.cfg.IdleTimeout))
		if s.state == StateAuthenticating {
			d = earliest(d, s.created.Add(HandshakeTimeout))
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
