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
	MaxPending          int // default 4096; cookie-validated newcomers may replace the oldest pending session
	MaxSessions         int // default 1024; authenticated sessions only
	HandshakesPerSecond int // default 256; global DH admission rate and burst
	HandshakesPerSource int // default 8; per-IP DH admission rate and burst
	ResetsPerSecond     int // stateless reset rate limit; default 100
	IdleTimeout         time.Duration
	Rand                io.Reader

	// NoFEC declines forward error correction (§11.2): clients neither
	// protect their uplink nor have the relay protect their downlink.
	NoFEC bool

	// NoRedundancy declines to send downlink traffic on two paths when a
	// client asks (§11.1), which doubles the relay's traffic for that
	// client. Without the feature advertised, clients send uplink copies
	// neither.
	NoRedundancy bool

	// NoStreams declines streams (§11.3): the relay does not connect TCP
	// streams for clients. The caller must otherwise answer each
	// StreamOpened, connecting or resetting the stream.
	NoStreams bool
}

// RelayDatagram is an outgoing packet for a client address.
type RelayDatagram struct {
	Addr netip.AddrPort
	Data []byte
}

// RelayEvent is reported by Relay.PollEvent: SessionEstablished,
// SessionClosed, StreamOpened, or RelayStreamUpdate. IP packets from
// clients come from Relay.PollIP.
type RelayEvent interface{ relayEvent() }

type SessionEstablished struct{ Session *RelaySession }

type SessionClosed struct {
	Session *RelaySession
	Err     error
}

// StreamOpened asks the relay to connect a client's stream to Dst (§11.3).
// Bytes the client already sent wait in the stream until read.
type StreamOpened struct {
	Session *RelaySession
	ID      uint32
	Dst     netip.AddrPort
}

// RelayStreamUpdate reports news on a stream, as StreamUpdate does for
// the client.
type RelayStreamUpdate struct {
	Session *RelaySession
	ID      uint32
}

func (SessionEstablished) relayEvent() {}
func (SessionClosed) relayEvent()      {}
func (StreamOpened) relayEvent()       {}
func (RelayStreamUpdate) relayEvent()  {}

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
	// retired holds CIDs of paths removed from sessions that are still
	// live. Packets for them are dropped rather than reset: the client may
	// not have heard of the removal yet, and a reset ends the whole session.
	retired map[wire.CID]bool
	live    []*RelaySession // each live session once, oldest first
	inits   map[initKey]*RelaySession
	pending int

	resetTokens float64
	resetRefill time.Time

	out       []RelayDatagram
	events    []RelayEvent
	ips       []relayIP // kept apart from events to avoid boxing per packet
	stats     RelayStats
	admission handshakeAdmission
}

type relayIP struct {
	s   *RelaySession
	pkt []byte
}

// RelaySession is one client's session on the relay.
type RelaySession struct {
	relay         *Relay
	state         State
	conn          *conn
	clientStatic  []byte
	credential    []byte
	result        wire.AuthResult
	created       time.Time
	resp          []byte
	initKey       initKey
	nextPathID    uint32
	lastUplink    *path  // where the client most recently sent from
	redundancySeq uint32 // REDUNDANCY seq last applied
	fecSeq        uint32 // FEC seq last applied
	fecSet        bool
	retiredCIDs   []wire.CID // this session's entries in Relay.retired, oldest first
	redundancySet bool
	flows         flowTable // downlink path per flow: where its uplink last arrived
}

func NewRelay(cfg RelayConfig, now time.Time) *Relay {
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.CookieThreshold == 0 {
		cfg.CookieThreshold = 64
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 4096
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 1024
	}
	if cfg.HandshakesPerSecond <= 0 {
		cfg.HandshakesPerSecond = 256
	}
	if cfg.HandshakesPerSource <= 0 {
		cfg.HandshakesPerSource = 8
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
		retired:     make(map[wire.CID]bool),
		inits:       make(map[initKey]*RelaySession),
		resetTokens: float64(cfg.ResetsPerSecond),
		resetRefill: now,
	}
}

func (r *Relay) Stats() RelayStats { return r.stats }

// Sessions returns the number of live sessions, including pending ones.
func (r *Relay) Sessions() int { return len(r.live) }

// LiveSessions returns the sessions that are not closed, for status
// reporting. The slice is a copy; the sessions are not.
func (r *Relay) LiveSessions() []*RelaySession { return slices.Clone(r.live) }

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
	if len(r.live)-r.pending >= r.cfg.MaxSessions {
		return
	}
	source := from.Addr().Unmap()
	cookieValid := false
	if r.cfg.AlwaysRequireCookie || r.pending >= r.cfg.CookieThreshold || r.pending >= r.cfg.MaxPending || r.admission.needsCookie(source) {
		cookieValid = r.cookies.Verify(now, from, init.SenderCID, init.Cookie)
		if !cookieValid {
			reply := wire.CookieReply{DestCID: init.SenderCID, Cookie: r.cookies.Make(now, from, init.SenderCID)}
			r.stats.CookiesSent++
			r.out = append(r.out, RelayDatagram{Addr: from, Data: reply.Append(nil)})
			return
		}
	}

	// Charge every expensive attempt, including ones whose Noise message
	// fails. Failed handshakes do not increase pending and cannot be used
	// as the only measure of cryptographic work under load.
	if !r.admission.allow(now, source, r.cfg.HandshakesPerSecond, r.cfg.HandshakesPerSource, cookieValid) {
		return
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
	if r.pending >= r.cfg.MaxPending {
		// Only cookie-validated, valid Noise handshakes can replace an
		// unauthenticated session. Active sessions are never evicted.
		for _, old := range r.live {
			if old.state == StateAuthenticating {
				r.closeSession(now, old, ErrHandshakeTimeout, false)
				break
			}
		}
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
	s.conn.primary, s.conn.pathFor, s.conn.emit = s.primary, s.pathFor, s.emit
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
		if !r.retired[h.DestCID] {
			r.maybeReset(now, from, h.DestCID, len(b))
		}
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
	s.probeIfStale(now, p)

	for _, f := range frames {
		switch f := f.(type) {
		case wire.Auth:
			if !s.onAuth(now, f.Credential) {
				return
			}
		case wire.Ack:
			s.conn.onAck(now, &f)
		case wire.IPPacket:
			s.onUplink(p)
			s.deliver(now, p, f.Packet, true)
		case wire.IPDatagram:
			s.onUplink(p)
			if s.result.Features&(wire.FeatureRedundancy|wire.FeatureFEC) != 0 && s.conn.receiveDatagram(f) {
				s.deliver(now, p, f.Packet, true)
				for _, pkt := range s.conn.fecSource(now, f.DatagramID, f.Packet) {
					s.deliver(now, p, pkt, true)
				}
			}
		case wire.FECRepair:
			if s.result.Features&wire.FeatureFEC != 0 {
				for _, pkt := range s.conn.fecRepair(now, f) {
					s.deliver(now, p, pkt, true)
				}
			}
		case wire.FEC:
			s.onFEC(f)
		case wire.StreamOpen:
			s.onUplink(p)
			s.conn.onStreamOpen(f)
		case wire.Stream:
			s.onUplink(p)
			if !s.conn.onStream(f) {
				s.violation(now)
				return
			}
		case wire.MaxStreamData:
			s.conn.onMaxStreamData(f)
		case wire.MaxData:
			s.conn.onMaxData(f)
		case wire.StreamReset:
			if !s.conn.onStreamReset(f) {
				s.violation(now)
				return
			}
		case wire.Redundancy:
			s.onRedundancy(f)
		case wire.IPFragment:
			s.onUplink(p)
			if s.state == StateActive {
				if pkt := s.conn.receiveFragment(now, f); pkt != nil {
					s.deliver(now, p, pkt, false)
					for _, rec := range s.conn.fecSource(now, f.DatagramID, pkt) {
						s.deliver(now, p, rec, true)
					}
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

// onRedundancy applies a client's downlink redundancy request, ignoring
// requests older than one already applied (§11.1).
func (s *RelaySession) onRedundancy(f wire.Redundancy) {
	if s.state != StateActive || s.result.Features&wire.FeatureRedundancy == 0 ||
		s.redundancySet && f.Seq <= s.redundancySeq {
		return
	}
	s.redundancySeq, s.redundancySet = f.Seq, true
	s.conn.redundant = f.Mode == wire.RedundancyDuplicate
}

// pathFor returns the downlink path for an IP packet: the path its flow's
// uplink last arrived on while that is healthy, otherwise the session's
// downlink path (§15.2).
func (s *RelaySession) pathFor(now time.Time, pkt []byte) *path {
	prim := s.primary(now)
	if prim == nil || !s.conn.multipath() {
		return prim
	}
	if k, ok := flowKeyOf(pkt, false); ok {
		if p, ok := s.flows.get(now, k); ok && p.healthy(now, s.conn.keepalive) {
			return p
		}
	}
	return prim
}

// onFEC applies a client's downlink FEC request, ignoring requests older
// than one already applied (§11.2).
func (s *RelaySession) onFEC(f wire.FEC) {
	if s.state != StateActive || s.result.Features&wire.FeatureFEC == 0 || s.fecSet && f.Seq <= s.fecSeq {
		return
	}
	s.fecSeq, s.fecSet = f.Seq, true
	s.conn.fec.mode = f.Mode
}

// onUplink notes that the client sent IP traffic on p. Downlink traffic
// follows it there (§15.2), so the client's choice of path, which accounts
// for loss in both directions, steers the downlink as well. Keepalives and
// probes on other paths do not move the downlink.
func (s *RelaySession) onUplink(p *path) {
	if p.joined && p.validated {
		s.lastUplink = p
	}
}

// probeIfStale pings a path that hears from the client while packets sent
// on it have gone unanswered for the suspect limit. The relay sends nothing
// acknowledged on an idle path, so packets lost in an outage would stay
// outstanding and keep the path suspect, but for a moment after each of the
// client's keepalives, until they expire; the PING's acknowledgement
// declares them lost by time threshold. At most one PING per PTO.
func (s *RelaySession) probeIfStale(now time.Time, p *path) {
	if s.state != StateActive || !p.joined || !p.validated {
		return
	}
	t0, ok := p.sent.oldestOutstanding()
	if !ok || now.Sub(t0) < suspectPTOs*p.rtt.pto() || now.Sub(p.lastSend) < p.rtt.pto() {
		return
	}
	s.conn.transmit(now, p, []wire.Frame{wire.Ping{}})
}

// onAddress tracks where an authenticated packet came from. A new path
// learns its address; a validated path seeing a new address starts
// validating it without moving the downlink (§14.5).
func (s *RelaySession) onAddress(now time.Time, p *path, from netip.AddrPort, n int) {
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
	s.conn.transmitTo(now, p, []wire.Frame{wire.PathChallenge{Data: p.candChallenge}}, ipPayload{}, true)
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
	p.remoteCID, p.joined, p.skippedAt = f.CID, true, time.Time{}
	p.control = append(p.control, wire.PathChallenge{Data: p.challenge})
	// The client opens slots lowest first, so an unjoined slot below this
	// one was probably lost to it (its NEW_PATH arrived too late, or
	// never). But JOINs travel over independent carriers and may arrive
	// out of order, so a lower slot's JOIN may still be in flight: stop
	// counting such slots as spares, so issueSlots replaces them, and
	// retire them in Tick only if no JOIN arrives within the path timeout.
	for _, q := range s.conn.paths {
		if !q.joined && q.id < p.id && q.skippedAt.IsZero() {
			q.skippedAt = now
		}
	}
	s.issueSlots(now)
	return s.state != StateClosed
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
func (s *RelaySession) issueSlots(now time.Time) {
	r := s.relay
	spare := 0
	for _, p := range s.conn.paths {
		if !p.joined && p.skippedAt.IsZero() {
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
		if !s.conn.addPath(p) {
			r.closeSession(now, s, ErrPathLimit, true)
			return
		}
		r.sessions[cid] = s
		s.conn.queue(wire.NewPath{PathID: p.id, CID: cid, ResetToken: token})
		spare++
	}
}

func (s *RelaySession) removePath(p *path) {
	s.conn.removePath(p)
	delete(s.relay.sessions, p.localCID)
	s.retiredCIDs = append(s.retiredCIDs, p.localCID)
	s.relay.retired[p.localCID] = true
	if len(s.retiredCIDs) > maxRetiredCIDs {
		delete(s.relay.retired, s.retiredCIDs[0])
		s.retiredCIDs = s.retiredCIDs[1:]
	}
	if s.lastUplink == p {
		s.lastUplink = nil
	}
}

// primary picks the downlink path: the path the client most recently sent
// IP traffic on while it is healthy, otherwise the best healthy path
// (§15.2).
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
	// Several pending handshakes may race for the last active slot.
	// Reject before Authorize, which can allocate an address lease.
	if s.state != StateActive && len(r.live)-r.pending >= r.cfg.MaxSessions {
		s.conn.transmit(now, s.conn.path(0), []wire.Frame{wire.AuthResult{Status: uint8(wire.CodeCapacity)}, wire.CloseFrame{Code: wire.CodeCapacity}})
		r.closeSession(now, s, ErrCapacity, false)
		return false
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
	if !r.cfg.NoRedundancy {
		result.Features |= wire.FeatureRedundancy
	}
	if !r.cfg.NoFEC {
		result.Features |= wire.FeatureFEC
	}
	if !r.cfg.NoStreams {
		result.Features |= wire.FeatureStreams
		s.conn.streams.init(false)
	}
	s.result = result
	s.state = StateActive
	r.leavePending(s)
	s.conn.queue(result)
	s.conn.setProbeSizes(result.TunMTU, result.Features&(wire.FeatureRedundancy|wire.FeatureFEC) != 0)
	if result.KeepaliveMS > 0 {
		s.conn.keepalive = time.Duration(result.KeepaliveMS) * time.Millisecond
	}
	s.conn.probe(now, s.conn.path(0))
	s.issueSlots(now)
	if s.state == StateClosed {
		return false
	}
	r.events = append(r.events, SessionEstablished{Session: s})
	return true
}

// deliver checks a client packet's inner source address against the lease
// (§11) and reports it.
func (s *RelaySession) deliver(now time.Time, p *path, pkt []byte, mustCopy bool) {
	if s.state != StateActive {
		return
	}
	if len(pkt) < 20 || pkt[0]>>4 != 4 || [4]byte(pkt[12:16]) != s.result.IPv4 {
		s.relay.stats.SpoofedDropped++
		return
	}
	if p.joined && p.validated && s.conn.multipath() {
		if k, ok := flowKeyOf(pkt, true); ok {
			if q, ok := s.flows.get(now, k); !ok || q != p {
				s.flows.put(now, k, p)
			}
		}
	}
	if mustCopy {
		pkt = copyBytes(pkt)
	}
	s.relay.ips = append(s.relay.ips, relayIP{s, pkt})
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
	for _, cid := range s.retiredCIDs {
		delete(r.retired, cid)
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

// violation ends the session over a client's protocol violation.
func (s *RelaySession) violation(now time.Time) {
	if p := s.primary(now); p != nil {
		s.conn.transmit(now, p, []wire.Frame{wire.CloseFrame{Code: wire.CodeProtocolViolation}})
	}
	s.relay.closeSession(now, s, ErrProtocolViolation, false)
}

// StreamWrite queues bytes for a stream, as Client.StreamWrite does.
func (s *RelaySession) StreamWrite(now time.Time, id uint32, p []byte) (int, error) {
	if s.state != StateActive {
		return 0, ErrClosed
	}
	return s.conn.streamWrite(now, id, p)
}

// StreamRead reads received stream bytes, as Client.StreamRead does.
func (s *RelaySession) StreamRead(now time.Time, id uint32, p []byte) (int, error) {
	if s.state != StateActive {
		return 0, ErrClosed
	}
	return s.conn.streamRead(now, id, p)
}

// StreamCloseWrite ends what the relay sends on a stream.
func (s *RelaySession) StreamCloseWrite(now time.Time, id uint32) error {
	if s.state != StateActive {
		return ErrClosed
	}
	return s.conn.streamCloseWrite(now, id)
}

// StreamReset abandons a stream, such as one the relay could not connect.
func (s *RelaySession) StreamReset(now time.Time, id uint32, code wire.ErrorCode) {
	if s.state == StateActive {
		s.conn.streamReset(now, id, code)
	}
}

// StreamInfo reports a stream's state. A stream reported Done is gone.
func (s *RelaySession) StreamInfo(id uint32) StreamInfo { return s.conn.streamInfo(id) }

// Tick runs expired timers for every session.
func (r *Relay) Tick(now time.Time) {
	for _, s := range slices.Clone(r.live) {
		switch {
		case s.state == StateAuthenticating && !now.Before(s.created.Add(relayPendingTimeout)):
			r.closeSession(now, s, ErrHandshakeTimeout, false)
		case !now.Before(s.conn.lastRecv().Add(r.cfg.IdleTimeout)):
			r.closeSession(now, s, ErrIdleTimeout, false)
		default:
			removed := false
			for _, p := range slices.Clone(s.conn.paths) {
				if at := s.conn.abandonAt(p, DefaultPathTimeout); p.joined && !at.IsZero() && !now.Before(at) {
					s.conn.queue(wire.PathAbandon{PathID: p.id, Code: wire.CodePathUnavailable})
					s.removePath(p)
					removed = true
				} else if !p.joined && !p.skippedAt.IsZero() && !now.Before(p.skippedAt.Add(DefaultPathTimeout)) {
					s.removePath(p)
					removed = true
				}
			}
			// Freed capacity may be needed for spares: a client whose slots
			// ran out cannot send the JOIN that would otherwise refill them.
			if removed {
				if s.issueSlots(now); s.state == StateClosed {
					continue
				}
			}
			s.conn.onTimers(now)
			s.flows.sweep(now, false)
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
			d = earliest(d, s.created.Add(relayPendingTimeout))
		}
		for _, p := range s.conn.paths {
			if p.joined {
				d = earliest(d, s.conn.abandonAt(p, DefaultPathTimeout))
			} else if !p.skippedAt.IsZero() {
				d = earliest(d, p.skippedAt.Add(DefaultPathTimeout))
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

// PollIP returns the next IP packet from a client, whose inner source
// address has been checked against the session's lease (§11). The packet
// is in a pooled buffer; return it with bufpool.Put when done.
func (r *Relay) PollIP() (*RelaySession, []byte, bool) {
	if len(r.ips) == 0 {
		return nil, nil, false
	}
	ip := r.ips[0]
	r.ips[0] = relayIP{}
	r.ips = r.ips[1:]
	return ip.s, ip.pkt, true
}

// PollEvent returns the next event.
func (r *Relay) PollEvent() (RelayEvent, bool) {
	for _, s := range r.live {
		ss := &s.conn.streams
		for _, f := range ss.opened {
			r.events = append(r.events, StreamOpened{Session: s, ID: f.ID, Dst: f.Dst})
		}
		for _, id := range ss.updates {
			r.events = append(r.events, RelayStreamUpdate{Session: s, ID: id})
		}
		ss.opened, ss.updates = ss.opened[:0], ss.updates[:0]
	}
	if len(r.events) == 0 {
		return nil, false
	}
	e := r.events[0]
	r.events = r.events[1:]
	return e, true
}
