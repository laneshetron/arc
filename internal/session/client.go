package session

import (
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/wire"
)

// State is a session's lifecycle state (§9.4).
type State int

const (
	StateHandshaking State = iota
	StateAuthenticating
	StateActive
	StateClosed
)

func (s State) String() string {
	return [...]string{"HANDSHAKING", "AUTHENTICATING", "ACTIVE", "CLOSED"}[s]
}

// ClientConfig configures a client session.
type ClientConfig struct {
	Static      crypto.StaticKey
	RelayPublic []byte // pinned relay static key
	Credential  []byte
	Rand        io.Reader // nil uses crypto/rand

	// PathTimeout is how long a path may go without receiving anything
	// before the client abandons it, unless it is the last path. Default
	// DefaultPathTimeout.
	PathTimeout time.Duration

	// Redundancy selects when IP traffic is sent on two paths at once
	// (§11.1). It needs a second healthy path and a relay that supports it.
	Redundancy RedundancyPolicy
}

// RedundancyPolicy selects when the client sends IP traffic on two paths
// and asks the relay to do the same.
type RedundancyPolicy uint8

const (
	// RedundancyOff never duplicates traffic.
	RedundancyOff RedundancyPolicy = iota
	// RedundancyAuto duplicates a direction while the primary path loses
	// more than 1% of its packets in that direction, until the loss falls
	// below 0.4%.
	RedundancyAuto
	// RedundancyAlways duplicates all traffic, doubling its cost.
	RedundancyAlways
)

// Datagram is an outgoing packet for one of the client's paths. The caller
// sends it on the carrier it bound to PathID.
type Datagram struct {
	PathID uint32
	Data   []byte
}

// ClientEvent is reported by Client.PollEvent.
type ClientEvent interface{ clientEvent() }

// Established reports that the session is active.
type Established struct{ Config wire.AuthResult }

// PathValidated reports that a path opened with OpenPath can carry traffic.
type PathValidated struct{ ID uint32 }

// RedundancyChanged reports that the client started or stopped sending
// uplink traffic, or asked the relay to send downlink traffic, on two
// paths. Copies go out only while a second healthy path exists.
type RedundancyChanged struct{ Uplink, Downlink bool }

// PathClosed reports that a path was removed; its carrier can be closed.
type PathClosed struct {
	ID  uint32
	Err error
}

// Closed reports that the session ended.
type Closed struct{ Err error }

func (Established) clientEvent()       {}
func (PathValidated) clientEvent()     {}
func (PathClosed) clientEvent()        {}
func (Closed) clientEvent()            {}
func (RedundancyChanged) clientEvent() {}

// MaxCredentialLen is the largest credential whose AUTH frame fits in one
// packet on a path that has not been MTU-probed.
const MaxCredentialLen = DefaultMaxPacketSize - dataOverhead

var errCredential = errors.New("session: credential must be 1 to MaxCredentialLen bytes")

type pathSlot struct {
	id    uint32
	cid   wire.CID
	token wire.Token
}

// Client is the initiator side of one ARC session. It is not safe for
// concurrent use; drive it from a single goroutine.
type Client struct {
	cfg   ClientConfig
	state State
	err   error

	// Handshake.
	hs            *crypto.ClientHandshake
	cookie        *[wire.CookieLen]byte
	attemptStart  time.Time
	attempts      uint64    // handshake attempts started
	heard         time.Time // last authentic packet from the relay, or creation
	nextInit      time.Time // next HANDSHAKE_INIT, or next AUTH while authenticating
	authenticated time.Time

	conn    *conn
	config  wire.AuthResult
	slots   []pathSlot
	current *path // primary path
	// Loss-driven moves of the primary (loss.go): when the next check is
	// due and the earliest the primary may move again.
	lossCheckAt, lossMoveAt time.Time
	downRedundant           bool      // downlink redundancy requested
	redundancySeq           uint32    // of the last REDUNDANCY sent
	now                     time.Time // latest time passed to any input, for NextDeadline

	out    []Datagram
	events []ClientEvent
	ips    [][]byte // received IP packets, kept apart from events to avoid boxing
}

// NewClient creates a client and queues its first HANDSHAKE_INIT on path 0.
func NewClient(cfg ClientConfig, now time.Time) (*Client, error) {
	if len(cfg.Credential) == 0 || len(cfg.Credential) > MaxCredentialLen {
		return nil, errCredential
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.PathTimeout == 0 {
		cfg.PathTimeout = DefaultPathTimeout
	}
	c := &Client{cfg: cfg, heard: now}
	if err := c.startHandshake(now); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) State() State { return c.state }

// HandshakeAttempt numbers the current handshake attempt. It changes when
// the client starts over with a new ephemeral key, which invalidates any
// cookie the previous attempt held.
func (c *Client) HandshakeAttempt() uint64 { return c.attempts }

// Stats returns counters for the current session, if any.
func (c *Client) Stats() Stats {
	if c.conn == nil {
		return Stats{}
	}
	return c.conn.stats
}

// Paths describes the session's joined paths.
func (c *Client) Paths(now time.Time) []PathInfo {
	if c.conn == nil {
		return nil
	}
	return c.conn.pathInfo(now)
}

func (c *Client) startHandshake(now time.Time) error {
	var cid wire.CID
	if _, err := io.ReadFull(c.cfg.Rand, cid[:]); err != nil {
		return err
	}
	hs, err := crypto.NewClientHandshake(crypto.ClientConfig{
		Static: c.cfg.Static, RelayPublic: c.cfg.RelayPublic, SenderCID: cid, Rand: c.cfg.Rand,
	})
	if err != nil {
		return err
	}
	c.state, c.hs, c.cookie, c.conn, c.slots, c.current = StateHandshaking, hs, nil, nil, nil, nil
	c.attemptStart = now
	c.attempts++
	c.sendInit(now)
	return nil
}

func (c *Client) sendInit(now time.Time) {
	init := c.hs.Init(c.cookie)
	c.out = append(c.out, Datagram{PathID: 0, Data: init.Append(nil)})
	c.nextInit = now.Add(c.handshakeInterval(now))
}

// handshakeInterval is how long to wait before repeating INIT or AUTH.
func (c *Client) handshakeInterval(now time.Time) time.Duration {
	if now.Sub(c.heard) < handshakeQuiet {
		return handshakeRetransmit
	}
	return handshakeRetransmitQuiet
}

// HandlePacket processes one packet received on the carrier bound to pathID.
func (c *Client) HandlePacket(now time.Time, pathID uint32, b []byte) {
	c.observe(now)
	if c.state == StateClosed {
		return
	}
	t, err := wire.PeekType(b)
	if err != nil {
		return
	}
	switch t {
	case wire.TypeCookieReply:
		c.handleCookieReply(now, b)
	case wire.TypeHandshakeResp:
		c.handleResp(now, b)
	case wire.TypeData:
		c.handleData(now, b)
	case wire.TypeStatelessReset:
		c.handleReset(b)
	}
}

func (c *Client) handleCookieReply(now time.Time, b []byte) {
	r, err := wire.ParseCookieReply(b)
	if err != nil || c.state != StateHandshaking || r.DestCID != c.hs.Init(nil).SenderCID {
		return
	}
	c.cookie, c.heard = &r.Cookie, now
	c.sendInit(now)
}

func (c *Client) handleResp(now time.Time, b []byte) {
	if c.state != StateHandshaking {
		return
	}
	resp, err := wire.ParseHandshakeResp(b)
	if err != nil {
		return
	}
	res, err := c.hs.Finish(&resp)
	if err != nil {
		return // possibly forged; keep waiting for the genuine response
	}
	c.heard = now
	p0 := newPath(0, c.hs.Init(nil).SenderCID, res.RelayCID, now)
	p0.resetToken, p0.joined = res.ResetToken, true
	c.conn = newConn(res.Keys, now)
	c.conn.primary, c.conn.emit = c.primary, c.emit
	c.conn.addPath(p0)
	c.state, c.authenticated = StateAuthenticating, now
	c.sendAuth(now)
}

// sendAuth sends AUTH in a new DATA packet and schedules the next copy.
// AUTH is repeated on a timer until AUTH_RESULT arrives rather than
// retransmitted on PTO, which would back off (§9.2); the relay answers
// each copy.
func (c *Client) sendAuth(now time.Time) {
	c.conn.transmit(now, c.conn.path(0), []wire.Frame{wire.Auth{Credential: c.cfg.Credential}})
	c.nextInit = now.Add(c.handshakeInterval(now))
}

func (c *Client) emit(p *path, b []byte, _ bool) {
	c.out = append(c.out, Datagram{PathID: p.id, Data: b})
}

// primary keeps the current path while it is healthy and not much lossier
// than another, and otherwise moves to the best healthy path. Before the
// session is active, everything goes on path 0. The relay sends downlink
// traffic on whichever path the client sends uplink traffic on, so this
// choice steers both directions.
func (c *Client) primary(now time.Time) *path {
	if c.state != StateActive {
		return c.conn.path(0)
	}
	if c.current != nil && !c.current.removed && c.current.healthy(now, c.conn.keepalive) {
		if now.Before(c.lossCheckAt) {
			return c.current
		}
		c.lossCheckAt = now.Add(lossCheckEvery)
		if best := c.conn.bestPath(now); best != c.current && !now.Before(c.lossMoveAt) &&
			lossierThan(now, c.current, best) {
			c.current, c.lossMoveAt = best, now.Add(lossDwell)
		}
		c.updateRedundancy(now)
		return c.current
	}
	if best := c.conn.bestPath(now); best != nil {
		c.current = best
	}
	return c.current
}

func (c *Client) handleData(now time.Time, b []byte) {
	if c.conn == nil {
		return
	}
	h, aad, ct, err := wire.ParseData(b)
	if err != nil {
		return
	}
	p := c.conn.byCID[h.DestCID]
	if p == nil {
		return
	}
	frames, err := c.conn.open(now, p, h, aad, ct)
	if err == ErrIntegrityLimit {
		c.close(now, err, false)
		return
	}
	if err != nil {
		return
	}
	c.heard = now
	for _, f := range frames {
		switch f := f.(type) {
		case wire.AuthResult:
			c.onAuthResult(now, f)
			if c.state == StateClosed {
				return
			}
		case wire.Ack:
			c.conn.onAck(now, &f)
		case wire.IPPacket:
			if c.state == StateActive {
				c.ips = append(c.ips, copyBytes(f.Packet))
			}
		case wire.IPDatagram:
			if c.state == StateActive && c.conn.receiveDatagram(f) {
				c.ips = append(c.ips, copyBytes(f.Packet))
			}
		case wire.IPFragment:
			if c.state == StateActive {
				if pkt := c.conn.receiveFragment(now, f); pkt != nil {
					c.ips = append(c.ips, pkt)
				}
			}
		case wire.NewPath:
			if len(c.slots) < maxPaths && c.conn.path(f.PathID) == nil {
				c.slots = append(c.slots, pathSlot{id: f.PathID, cid: f.CID, token: f.ResetToken})
			}
		case wire.PathChallenge:
			c.onChallenge(now, p, f)
		case wire.PathAbandon:
			if q := c.conn.path(f.PathID); q != nil {
				c.dropPath(q, ErrPathAbandoned)
			}
		case wire.CloseFrame:
			c.close(now, &PeerClosedError{Code: f.Code}, false)
			return
		}
	}
	c.conn.flush(now)
}

// onChallenge answers a PATH_CHALLENGE. An authenticated challenge on a
// joining path proves the relay received our PATH_JOIN and can reach us, so
// the path is validated (§14.4).
func (c *Client) onChallenge(now time.Time, p *path, f wire.PathChallenge) {
	c.conn.transmit(now, p, []wire.Frame{wire.PathResponse{Data: f.Data}})
	if !p.validated && c.state == StateActive {
		p.validated = true
		p.control = nil // the pending PATH_JOIN is no longer needed
		c.events = append(c.events, PathValidated{ID: p.id})
		c.conn.probe(now, p)
		if best := c.conn.bestPath(now); best != nil && (c.current == nil || best.cost(now) < c.current.cost(now)) {
			c.current = best
		}
	}
}

func (c *Client) onAuthResult(now time.Time, r wire.AuthResult) {
	if c.state != StateAuthenticating {
		return // duplicate or a credential refresh acknowledgement
	}
	if r.Status != 0 {
		c.state, c.err = StateClosed, ErrAuthFailed
		c.events = append(c.events, Closed{Err: ErrAuthFailed})
		return
	}
	c.config = r
	c.state = StateActive
	p0 := c.conn.path(0)
	p0.validated = true
	c.conn.setProbeSizes(r.TunMTU, r.Features&wire.FeatureRedundancy != 0)
	c.conn.keepalive = c.keepalive()
	c.conn.probe(now, p0)
	c.events = append(c.events, Established{Config: r})
}

// updateRedundancy applies the redundancy policy to the current primary
// path's loss in each direction, asking the relay to change the downlink.
func (c *Client) updateRedundancy(now time.Time) {
	if c.cfg.Redundancy == RedundancyOff || c.config.Features&wire.FeatureRedundancy == 0 {
		return
	}
	up, down := true, true
	if c.cfg.Redundancy == RedundancyAuto {
		up = wantRedundancy(now, &c.current.sendLoss, c.conn.redundant)
		down = wantRedundancy(now, &c.current.recvLoss, c.downRedundant)
	}
	if up == c.conn.redundant && down == c.downRedundant {
		return
	}
	if down != c.downRedundant {
		c.redundancySeq++
		mode := wire.RedundancyNone
		if down {
			mode = wire.RedundancyDuplicate
		}
		c.conn.queue(wire.Redundancy{Seq: c.redundancySeq, Mode: mode})
	}
	c.conn.redundant, c.downRedundant = up, down
	c.events = append(c.events, RedundancyChanged{Uplink: up, Downlink: down})
}

// wantRedundancy applies the RedundancyAuto thresholds to one direction's
// loss estimate, with hysteresis.
func wantRedundancy(now time.Time, l *lossEstimator, on bool) bool {
	rate, ok := l.estimate(now)
	if !ok {
		return false
	}
	if on {
		return rate >= redundancyOff
	}
	return rate >= redundancyOn
}

func (c *Client) handleReset(b []byte) {
	r, err := wire.ParseStatelessReset(b)
	if err != nil || c.conn == nil {
		return
	}
	for _, p := range c.conn.paths {
		if r.CID == p.remoteCID && crypto.ResetTokenEqual(r.Token, p.resetToken) {
			c.state, c.err = StateClosed, ErrStatelessReset
			c.events = append(c.events, Closed{Err: ErrStatelessReset})
			return
		}
	}
}

// OpenPath joins a new path using a slot the relay issued (§14.4) and
// returns its ID. Bind a new carrier to the ID: datagrams for it appear in
// PollTransmit, and received packets go to HandlePacket with that ID. A
// PathValidated event follows when the relay has proven reachability.
func (c *Client) OpenPath(now time.Time) (uint32, error) {
	c.observe(now)
	if c.state != StateActive {
		return 0, ErrNotActive
	}
	if len(c.slots) == 0 {
		return 0, ErrNoPathSlots
	}
	slot := c.slots[0]
	c.slots = c.slots[1:]
	var cid wire.CID
	for {
		if _, err := io.ReadFull(c.cfg.Rand, cid[:]); err != nil {
			return 0, err
		}
		if c.conn.byCID[cid] == nil {
			break
		}
	}
	p := newPath(slot.id, cid, slot.cid, now)
	p.resetToken, p.joined = slot.token, true
	p.control = []wire.Frame{wire.PathJoin{CID: cid}}
	c.conn.addPath(p)
	c.conn.flush(now)
	return p.id, nil
}

// ClosePath abandons a path and tells the relay.
func (c *Client) ClosePath(now time.Time, id uint32) {
	if c.conn == nil {
		return
	}
	p := c.conn.path(id)
	if p == nil || len(c.conn.paths) == 1 {
		return // the last path stays; Close ends the session
	}
	c.conn.queue(wire.PathAbandon{PathID: id, Code: wire.CodeNoError})
	c.dropPath(p, ErrClosed)
	c.conn.flush(now)
}

func (c *Client) dropPath(p *path, err error) {
	c.conn.removePath(p)
	if c.current == p {
		c.current = nil
	}
	c.events = append(c.events, PathClosed{ID: p.id, Err: err})
}

// SendIP tunnels one IP packet. The packet is copied.
func (c *Client) SendIP(now time.Time, pkt []byte) error {
	c.observe(now)
	switch {
	case c.state == StateClosed:
		return ErrClosed
	case c.state != StateActive:
		return ErrNotActive
	case len(pkt) > int(c.config.TunMTU):
		return ErrPacketTooLarge
	}
	if err := wire.ValidateIPPacket(pkt); err != nil {
		return err
	}
	return c.conn.sendIP(now, pkt)
}

// Close ends the session, telling the relay.
func (c *Client) Close(now time.Time) { c.close(now, ErrClosed, true) }

func (c *Client) close(now time.Time, err error, notify bool) {
	if c.state == StateClosed {
		return
	}
	if notify && c.conn != nil {
		if p := c.conn.primary(now); p != nil {
			c.conn.transmit(now, p, []wire.Frame{wire.CloseFrame{Code: wire.CodeNoError}})
		}
	}
	c.state, c.err = StateClosed, err
	c.events = append(c.events, Closed{Err: err})
}

// Tick runs timers that have expired by now.
func (c *Client) Tick(now time.Time) {
	c.observe(now)
	switch c.state {
	case StateClosed:
		return
	case StateHandshaking:
		if !now.Before(c.attemptStart.Add(HandshakeTimeout)) {
			c.restart(now)
		} else if !now.Before(c.nextInit) {
			c.sendInit(now)
		}
		return
	case StateAuthenticating:
		if !now.Before(c.authenticated.Add(HandshakeTimeout)) {
			c.restart(now)
			return
		}
		if !now.Before(c.nextInit) {
			c.sendAuth(now)
		}
	}

	if !now.Before(c.conn.lastRecv().Add(c.idleTimeout())) {
		c.close(now, ErrIdleTimeout, false)
		return
	}
	if c.state == StateActive {
		for _, p := range slices.Clone(c.conn.paths) {
			// A dead path is abandoned unless it is the last one; the session
			// idle timeout governs that case (§9.4).
			if !now.Before(p.lastRecv.Add(c.cfg.PathTimeout)) && len(c.conn.paths) > 1 {
				c.conn.queue(wire.PathAbandon{PathID: p.id, Code: wire.CodePathUnavailable})
				c.dropPath(p, ErrPathTimeout)
			}
		}
	}
	c.conn.onTimers(now)
	if c.state == StateActive {
		for _, p := range c.conn.paths {
			if p.validated && !now.Before(p.lastSend.Add(c.pingInterval(p, now))) {
				c.conn.transmit(now, p, []wire.Frame{wire.Ping{}})
			}
		}
	}
}

// restart abandons the current attempt and begins a new handshake with a
// new ephemeral key and CID (§9.2).
func (c *Client) restart(now time.Time) {
	if err := c.startHandshake(now); err != nil {
		c.close(now, err, false)
	}
}

func (c *Client) idleTimeout() time.Duration {
	if c.config.IdleMS > 0 {
		return time.Duration(c.config.IdleMS) * time.Millisecond
	}
	return DefaultIdleTimeout
}

func (c *Client) keepalive() time.Duration {
	if c.config.KeepaliveMS > 0 {
		return time.Duration(c.config.KeepaliveMS) * time.Millisecond
	}
	return DefaultKeepalive
}

// observe records the latest time an input supplied.
func (c *Client) observe(now time.Time) {
	if now.After(c.now) {
		c.now = now
	}
}

// minProbeInterval bounds how often a suspect path is probed.
const minProbeInterval = 100 * time.Millisecond

// pingInterval is how long a validated path may go without sending before
// it gets a PING: the keepalive interval while healthy, and about one PTO
// while suspect, so that a path that recovers is noticed within a round
// trip rather than at the next keepalive (§14.1).
func (c *Client) pingInterval(p *path, now time.Time) time.Duration {
	if p.healthy(now, c.conn.keepalive) {
		return c.keepalive()
	}
	return min(c.keepalive(), max(p.rtt.pto(), minProbeInterval))
}

// NextDeadline returns when Tick should next be called, or zero if no
// timer is pending.
func (c *Client) NextDeadline() time.Time {
	switch c.state {
	case StateClosed:
		return time.Time{}
	case StateHandshaking:
		return earliest(c.nextInit, c.attemptStart.Add(HandshakeTimeout))
	}
	d := earliest(c.conn.nextDeadline(), c.conn.lastRecv().Add(c.idleTimeout()))
	if c.state != StateActive {
		return earliest(d, c.authenticated.Add(HandshakeTimeout), c.nextInit)
	}
	for _, p := range c.conn.paths {
		if len(c.conn.paths) > 1 {
			d = earliest(d, p.lastRecv.Add(c.cfg.PathTimeout))
		}
		if !p.validated {
			continue
		}
		d = earliest(d, p.lastSend.Add(c.pingInterval(p, c.now)))
		if p.healthy(c.now, c.conn.keepalive) {
			// Wake when the path would turn suspect, to start probing it.
			d = earliest(d, p.suspectAt(c.conn.keepalive))
		}
	}
	return d
}

// PollTransmit returns the next outgoing datagram.
func (c *Client) PollTransmit() (Datagram, bool) {
	if len(c.out) == 0 {
		return Datagram{}, false
	}
	d := c.out[0]
	c.out = c.out[1:]
	return d, true
}

// PollIP returns the next tunneled IP packet received from the relay. The
// packet is in a pooled buffer; return it with bufpool.Put when done.
func (c *Client) PollIP() ([]byte, bool) {
	if len(c.ips) == 0 {
		return nil, false
	}
	p := c.ips[0]
	c.ips[0] = nil
	c.ips = c.ips[1:]
	return p, true
}

// PollEvent returns the next event.
func (c *Client) PollEvent() (ClientEvent, bool) {
	if len(c.events) == 0 {
		return nil, false
	}
	e := c.events[0]
	c.events = c.events[1:]
	return e, true
}
