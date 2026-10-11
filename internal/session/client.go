package session

import (
	"crypto/rand"
	"errors"
	"io"
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
}

// Datagram is an outgoing packet for one of the client's paths.
type Datagram struct {
	PathID uint32
	Data   []byte
}

// ClientEvent is reported by Client.PollEvent: one of Established,
// IPReceived, or Closed.
type ClientEvent interface{ clientEvent() }

// Established reports that the session is active.
type Established struct{ Config wire.AuthResult }

// IPReceived carries one tunneled IP packet.
type IPReceived struct{ Packet []byte }

// Closed reports that the session ended.
type Closed struct{ Err error }

func (Established) clientEvent() {}
func (IPReceived) clientEvent()  {}
func (Closed) clientEvent()      {}

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
	nextInit      time.Time
	initInterval  time.Duration
	authenticated time.Time

	conn   *conn
	config wire.AuthResult

	out    []Datagram
	events []ClientEvent
}

// MaxCredentialLen is the largest credential whose AUTH frame fits in one
// packet on a path that has not been MTU-probed.
const MaxCredentialLen = DefaultMaxPacketSize - wire.DataHeaderLen - wire.AEADTagLen - wire.FrameHeaderLen

var errCredential = errors.New("session: credential must be 1 to MaxCredentialLen bytes")

// NewClient creates a client and queues its first HANDSHAKE_INIT.
func NewClient(cfg ClientConfig, now time.Time) (*Client, error) {
	if len(cfg.Credential) == 0 || len(cfg.Credential) > MaxCredentialLen {
		return nil, errCredential
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	c := &Client{cfg: cfg}
	if err := c.startHandshake(now); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) State() State { return c.state }

// Stats returns counters for the current handshake's session, if any.
func (c *Client) Stats() Stats {
	if c.conn == nil {
		return Stats{}
	}
	return c.conn.stats
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
	c.state, c.hs, c.cookie, c.conn = StateHandshaking, hs, nil, nil
	c.attemptStart, c.initInterval = now, initialRetransmit
	c.sendInit(now)
	return nil
}

func (c *Client) sendInit(now time.Time) {
	init := c.hs.Init(c.cookie)
	c.out = append(c.out, Datagram{PathID: 0, Data: init.Append(nil)})
	c.nextInit = now.Add(c.initInterval)
}

// HandlePacket processes one packet received on a path's carrier.
func (c *Client) HandlePacket(now time.Time, pathID uint32, b []byte) {
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
	c.cookie = &r.Cookie
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
	p0 := newPath(0, c.hs.Init(nil).SenderCID, res.RelayCID, now)
	p0.resetToken = res.ResetToken
	c.conn = newConn(res.Keys, p0, now, c.emit)
	c.state, c.authenticated = StateAuthenticating, now
	c.conn.queue(wire.Auth{Credential: c.cfg.Credential})
	c.conn.flush(now)
}

func (c *Client) emit(p *path, b []byte) {
	c.out = append(c.out, Datagram{PathID: p.id, Data: b})
}

func (c *Client) handleData(now time.Time, b []byte) {
	if c.conn == nil {
		return
	}
	h, aad, ct, err := wire.ParseData(b)
	if err != nil {
		return
	}
	p := c.conn.pathByCID(h.DestCID)
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
	for _, f := range frames {
		switch f := f.(type) {
		case wire.AuthResult:
			c.onAuthResult(f)
			if c.state == StateClosed {
				return
			}
		case wire.Ack:
			c.conn.onAck(now, &f)
		case wire.IPPacket:
			if c.state == StateActive {
				c.events = append(c.events, IPReceived{Packet: copyBytes(f.Packet)})
			}
		case wire.IPFragment:
			if c.state == StateActive {
				if pkt := c.conn.receiveFragment(now, f); pkt != nil {
					c.events = append(c.events, IPReceived{Packet: pkt})
				}
			}
		case wire.CloseFrame:
			c.close(now, &PeerClosedError{Code: f.Code}, false)
			return
		}
	}
	c.conn.flush(now)
}

func (c *Client) onAuthResult(r wire.AuthResult) {
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
	c.events = append(c.events, Established{Config: r})
}

func (c *Client) handleReset(b []byte) {
	r, err := wire.ParseStatelessReset(b)
	if err != nil || c.conn == nil {
		return
	}
	p := c.conn.path0
	if r.CID == p.remoteCID && crypto.ResetTokenEqual(r.Token, p.resetToken) {
		c.state, c.err = StateClosed, ErrStatelessReset
		c.events = append(c.events, Closed{Err: ErrStatelessReset})
	}
}

// SendIP tunnels one IP packet. The packet is copied.
func (c *Client) SendIP(now time.Time, pkt []byte) error {
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
	c.conn.sendIP(now, pkt)
	return nil
}

// Close ends the session, telling the relay.
func (c *Client) Close(now time.Time) { c.close(now, ErrClosed, true) }

func (c *Client) close(now time.Time, err error, notify bool) {
	if c.state == StateClosed {
		return
	}
	if notify && c.conn != nil {
		c.conn.transmit(now, c.conn.path0, []wire.Frame{wire.CloseFrame{Code: wire.CodeNoError}})
	}
	c.state, c.err = StateClosed, err
	c.events = append(c.events, Closed{Err: err})
}

// Tick runs timers that have expired by now.
func (c *Client) Tick(now time.Time) {
	switch c.state {
	case StateClosed:
		return
	case StateHandshaking:
		if !now.Before(c.attemptStart.Add(HandshakeTimeout)) {
			c.restart(now)
		} else if !now.Before(c.nextInit) {
			c.initInterval *= 2
			c.sendInit(now)
		}
		return
	case StateAuthenticating:
		if !now.Before(c.authenticated.Add(HandshakeTimeout)) {
			c.restart(now)
			return
		}
	}

	p := c.conn.path0
	if !now.Before(p.lastRecv.Add(c.idleTimeout())) {
		c.close(now, ErrIdleTimeout, false)
		return
	}
	c.conn.onTimers(now)
	if c.state == StateActive && !now.Before(p.lastSend.Add(c.keepalive())) {
		c.conn.transmit(now, p, []wire.Frame{wire.Ping{}})
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

// NextDeadline returns when Tick should next be called, or zero if no
// timer is pending.
func (c *Client) NextDeadline() time.Time {
	switch c.state {
	case StateClosed:
		return time.Time{}
	case StateHandshaking:
		return earliest(c.nextInit, c.attemptStart.Add(HandshakeTimeout))
	}
	p := c.conn.path0
	d := earliest(c.conn.nextDeadline(), p.lastRecv.Add(c.idleTimeout()))
	if c.state == StateActive {
		d = earliest(d, p.lastSend.Add(c.keepalive()))
	} else {
		d = earliest(d, c.authenticated.Add(HandshakeTimeout))
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

// PollEvent returns the next event.
func (c *Client) PollEvent() (ClientEvent, bool) {
	if len(c.events) == 0 {
		return nil, false
	}
	e := c.events[0]
	c.events = c.events[1:]
	return e, true
}
