package session

import (
	"cmp"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
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

	// FEC selects forward error correction (§11.2) for both directions:
	// off, auto (while measured loss is at least 0.5%, sized from it), or
	// always. It needs a relay that supports it.
	FEC wire.FECMode
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
	// AckEliciting is set when the relay owes this packet a reply: an
	// acknowledgement within its maximum ACK delay. ACK-only packets are
	// not answered; a carrier that watches for replies (a stream
	// carrier's stall detection) must not wait for one.
	AckEliciting bool
}

// ClientEvent is reported by Client.PollEvent.
type ClientEvent interface{ clientEvent() }

// Established reports that the session is active.
type Established struct{ Config wire.AuthResult }

// Enrolled reports the relay's ENROLLED: the client's enrollment
// credential made it the device DeviceID, named Name (§9.2).
type Enrolled struct {
	DeviceID [8]byte
	Name     string
}

// InviteAnswer reports the relay's INVITE, answering RequestInvite.
type InviteAnswer struct{ wire.Invite }

// DevicesAnswer reports the relay's DEVICES, answering RequestDevices.
type DevicesAnswer struct{ wire.Devices }

// RevokeAnswer reports the relay's REVOKE_RESULT, answering
// RequestRevoke.
type RevokeAnswer struct{ wire.RevokeResult }

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

// StreamUpdate reports news on a stream: bytes to read, room to write, the
// end of either, or a reset. StreamInfo says which; until it is called,
// further news raises no further StreamUpdate for the stream.
type StreamUpdate struct{ ID uint32 }

func (Established) clientEvent()       {}
func (Enrolled) clientEvent()          {}
func (InviteAnswer) clientEvent()      {}
func (DevicesAnswer) clientEvent()     {}
func (RevokeAnswer) clientEvent()      {}
func (PathValidated) clientEvent()     {}
func (PathClosed) clientEvent()        {}
func (Closed) clientEvent()            {}
func (RedundancyChanged) clientEvent() {}
func (StreamUpdate) clientEvent()      {}

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

	conn     *conn
	config   wire.AuthResult
	enrolled bool // ENROLLED reported
	slots    []pathSlot
	current  *path // primary path
	// Loss-driven moves of the primary (loss.go): when the next check is
	// due and the earliest the primary may move again.
	lossCheckAt, lossMoveAt time.Time
	flows                   flowTable // flow-to-path pins; see sched.go
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

// ErrNoInvites: the relay does not let this session's device mint
// invites (AUTH_RESULT without FeatureInvites).
var ErrNoInvites = errors.New("session: the relay does not offer invites to this device")

// ErrNoDevices: the relay does not let this session's device manage
// devices (AUTH_RESULT without FeatureDevices).
var ErrNoDevices = errors.New("session: the relay does not let this device manage devices")

// RequestDevices asks the relay for the account's devices (§10.1),
// reliably. The answer comes as a DevicesAnswer; the caller repeats the
// request, with the same id, until answered.
func (c *Client) RequestDevices(id [8]byte) error {
	if c.state != StateActive {
		return ErrNotActive
	}
	if c.config.Features&wire.FeatureDevices == 0 {
		return ErrNoDevices
	}
	c.conn.queue(wire.DevicesRequest{RequestID: id})
	return nil
}

// RequestRevoke asks the relay to revoke one of the account's devices,
// and with descendants every device enrolled through its invites
// (§10.1), reliably. The answer comes as a RevokeAnswer once the
// revocation is committed; the caller repeats the request, with the same
// id, until answered. Revoking this session's own device closes the
// session with ErrRevoked instead.
func (c *Client) RequestRevoke(id, device [8]byte, descendants bool) error {
	if c.state != StateActive {
		return ErrNotActive
	}
	if c.config.Features&wire.FeatureDevices == 0 {
		return ErrNoDevices
	}
	c.conn.queue(wire.RevokeRequest{RequestID: id, DeviceID: device, Descendants: descendants})
	return nil
}

// RequestInvite asks the relay for an invite to the session's account
// (§10.1), reliably. The answer comes as an InviteAnswer; the relay may
// hold a request it cannot answer yet, so the caller repeats it, with the
// same id, until answered.
func (c *Client) RequestInvite(id [8]byte) error {
	if c.state != StateActive {
		return ErrNotActive
	}
	if c.config.Features&wire.FeatureInvites == 0 {
		return ErrNoInvites
	}
	c.conn.queue(wire.InviteRequest{RequestID: id})
	return nil
}

// SetFallback marks a path to carry traffic only while no other path is
// healthy, as for a TLS/TCP carrier (§16.3). It may be called before the
// path validates, and for path 0.
func (c *Client) SetFallback(id uint32, fallback bool) {
	if c.conn == nil {
		return
	}
	if p := c.conn.path(id); p != nil {
		p.fallback = fallback
		p.ratioAt = time.Time{}
	}
}

// Probe sends a PING on a validated path now. The engine calls it when
// the transport under the path has moved to a new connection (a stream
// carrier's redial or rotation): the relay keeps sending on the old one
// until it hears from the new one, and a client with nothing to say
// would otherwise stay silent until its next keepalive.
func (c *Client) Probe(now time.Time, id uint32) {
	c.observe(now)
	if c.state != StateActive {
		return
	}
	if p := c.conn.path(id); p != nil && p.validated {
		c.conn.transmit(now, p, []wire.Frame{wire.Ping{}})
	}
}

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
	c.flows = flowTable{}
	c.attemptStart = now
	c.attempts++
	c.sendInit(now)
	return nil
}

func (c *Client) sendInit(now time.Time) {
	init := c.hs.Init(c.cookie)
	c.out = append(c.out, Datagram{PathID: 0, Data: init.Append(nil), AckEliciting: true})
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
	c.conn.primary, c.conn.pathFor, c.conn.emit = c.primary, c.pathFor, c.emit
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

func (c *Client) emit(p *path, b []byte, _, ackEliciting bool) {
	c.out = append(c.out, Datagram{PathID: p.id, Data: b, AckEliciting: ackEliciting})
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
	healthy := c.current != nil && !c.current.removed && c.current.healthy(now, c.conn.keepalive)
	if !healthy {
		if best := c.conn.bestPath(now); best != nil {
			c.current = best
		}
	}
	if c.current == nil || now.Before(c.lossCheckAt) {
		return c.current
	}
	c.lossCheckAt = now.Add(lossCheckEvery)
	if healthy && c.current.fallback {
		if best := c.conn.bestPath(now); best != nil && !best.fallback {
			c.current = best // a preferred path is healthy again
		}
	}
	if healthy {
		if best := c.conn.bestPath(now); best != c.current && !now.Before(c.lossMoveAt) &&
			lossierThan(now, c.current, best) {
			c.current, c.lossMoveAt = best, now.Add(lossDwell)
		}
	}
	c.updateRedundancy(now)
	return c.current
}

// pathFor returns the path for an uplink IP packet: its flow's path while
// that stays eligible, otherwise a newly assigned one (§15.2).
func (c *Client) pathFor(now time.Time, pkt []byte) *path {
	prim := c.primary(now)
	if prim == nil || !c.conn.multipath() {
		return prim
	}
	k, ok := flowKeyOf(pkt, true)
	if !ok {
		return prim
	}
	if p, ok := c.flows.get(now, k); ok && c.conn.keeps(now, p, prim) {
		return p
	}
	c.flows.sweep(now, false) // fresh counts for the decision
	p := c.conn.assign(now, prim)
	c.flows.put(now, k, p)
	return p
}

// deliverRecovered queues IP packets rebuilt by FEC; the decoder owns them.
func (c *Client) deliverRecovered(pkts [][]byte) {
	for _, p := range pkts {
		c.ips = append(c.ips, copyBytes(p))
	}
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
		case wire.Enrolled:
			if !c.enrolled {
				c.enrolled = true
				c.events = append(c.events, Enrolled{DeviceID: f.DeviceID, Name: f.Name})
			}
			if c.state == StateClosed {
				return
			}
		case wire.Invite:
			c.events = append(c.events, InviteAnswer{f})
		case wire.Devices:
			c.events = append(c.events, DevicesAnswer{f})
		case wire.RevokeResult:
			c.events = append(c.events, RevokeAnswer{f})
		case wire.Ack:
			c.conn.onAck(now, &f)
		case wire.IPPacket:
			if c.state == StateActive {
				c.ips = append(c.ips, copyBytes(f.Packet))
			}
		case wire.IPDatagram:
			if c.state == StateActive && c.conn.receiveDatagram(f) {
				c.ips = append(c.ips, copyBytes(f.Packet))
				c.deliverRecovered(c.conn.fecSource(now, f.DatagramID, f.Packet))
			}
		case wire.IPFragment:
			if c.state == StateActive {
				if pkt := c.conn.receiveFragment(now, f); pkt != nil {
					c.ips = append(c.ips, pkt)
					c.deliverRecovered(c.conn.fecSource(now, f.DatagramID, pkt))
				}
			}
		case wire.FECRepair:
			if c.state == StateActive {
				c.deliverRecovered(c.conn.fecRepair(now, f))
			}
		case wire.NewPath:
			// Control frames may be retransmitted in fresh DATA packets,
			// possibly after later ones. Paths open in increasing ID order
			// (the lowest slot first), so a slot at or below the highest
			// path opened is stale and a queued one a duplicate: no path
			// ID, and so no nonce space, is used twice.
			i, queued := slices.BinarySearchFunc(c.slots, f.PathID, func(s pathSlot, id uint32) int { return cmp.Compare(s.id, id) })
			if len(c.slots) < maxPaths && !queued && f.PathID > c.conn.highestPathID {
				c.slots = slices.Insert(c.slots, i, pathSlot{id: f.PathID, cid: f.CID, token: f.ResetToken})
			}
		case wire.PathChallenge:
			c.onChallenge(now, p, f)
		case wire.PathAbandon:
			if q := c.conn.path(f.PathID); q != nil {
				c.dropPath(q, ErrPathAbandoned)
			}
		case wire.Stream:
			if !c.conn.onStream(f) {
				c.violation(now)
				return
			}
		case wire.MaxStreamData:
			c.conn.onMaxStreamData(f)
		case wire.MaxData:
			c.conn.onMaxData(f)
		case wire.StreamReset:
			if !c.conn.onStreamReset(f) {
				c.violation(now)
				return
			}
		case wire.CloseFrame:
			c.close(now, &PeerClosedError{Code: f.Code}, false)
			return
		}
	}
	c.conn.flush(now)
}

// violation ends the session over a peer's protocol violation.
func (c *Client) violation(now time.Time) {
	if p := c.conn.primary(now); p != nil {
		c.conn.transmit(now, p, []wire.Frame{wire.CloseFrame{Code: wire.CodeProtocolViolation}})
	}
	c.close(now, ErrProtocolViolation, false)
}

// streamEvents turns stream news into events.
func (c *Client) streamEvents() {
	for _, id := range c.conn.streams.updates {
		c.events = append(c.events, StreamUpdate{ID: id})
	}
	c.conn.streams.updates = c.conn.streams.updates[:0]
}

// StreamsSupported reports whether the active session's relay carries
// streams (§11.3).
func (c *Client) StreamsSupported() bool {
	return c.state == StateActive && c.conn.streams.connect
}

// DiagnosticsSupported reports whether the active session's relay accepts
// diagnostics uploads (§11.4).
func (c *Client) DiagnosticsSupported() bool {
	return c.state == StateActive && c.conn.streams.diagnostics
}

// OpenDiagnostics opens a stream uploading diagnostics to the relay's
// operator (§11.4) and returns its ID. The client writes the upload and
// finishes its side; the relay answers "ok\n" and FIN once it kept it, or
// resets the stream.
func (c *Client) OpenDiagnostics(now time.Time) (uint32, error) {
	c.observe(now)
	if c.state != StateActive {
		return 0, ErrNotActive
	}
	return c.conn.openDiagnostics(now)
}

// OpenStream asks the relay to connect a new stream to a TCP destination
// and returns its ID (§11.3). Bytes may be written at once; if the relay
// cannot connect, the stream is reset.
func (c *Client) OpenStream(now time.Time, dst netip.AddrPort) (uint32, error) {
	c.observe(now)
	if c.state != StateActive {
		return 0, ErrNotActive
	}
	return c.conn.openStream(now, dst)
}

// StreamWrite queues bytes for a stream and returns how many it accepted,
// which StreamInfo's Writable bounds. It copies them.
func (c *Client) StreamWrite(now time.Time, id uint32, p []byte) (int, error) {
	c.observe(now)
	if c.state != StateActive {
		return 0, ErrNotActive
	}
	return c.conn.streamWrite(now, id, p)
}

// StreamRead reads received stream bytes, returning io.EOF once the peer
// finished sending and everything was read.
func (c *Client) StreamRead(now time.Time, id uint32, p []byte) (int, error) {
	c.observe(now)
	if c.state != StateActive {
		return 0, ErrNotActive
	}
	return c.conn.streamRead(now, id, p)
}

// StreamCloseWrite ends what this end sends on a stream, after the bytes
// already written.
func (c *Client) StreamCloseWrite(now time.Time, id uint32) error {
	c.observe(now)
	if c.state != StateActive {
		return ErrNotActive
	}
	return c.conn.streamCloseWrite(now, id)
}

// StreamReset abandons a stream in both directions.
func (c *Client) StreamReset(now time.Time, id uint32, code wire.ErrorCode) {
	c.observe(now)
	if c.state == StateActive {
		c.conn.streamReset(now, id, code)
	}
}

// StreamInfo reports a stream's state. A stream reported Done is gone.
func (c *Client) StreamInfo(id uint32) StreamInfo {
	if c.conn == nil {
		return StreamInfo{Done: true, Err: ErrStreamClosed}
	}
	return c.conn.streamInfo(id)
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
		err := ErrAuthFailed
		switch wire.ErrorCode(r.Status) {
		case wire.CodeCapacity:
			err = ErrCapacity
		case wire.CodeInviteUsed:
			err = ErrInviteUsed
		case wire.CodeInviteExpired:
			err = ErrInviteExpired
		case wire.CodeRevoked:
			err = ErrRevoked
		}
		c.state, c.err = StateClosed, err
		c.events = append(c.events, Closed{Err: err})
		return
	}
	c.config = r
	c.state = StateActive
	p0 := c.conn.path(0)
	p0.validated = true
	c.conn.setProbeSizes(r.TunMTU, r.Features&(wire.FeatureRedundancy|wire.FeatureFEC) != 0)
	if r.Features&wire.FeatureFEC != 0 && c.cfg.FEC != wire.FECOff {
		c.conn.fec.mode = c.cfg.FEC
		c.conn.queue(wire.FEC{Seq: 1, Mode: c.cfg.FEC}) // the relay protects the downlink likewise
	}
	if r.Features&(wire.FeatureStreams|wire.FeatureDiagnostics) != 0 {
		c.conn.streams.init(true)
		c.conn.streams.connect = r.Features&wire.FeatureStreams != 0
		c.conn.streams.diagnostics = r.Features&wire.FeatureDiagnostics != 0
	}
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
	// In auto mode a primary that is not healthy also turns redundancy on:
	// that happens only when no path is healthy (otherwise the primary
	// moves), and under loss heavy enough that acknowledgements stop
	// arriving, the loss estimates themselves update slowly. Otherwise a
	// direction is duplicated while any path carrying traffic (the primary
	// or a path with flows) loses enough in that direction.
	if c.cfg.Redundancy == RedundancyAuto && c.current.healthy(now, c.conn.keepalive) {
		up, down = false, false
		for _, p := range c.conn.paths {
			if p == c.current || p.flows > 0 {
				up = up || wantRedundancy(now, &p.sendLoss, c.conn.redundant)
				down = down || wantRedundancy(now, &p.recvLoss, c.downRedundant)
			}
		}
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
	// Defensive against a stale slot queued before its path was opened.
	for len(c.slots) > 0 && c.slots[0].id <= c.conn.highestPathID {
		c.slots = c.slots[1:]
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
	if !c.conn.addPath(p) {
		c.close(now, ErrPathLimit, true)
		return 0, ErrPathLimit
	}
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
			// A silent path is abandoned only while another is heard from
			// (§14.6); the session idle timeout governs the rest (§9.4).
			if at := c.conn.abandonAt(p, c.cfg.PathTimeout); !at.IsZero() && !now.Before(at) {
				c.conn.queue(wire.PathAbandon{PathID: p.id, Code: wire.CodePathUnavailable})
				c.dropPath(p, ErrPathTimeout)
			}
		}
	}
	c.conn.onTimers(now)
	c.flows.sweep(now, false)
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
		d = earliest(d, c.conn.abandonAt(p, c.cfg.PathTimeout))
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
	if c.conn != nil {
		c.streamEvents()
	}
	if len(c.events) == 0 {
		return nil, false
	}
	e := c.events[0]
	c.events = c.events[1:]
	return e, true
}
