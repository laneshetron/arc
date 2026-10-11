// Package session implements ARC/1 client and relay sessions as
// deterministic, I/O-free state machines (spec §9–§14). Callers feed in
// received packets and the current time, then drain outgoing datagrams,
// events, and the next timer deadline. Nothing here reads a clock, sleeps,
// or touches a socket.
package session

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/reassembly"
	"github.com/laneshetron/arc/internal/wire"
)

// Defaults from the spec.
const (
	HandshakeTimeout     = 10 * time.Second
	initialRetransmit    = time.Second
	DefaultMaxPacketSize = 1232 // safe on any IPv6 path (§16.1)
	DefaultKeepalive     = 10 * time.Second
	DefaultIdleTimeout   = 120 * time.Second
	DefaultPathTimeout   = 30 * time.Second // no packets received: the path is dead
	sentHorizon          = 30 * time.Second
	suspectPTOs          = 3
	maxPaths             = 8 // joined paths plus unused slots (§14.3)
	spareSlots           = 2
	amplificationFactor  = 3
	dataOverhead         = wire.DataHeaderLen + wire.AEADTagLen + wire.FrameHeaderLen
)

var (
	ErrClosed         = errors.New("session: closed")
	ErrNotActive      = errors.New("session: not active")
	ErrPacketTooLarge = errors.New("session: packet larger than tunnel MTU")
	ErrNoPath         = errors.New("session: no usable path")
	ErrNoPathSlots    = errors.New("session: relay has not issued a path slot")
	ErrAuthFailed     = errors.New("session: authentication failed")
	ErrStatelessReset = errors.New("session: relay reset the session")
	ErrIdleTimeout    = errors.New("session: idle timeout")
	ErrPathTimeout    = errors.New("session: path timed out")
	ErrPathAbandoned  = errors.New("session: path abandoned by peer")
	ErrIntegrityLimit = errors.New("session: too many authentication failures")
	errReplay         = errors.New("session: replayed or stale packet")
)

// PeerClosedError reports a CLOSE frame from the peer.
type PeerClosedError struct{ Code wire.ErrorCode }

func (e *PeerClosedError) Error() string { return "session: closed by peer" }

// PathInfo describes one path for observability.
type PathInfo struct {
	ID        uint32
	Validated bool
	Healthy   bool
	Primary   bool
	SRTT      time.Duration
	MaxPacket int
	LastRecv  time.Time
}

type path struct {
	id         uint32
	localCID   wire.CID // CID the peer puts on packets to us
	remoteCID  wire.CID // CID we put on packets to the peer
	resetToken wire.Token
	joined     bool // remoteCID is known
	validated  bool
	removed    bool
	maxPacket  int
	nextPN     uint64
	replay     crypto.ReplayWindow
	acks       ackTracker
	sent       sentLog
	rtt        rttEstimator
	control    []wire.Frame // frames that must travel on this path
	probed     bool
	created    time.Time
	lastSend   time.Time
	lastRecv   time.Time

	// Relay only: where the client is, and address validation (§14.4–14.5).
	addr          netip.AddrPort
	recvBytes     int // from addr while the path is unvalidated
	sentBytes     int
	challenge     [8]byte
	cand          netip.AddrPort // unvalidated new address of a validated path
	candChallenge [8]byte
	candActive    bool
	candRecv      int
	candSent      int
	candSentAt    time.Time
}

func newPath(id uint32, local, remote wire.CID, now time.Time) *path {
	return &path{
		id: id, localCID: local, remoteCID: remote, maxPacket: DefaultMaxPacketSize,
		created: now, lastRecv: now,
	}
}

// healthy reports whether the path is validated and not suspect (§14.6).
// A path is suspect when a packet has been unacknowledged for several PTOs
// and nothing at all has arrived for as long, or when the path has been
// silent for longer than the keepalive interval allows: the client sends
// on every validated path at least that often, and the relay acknowledges.
func (p *path) healthy(now time.Time, keepalive time.Duration) bool {
	if !p.validated {
		return false
	}
	limit := suspectPTOs * p.rtt.pto()
	silent := now.Sub(p.lastRecv)
	if silent > keepalive+limit {
		return false
	}
	t0, ok := p.sent.oldestOutstanding()
	return !ok || now.Sub(t0) < limit || silent < limit
}

// suspectAt returns when a currently healthy path would turn suspect if
// nothing else happened, so callers can wake up and start probing it.
func (p *path) suspectAt(keepalive time.Duration) time.Time {
	limit := suspectPTOs * p.rtt.pto()
	at := p.lastRecv.Add(keepalive + limit + time.Nanosecond)
	if t0, ok := p.sent.oldestOutstanding(); ok {
		unanswered := t0.Add(limit)
		if silent := p.lastRecv.Add(limit); silent.After(unanswered) {
			unanswered = silent
		}
		at = earliest(at, unanswered)
	}
	return at
}

// pathBound reports whether a frame must be retransmitted on the path it
// was first sent on.
func pathBound(f wire.Frame) bool {
	switch f.Type() {
	case wire.FramePathJoin, wire.FramePathChallenge:
		return true
	}
	return false
}

// conn is the state shared by both roles once traffic keys exist.
type conn struct {
	send  *crypto.SendKeys
	recv  *crypto.RecvKeys
	paths []*path // ordered by ID for deterministic iteration
	byCID map[wire.CID]*path

	// primary chooses the path for IP traffic and unbound control frames.
	primary func(now time.Time) *path
	emit    func(p *path, b []byte, toCandidate bool)

	ackedThisEpoch bool
	keepalive      time.Duration
	control        []wire.Frame // frames that may travel on any path
	nextDatagramID uint64
	reasm          *reassembly.IP
	probeSize      int // UDP payload needed for an unfragmented TUN packet

	plaintext []byte
	frameBuf  []wire.Frame
	fragBuf   []wire.IPFragment

	stats Stats
}

// Stats counts notable session events.
type Stats struct {
	PacketsSent, PacketsReceived uint64
	ReplaysDropped               uint64
	AuthFailures                 uint64
	PacketsLost                  uint64
	Rekeys                       uint64
	AmplificationDrops           uint64
}

func newConn(keys crypto.TrafficKeys, now time.Time) *conn {
	return &conn{
		send:      crypto.NewSendKeys(keys.Send, now),
		recv:      crypto.NewRecvKeys(keys.Recv),
		byCID:     make(map[wire.CID]*path),
		reasm:     reassembly.New(reassembly.DefaultConfig()),
		keepalive: DefaultKeepalive,
	}
}

func (c *conn) addPath(p *path) {
	i, _ := slices.BinarySearchFunc(c.paths, p.id, func(q *path, id uint32) int { return int(q.id) - int(id) })
	c.paths = slices.Insert(c.paths, i, p)
	c.byCID[p.localCID] = p
}

func (c *conn) removePath(p *path) {
	c.paths = slices.DeleteFunc(c.paths, func(q *path) bool { return q == p })
	delete(c.byCID, p.localCID)
	p.removed = true
	// Unbound frames waiting on this path's packets are retransmitted elsewhere.
	for _, sp := range p.sent.packets {
		if !sp.acked {
			for _, f := range sp.frames {
				if !pathBound(f) {
					c.control = append(c.control, f)
				}
			}
		}
	}
}

func (c *conn) path(id uint32) *path {
	for _, p := range c.paths {
		if p.id == id {
			return p
		}
	}
	return nil
}

// bestPath returns the healthy validated path with the lowest smoothed
// RTT, falling back to any validated path.
func (c *conn) bestPath(now time.Time) *path {
	var best, fallback *path
	for _, p := range c.paths {
		if !p.validated {
			continue
		}
		if fallback == nil {
			fallback = p
		}
		if p.healthy(now, c.keepalive) && (best == nil || p.rtt.srtt() < best.rtt.srtt()) {
			best = p
		}
	}
	if best != nil {
		return best
	}
	return fallback
}

func (c *conn) pathInfo(now time.Time) []PathInfo {
	prim := c.primary(now)
	out := make([]PathInfo, 0, len(c.paths))
	for _, p := range c.paths {
		if !p.joined {
			continue
		}
		out = append(out, PathInfo{
			ID: p.id, Validated: p.validated, Healthy: p.healthy(now, c.keepalive), Primary: p == prim,
			SRTT: p.rtt.srtt(), MaxPacket: p.maxPacket, LastRecv: p.lastRecv,
		})
	}
	return out
}

// lastRecv is the most recent receipt on any path.
func (c *conn) lastRecv() time.Time {
	var t time.Time
	for _, p := range c.paths {
		if p.lastRecv.After(t) {
			t = p.lastRecv
		}
	}
	return t
}

// open runs the receive pipeline of §13: replay check, decryption (which
// may commit an epoch change), then replay-window update. The returned
// frames alias an internal buffer valid until the next call.
func (c *conn) open(now time.Time, p *path, h wire.DataHeader, aad, ct []byte) ([]wire.Frame, error) {
	if !p.replay.Check(h.PacketNumber) {
		c.stats.ReplaysDropped++
		return nil, errReplay
	}
	pt, _, err := c.recv.Open(c.plaintext[:0], h, aad, p.id, ct, now)
	if err != nil {
		c.stats.AuthFailures++
		if c.recv.IntegrityLimitReached() {
			return nil, ErrIntegrityLimit
		}
		return nil, err
	}
	c.plaintext = pt
	p.replay.Record(h.PacketNumber)
	p.lastRecv = now
	c.stats.PacketsReceived++

	frames, err := wire.ParseFrames(c.frameBuf[:0], pt)
	if err != nil {
		return nil, err
	}
	c.frameBuf = frames
	ackEliciting := false
	for _, f := range frames {
		ackEliciting = ackEliciting || f.Type().AckEliciting()
	}
	p.acks.onReceive(h.PacketNumber, now, ackEliciting)
	return frames, nil
}

// onAck processes an ACK frame, which may arrive on any path.
func (c *conn) onAck(now time.Time, ack *wire.Ack) {
	p := c.path(ack.PathID)
	if p == nil {
		return
	}
	intervals, err := ack.AppendIntervals(nil)
	if err != nil {
		return
	}
	res := p.sent.onAck(now, ack, intervals)
	if res.hasRTT {
		p.rtt.update(res.rttSample, time.Duration(ack.AckDelayMicros)*time.Microsecond)
	}
	if res.ackedProbe && c.probeSize > p.maxPacket {
		p.maxPacket = c.probeSize
	}
	for _, e := range res.ackedEpochs {
		if e == c.send.Epoch() {
			c.ackedThisEpoch = true
		}
	}
	c.stats.PacketsLost += uint64(res.lostCount)
	c.requeue(p, res.lost)
}

func (c *conn) requeue(p *path, frames []wire.Frame) {
	for _, f := range frames {
		if pathBound(f) {
			p.control = append(p.control, f)
		} else {
			c.control = append(c.control, f)
		}
	}
}

// queue adds a control frame that may travel on any path and is
// retransmitted until acknowledged.
func (c *conn) queue(f wire.Frame) { c.control = append(c.control, f) }

// flush sends pending path-bound frames, due acknowledgements, and unbound
// control frames on the primary path.
func (c *conn) flush(now time.Time) {
	for _, p := range c.paths {
		for len(p.control) > 0 || p.acks.due(now) {
			if !c.transmit(now, p, nil) {
				break
			}
		}
	}
	if prim := c.primary(now); prim != nil {
		for len(c.control) > 0 {
			if !c.transmit(now, prim, nil) {
				break
			}
		}
	}
}

func (c *conn) transmit(now time.Time, p *path, extra []wire.Frame) bool {
	return c.transmitTo(now, p, extra, false)
}

// transmitTo builds and sends one packet on p carrying the frames in extra
// (which must fit), a pending ACK, the path's own control frames, and, on
// the primary path, unbound control frames. It reports whether a packet was
// sent. toCandidate directs a relay's packet to the path's unvalidated new
// address.
func (c *conn) transmitTo(now time.Time, p *path, extra []wire.Frame, toCandidate bool) bool {
	if !p.joined {
		return false
	}
	budget := p.maxPacket - wire.DataHeaderLen - wire.AEADTagLen
	var pt []byte
	for _, f := range extra {
		pt = wire.AppendFrame(pt, f)
	}
	if len(pt) > budget {
		panic("session: frames exceed path budget")
	}
	if p.acks.unacked > 0 { // piggyback a pending acknowledgement if it fits
		if next := wire.AppendFrame(pt, p.acks.peek(now, p.id)); len(next) <= budget {
			pt = next
			p.acks.sent()
		}
	}
	var retx []wire.Frame
	take := func(q *[]wire.Frame) {
		for len(*q) > 0 {
			next := wire.AppendFrame(pt, (*q)[0])
			if len(next) > budget {
				return
			}
			pt = next
			retx = append(retx, (*q)[0])
			*q = (*q)[1:]
		}
	}
	take(&p.control)
	if !toCandidate && len(c.control) > 0 && p == c.primary(now) {
		take(&c.control)
	}
	if len(pt) == 0 {
		return false
	}
	ackEliciting := len(retx) > 0
	for _, f := range extra {
		ackEliciting = ackEliciting || f.Type().AckEliciting()
	}
	c.seal(now, p, pt, retx, ackEliciting, false, toCandidate)
	return true
}

func (c *conn) seal(now time.Time, p *path, pt []byte, retx []wire.Frame, ackEliciting, probe, toCandidate bool) {
	pn := p.nextPN
	p.nextPN++
	epoch := c.send.Epoch()
	pkt := c.send.Seal(nil, wire.DataHeader{DestCID: p.remoteCID, PacketNumber: pn}, p.id, pt)
	if ackEliciting {
		p.sent.add(sentPacket{pn: pn, sentAt: now, epoch: epoch, frames: retx, probe: probe})
	}
	p.lastSend = now
	c.stats.PacketsSent++
	c.emit(p, pkt, toCandidate)
	c.maybeRekey(now)
}

// probe sends one padded PING of probeSize bytes on a validated path. If it
// is acknowledged the path carries full-size packets without IP_FRAGMENT.
// A lost probe leaves the path at its current size (§14.4).
func (c *conn) probe(now time.Time, p *path) {
	if p.probed || !p.validated || c.probeSize <= p.maxPacket {
		return
	}
	p.probed = true
	pt := wire.AppendFrame(nil, wire.Ping{})
	pad := c.probeSize - wire.DataHeaderLen - wire.AEADTagLen - len(pt) - wire.FrameHeaderLen
	pt = wire.AppendFrame(pt, wire.Padding{Len: pad})
	c.seal(now, p, pt, nil, true, true, false)
}

// maybeRekey advances the send epoch once it is due and a packet of the
// current epoch has been acknowledged (§13).
func (c *conn) maybeRekey(now time.Time) {
	if c.ackedThisEpoch && c.send.RekeyDue(now) {
		c.send.Advance(now)
		c.ackedThisEpoch = false
		c.stats.Rekeys++
	}
}

// sendIP sends one IP packet on the primary path, fragmenting it to fit.
func (c *conn) sendIP(now time.Time, pkt []byte) error {
	p := c.primary(now)
	if p == nil {
		return ErrNoPath
	}
	budget := p.maxPacket - wire.DataHeaderLen - wire.AEADTagLen
	if wire.FrameHeaderLen+len(pkt) <= budget {
		c.transmit(now, p, []wire.Frame{wire.IPPacket{Packet: pkt}})
		return nil
	}
	maxData := budget - wire.FrameHeaderLen - 12
	c.fragBuf = reassembly.Fragment(c.fragBuf[:0], c.nextDatagramID, pkt, maxData)
	c.nextDatagramID++
	for _, f := range c.fragBuf {
		c.transmit(now, p, []wire.Frame{f})
	}
	return nil
}

// receiveFragment adds an IP_FRAGMENT and returns a completed packet.
func (c *conn) receiveFragment(now time.Time, f wire.IPFragment) []byte {
	pkt, _ := c.reasm.Add(now, f)
	return pkt
}

// onTimers handles PTO expiry and pending acknowledgements.
func (c *conn) onTimers(now time.Time) {
	for _, p := range c.paths {
		if d := p.sent.ptoDeadline(&p.rtt); !d.IsZero() && !now.Before(d) {
			c.requeue(p, p.sent.onPTO())
		}
		p.sent.expire(now, sentHorizon)
	}
	c.reasm.Expire(now)
	c.flush(now)
}

func (c *conn) nextDeadline() time.Time {
	var d time.Time
	for _, p := range c.paths {
		d = earliest(d, p.acks.deadline(), p.sent.ptoDeadline(&p.rtt))
	}
	return d
}

// earliest returns the earliest non-zero time.
func earliest(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if !t.IsZero() && (out.IsZero() || t.Before(out)) {
			out = t
		}
	}
	return out
}

func copyBytes(b []byte) []byte { return append([]byte(nil), b...) }
