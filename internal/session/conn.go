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

	"github.com/laneshetron/arc/internal/bufpool"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/reassembly"
	"github.com/laneshetron/arc/internal/wire"
)

// Defaults from the spec.
const (
	HandshakeTimeout = 10 * time.Second
	// handshakeRetransmit is the interval at which the client repeats
	// HANDSHAKE_INIT and AUTH until answered (§9.2). It does not back off:
	// the packets are small, a duplicate INIT costs the relay no
	// Diffie-Hellman, and on a link losing most packets only the number of
	// attempts within the timeout matters. After handshakeQuiet without
	// hearing from the relay at all, the relay is more likely down than
	// the link lossy, and the client slows to handshakeRetransmitQuiet
	// until it hears something.
	handshakeRetransmit      = 100 * time.Millisecond
	handshakeRetransmitQuiet = time.Second
	handshakeQuiet           = 30 * time.Second
	// relayPendingTimeout is how long the relay keeps a session that has
	// not authenticated: the client's INIT phase and AUTH phase may each
	// take up to HandshakeTimeout.
	relayPendingTimeout  = 2 * HandshakeTimeout
	DefaultMaxPacketSize = 1232 // safe on any IPv6 path (§16.1)
	DefaultKeepalive     = 10 * time.Second
	DefaultIdleTimeout   = 120 * time.Second
	DefaultPathTimeout   = 30 * time.Second // no packets received: the path is dead
	sentHorizon          = 30 * time.Second
	secondPathRefresh    = 100 * time.Millisecond
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
	Loss      float64 // worse direction's recent loss rate; 0 if unmeasured
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
	sendLoss   lossEstimator // from acknowledgements; see loss.go
	recvLoss   lossEstimator // from gaps in received packet numbers
	control    []wire.Frame  // frames that must travel on this path
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
	dedup          reassembly.Window // datagram IDs delivered (§11.1)
	// probeSizes are the MTU probes sent on each path: the UDP payload
	// needed for an unfragmented TUN packet in IP_PACKET and, when
	// redundancy is negotiated, in IP_DATAGRAM.
	probeSizes []int

	// redundant sends each IP packet on the primary and a second path
	// (§11.1): uplink for the client, downlink for the relay.
	redundant bool
	second    *path // cached second path; see secondPath
	secondAt  time.Time

	plaintext []byte
	ptScratch []byte // reused to build each outgoing packet's plaintext
	ivScratch []wire.PacketRange
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
	RedundantSent                uint64 // IP packets sent on two paths
	DuplicatesDropped            uint64 // received copies already delivered
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

// bestPath returns the healthy validated path with the lowest cost (RTT
// and loss; see loss.go), falling back to any validated path.
func (c *conn) bestPath(now time.Time) *path {
	var best, fallback *path
	var bestCost float64
	for _, p := range c.paths {
		if !p.validated {
			continue
		}
		if fallback == nil {
			fallback = p
		}
		if !p.healthy(now, c.keepalive) {
			continue
		}
		if cost := p.cost(now); best == nil || cost < bestCost {
			best, bestCost = p, cost
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
		loss, _ := p.loss(now)
		out = append(out, PathInfo{
			ID: p.id, Validated: p.validated, Healthy: p.healthy(now, c.keepalive), Primary: p == prim,
			SRTT: p.rtt.srtt(), Loss: loss, MaxPacket: p.maxPacket, LastRecv: p.lastRecv,
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
	if top, ok := p.acks.largest(); !ok {
		p.recvLoss.record(now, 1, 0)
	} else if pn := h.PacketNumber; pn > top {
		gap := int(min(pn-top-1, 1<<20))
		p.recvLoss.record(now, gap+1, gap)
	} else {
		p.recvLoss.record(now, 0, -1) // late: counted as lost when the gap opened
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
	intervals, err := ack.AppendIntervals(c.ivScratch[:0])
	if err != nil {
		return
	}
	c.ivScratch = intervals
	res := p.sent.onAck(now, ack, intervals, c.send.Epoch())
	if res.hasRTT {
		p.rtt.update(res.rttSample, time.Duration(ack.AckDelayMicros)*time.Microsecond)
	}
	if res.ackedProbe > p.maxPacket {
		p.maxPacket = res.ackedProbe
	}
	if res.ackedCurrentEpoch {
		c.ackedThisEpoch = true
	}
	if n := res.delivered + res.lostCount; n > 0 {
		p.sendLoss.record(now, n, res.lostCount)
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
	return c.transmitTo(now, p, extra, ipPayload{}, false)
}

// ipPayload is an IP packet for transmitTo, carried as IP_DATAGRAM when it
// has a datagram ID and as IP_PACKET otherwise.
type ipPayload struct {
	pkt   []byte
	id    uint64
	hasID bool
}

func (ip ipPayload) frameLen() int {
	n := wire.FrameHeaderLen + len(ip.pkt)
	if ip.hasID {
		n += 8
	}
	return n
}

// transmitTo builds and sends one packet on p carrying the frames in extra
// (which must fit), a pending ACK, the path's own control frames, and, on
// the primary path, unbound control frames. It reports whether a packet was
// sent. toCandidate directs a relay's packet to the path's unvalidated new
// address.
func (c *conn) transmitTo(now time.Time, p *path, extra []wire.Frame, ip ipPayload, toCandidate bool) bool {
	if !p.joined {
		return false
	}
	budget := p.maxPacket - wire.DataHeaderLen - wire.AEADTagLen
	pt := c.ptScratch[:0]
	switch {
	case ip.hasID:
		pt = wire.AppendIPDatagram(pt, ip.id, ip.pkt)
	case ip.pkt != nil:
		pt = wire.AppendIPPacket(pt, ip.pkt)
	}
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
	pt, retx = takeFrames(pt, retx, &p.control, budget)
	if !toCandidate && len(c.control) > 0 && p == c.primary(now) {
		pt, retx = takeFrames(pt, retx, &c.control, budget)
	}
	c.ptScratch = pt[:0] // keep any growth for the next packet
	if len(pt) == 0 {
		return false
	}
	ackEliciting := len(retx) > 0 || ip.pkt != nil
	for _, f := range extra {
		ackEliciting = ackEliciting || f.Type().AckEliciting()
	}
	c.seal(now, p, pt, retx, ackEliciting, 0, toCandidate)
	return true
}

// takeFrames moves frames from the front of q into the plaintext while they
// fit in budget, recording them for retransmission.
func takeFrames(pt []byte, retx []wire.Frame, q *[]wire.Frame, budget int) ([]byte, []wire.Frame) {
	for len(*q) > 0 {
		next := wire.AppendFrame(pt, (*q)[0])
		if len(next) > budget {
			break
		}
		pt = next
		retx = append(retx, (*q)[0])
		*q = (*q)[1:]
	}
	return pt, retx
}

func (c *conn) seal(now time.Time, p *path, pt []byte, retx []wire.Frame, ackEliciting bool, probe int, toCandidate bool) {
	pn := p.nextPN
	p.nextPN++
	epoch := c.send.Epoch()
	// The packet buffer comes from the pool; whoever sends it returns it.
	pkt := c.send.Seal(bufpool.Get(), wire.DataHeader{DestCID: p.remoteCID, PacketNumber: pn}, p.id, pt)
	if ackEliciting {
		p.sent.add(sentPacket{pn: pn, sentAt: now, epoch: epoch, frames: retx, probe: probe})
	}
	p.lastSend = now
	c.stats.PacketsSent++
	c.emit(p, pkt, toCandidate)
	c.maybeRekey(now)
}

// probe sends a padded PING of each probe size on a validated path. The
// path's maximum packet size rises to the largest one acknowledged, so it
// carries full-size packets without IP_FRAGMENT. A lost probe leaves the
// path at its current size (§14.4).
func (c *conn) probe(now time.Time, p *path) {
	if p.probed || !p.validated {
		return
	}
	p.probed = true
	for _, size := range c.probeSizes {
		if size <= p.maxPacket {
			continue
		}
		pt := wire.AppendFrame(nil, wire.Ping{})
		pad := size - wire.DataHeaderLen - wire.AEADTagLen - len(pt) - wire.FrameHeaderLen
		pt = wire.AppendFrame(pt, wire.Padding{Len: pad})
		c.seal(now, p, pt, nil, true, size, false)
	}
}

// setProbeSizes sets the MTU probe sizes for a TUN MTU (§14.4).
func (c *conn) setProbeSizes(tunMTU uint16, redundancy bool) {
	c.probeSizes = []int{int(tunMTU) + dataOverhead}
	if redundancy {
		c.probeSizes = append(c.probeSizes, int(tunMTU)+dataOverhead+8)
	}
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
// With redundancy on, it sends a copy with the same datagram ID on a second
// path too (§11.1).
func (c *conn) sendIP(now time.Time, pkt []byte) error {
	p := c.primary(now)
	if p == nil {
		return ErrNoPath
	}
	if c.redundant {
		if q := c.secondPath(now, p); q != nil {
			ip := ipPayload{pkt: pkt, id: c.nextDatagramID, hasID: true}
			c.nextDatagramID++
			c.sendOn(now, p, ip)
			c.sendOn(now, q, ip)
			c.stats.RedundantSent++
			return nil
		}
	}
	c.sendOn(now, p, ipPayload{pkt: pkt})
	return nil
}

// sendOn sends an IP packet on p, as IP_FRAGMENTs if it does not fit. The
// fragments use the packet's datagram ID if it has one.
func (c *conn) sendOn(now time.Time, p *path, ip ipPayload) {
	budget := p.maxPacket - wire.DataHeaderLen - wire.AEADTagLen
	if ip.frameLen() <= budget {
		c.transmitTo(now, p, nil, ip, false)
		return
	}
	id := ip.id
	if !ip.hasID {
		id = c.nextDatagramID
		c.nextDatagramID++
	}
	maxData := budget - wire.FrameHeaderLen - 12
	c.fragBuf = reassembly.Fragment(c.fragBuf[:0], id, ip.pkt, maxData)
	for _, f := range c.fragBuf {
		c.transmit(now, p, []wire.Frame{f})
	}
}

// secondPath returns the healthy path other than p with the lowest cost,
// or nil. The choice is cached briefly, since it is made per packet.
func (c *conn) secondPath(now time.Time, p *path) *path {
	if q := c.second; q != nil && q != p && !q.removed && now.Before(c.secondAt) {
		return q
	}
	c.second, c.secondAt = nil, now.Add(secondPathRefresh)
	var bestCost float64
	for _, q := range c.paths {
		if q == p || !q.healthy(now, c.keepalive) {
			continue
		}
		if cost := q.cost(now); c.second == nil || cost < bestCost {
			c.second, bestCost = q, cost
		}
	}
	return c.second
}

// receiveFragment adds an IP_FRAGMENT and returns a completed packet that
// was not already delivered.
func (c *conn) receiveFragment(now time.Time, f wire.IPFragment) []byte {
	pkt, _ := c.reasm.Add(now, f)
	if pkt != nil && !c.dedup.Deliver(f.DatagramID) {
		c.stats.DuplicatesDropped++
		return nil
	}
	return pkt
}

// receiveDatagram reports whether an IP_DATAGRAM is new (§11.1).
func (c *conn) receiveDatagram(f wire.IPDatagram) bool {
	if !c.dedup.Deliver(f.DatagramID) {
		c.stats.DuplicatesDropped++
		return false
	}
	return true
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

// copyBytes copies a packet into a pooled buffer, which the receiver of
// the event returns with bufpool.Put.
func copyBytes(b []byte) []byte {
	if len(b) > bufpool.Packet {
		return append([]byte(nil), b...)
	}
	return append(bufpool.Get(), b...)
}
