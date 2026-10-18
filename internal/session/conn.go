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
	outageSilence        = time.Second
	maxRetiredCIDs       = 2 * maxPaths // per session; see Relay.retired
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
	// ErrHandshakeTimeout ends a relay session the client never
	// authenticated, such as one of the extra handshakes a client with
	// several carriers starts (§9.2).
	ErrHandshakeTimeout = errors.New("session: handshake timed out")
	ErrStatelessReset   = errors.New("session: relay reset the session")
	ErrIdleTimeout      = errors.New("session: idle timeout")
	ErrPathTimeout      = errors.New("session: path timed out")
	ErrPathAbandoned    = errors.New("session: path abandoned by peer")
	ErrIntegrityLimit   = errors.New("session: too many authentication failures")
	ErrPathLimit        = errors.New("session: path IDs exhausted; establish a new session")
	ErrCapacity         = errors.New("session: authenticated session limit reached")
	// ErrProtocolViolation ends a session whose peer broke the protocol,
	// such as by sending beyond a stream's flow control limit.
	ErrProtocolViolation = errors.New("session: peer violated the protocol")
	errReplay            = errors.New("session: replayed or stale packet")
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
	MinRTT    time.Duration
	Loss      float64 // worse direction's recent loss rate; 0 if unmeasured
	Burst     float64 // mean length of loss runs in the send direction; 0 if none seen
	// StreamRate is the pace of stream data (streamcc.go), in bytes per
	// second, and StreamInflight its bytes in flight; 0 if unused.
	StreamRate     float64
	StreamInflight int
	// Stream rate backoffs so far: for queueing delay, for a loss spike,
	// and of those, in rounds that didn't use the rate; and stalls seen.
	StreamBackoffsDelay, StreamBackoffsLoss, StreamBackoffsIdle, StreamStalls int
	MaxPacket                                                                 int
	LastRecv                                                                  time.Time
	Flows                                                                     int     // flows pinned to the path (§15.2)
	Capacity                                                                  float64 // estimated, in bytes per second; 0 if unmeasured
	Eligible                                                                  bool    // may take new flows
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
	burst      float64       // mean length of loss runs in the send direction, 0 if none seen
	sendLoss   lossEstimator // from acknowledgements; see loss.go
	recvLoss   lossEstimator // from gaps in received packet numbers
	sendRate   rateMax       // acknowledged bytes per second; see sched.go
	recvRate   rateMax       // received bytes per second
	cc         streamCC      // paces stream data; see streamcc.go
	flows      int           // active flows pinned to this path (sched.go)
	// fallback marks a path to use only when no other path is healthy,
	// such as one over TLS/TCP, where tunneled TCP suffers head-of-line
	// blocking (§16.3). Client only.
	fallback  bool
	overSince time.Time // when the path rose over keepFlowRatio; see keeps
	ratio     float64   // cached conn.costRatio result, until ratioAt
	ratioOK   bool
	ratioAt   time.Time
	control   []wire.Frame // frames that must travel on this path
	probed    bool
	created   time.Time
	lastSend  time.Time
	lastRecv  time.Time

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
	// skippedAt is when the client joined a higher slot while this one
	// was unjoined; the slot is retired if no JOIN follows (see onJoin).
	skippedAt time.Time
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
	if silent > idleLimit(keepalive, limit) {
		return false
	}
	t0, ok := p.sent.oldestOutstanding()
	return !ok || now.Sub(t0) < limit || silent < limit
}

// idleLimit is how long a path may go without receiving anything before it
// is suspect even with nothing outstanding. An idle path hears from the
// peer about once per keepalive interval (the relay hears the client's
// keepalives themselves), so the limit allows half an interval of slack
// for timers that fire late on a busy host: with only a few PTOs of slack,
// the relay judged idle standby paths unhealthy just before each keepalive.
func idleLimit(keepalive, limit time.Duration) time.Duration {
	return keepalive + max(limit, keepalive/2)
}

// suspectAt returns when a currently healthy path would turn suspect if
// nothing else happened, so callers can wake up and start probing it.
func (p *path) suspectAt(keepalive time.Duration) time.Time {
	limit := suspectPTOs * p.rtt.pto()
	at := p.lastRecv.Add(idleLimit(keepalive, limit) + time.Nanosecond)
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
	// highestPathID is the highest path ID ever added. Path IDs only
	// increase, so a path's nonce space (path ID and packet number under
	// the session's keys) is never recreated, without remembering every
	// retired path: a session's paths can come and go indefinitely.
	highestPathID uint32

	// primary chooses the path for unbound control frames, and pathFor
	// the path for each IP packet (the primary when nil); see sched.go.
	primary func(now time.Time) *path
	pathFor func(now time.Time, pkt []byte) *path
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
	fec       fecState
	secondAt  time.Time
	streams   streamSet // see stream.go
	// streamWake is when pacing next lets stream data go, if it is waiting.
	streamWake time.Time

	plaintext    []byte
	ptScratch    []byte // reused to build each outgoing packet's plaintext
	streamFrames []wire.Frame
	ackScratch   []byte
	ivScratch    []wire.PacketRange
	frameBuf     []wire.Frame
	fragBuf      []wire.IPFragment

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
	FECRepairsSent               uint64 // FEC repair symbols sent
	FECRecovered                 uint64 // IP packets rebuilt from FEC repairs
	StreamBytesSent              uint64 // stream data sent, counting retransmissions
	StreamBytesRetransmitted     uint64 // sent again because they were lost
	StreamBytesRepeated          uint64 // sent again while in flight, on a very lossy path
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

func (c *conn) addPath(p *path) bool {
	if (len(c.paths) > 0 || c.highestPathID > 0) && p.id <= c.highestPathID || c.byCID[p.localCID] != nil {
		return false
	}
	c.highestPathID = p.id
	i, _ := slices.BinarySearchFunc(c.paths, p.id, func(q *path, id uint32) int { return int(q.id) - int(id) })
	c.paths = slices.Insert(c.paths, i, p)
	c.byCID[p.localCID] = p
	return true
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
					c.requeueFrame(p, f)
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

// abandonAt returns when p is abandoned for silence: timeout after it last
// received anything, provided another validated path received something at
// least timeout/2 after that, showing the silence is p's own. Otherwise it
// returns zero. When every path falls silent together the trouble is
// shared (the relay, or loss on every link), and closing paths would only
// discard state that rejoining could not rebuild under the same
// conditions; the session idle timeout governs that case. The answer
// changes only when a packet arrives, so it is also a stable deadline.
func (c *conn) abandonAt(p *path, timeout time.Duration) time.Time {
	for _, q := range c.paths {
		if q != p && q.validated && q.lastRecv.Sub(p.lastRecv) >= timeout/2 {
			return p.lastRecv.Add(timeout)
		}
	}
	return time.Time{}
}

// bestPath returns the healthy validated path with the lowest cost (RTT
// and loss; see loss.go), preferring paths not marked fallback, and
// otherwise any validated path.
func (c *conn) bestPath(now time.Time) *path {
	var best, any *path
	var bestCost float64
	for _, p := range c.paths {
		if !p.validated {
			continue
		}
		if any == nil {
			any = p
		}
		if !p.healthy(now, c.keepalive) {
			continue
		}
		cost := p.cost(now)
		if best == nil || (best.fallback && !p.fallback) || (best.fallback == p.fallback && cost < bestCost) {
			best, bestCost = p, cost
		}
	}
	if best != nil {
		return best
	}
	return any
}

func (c *conn) pathInfo(now time.Time) []PathInfo {
	prim := c.primary(now)
	out := make([]PathInfo, 0, len(c.paths))
	for _, p := range c.paths {
		if !p.joined {
			continue
		}
		loss, _ := p.loss(now)
		info := PathInfo{
			ID: p.id, Validated: p.validated, Healthy: p.healthy(now, c.keepalive), Primary: p == prim,
			SRTT: p.rtt.srtt(), MinRTT: p.rtt.minRTT(), Loss: loss, MaxPacket: p.maxPacket, LastRecv: p.lastRecv,
			Flows: p.flows, Capacity: p.capacity(now), Burst: p.burst,
			StreamRate: p.cc.rate, StreamInflight: p.sent.streamBytes,
			StreamBackoffsDelay: p.cc.backoffsDelay, StreamBackoffsLoss: p.cc.backoffsLoss,
			StreamBackoffsIdle: p.cc.backoffsIdle, StreamStalls: p.cc.stalls,
		}
		if prim != nil {
			info.Eligible = c.eligible(now, p, prim)
		}
		out = append(out, info)
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
	p.recvRate.add(now, len(ct)+wire.DataHeaderLen)
	// A path heard from again after an outage (nothing received for
	// outageSilence while a packet sent at least that long ago was waiting
	// for an answer) starts its loss estimates afresh: what was lost was
	// the outage, which health accounts for, and it would otherwise linger
	// as loss and keep flows off the recovered path (§15.2). An idle path
	// is silent without an outage, and a path with heavy random loss falls
	// silent briefly and often; resetting then would erase its evidence.
	recovered := false
	if p.validated && now.Sub(p.lastRecv) >= outageSilence {
		t0, waiting := p.sent.oldestOutstanding()
		recovered = waiting && now.Sub(t0) >= outageSilence
	}
	if recovered {
		p.sendLoss, p.recvLoss = lossEstimator{}, lossEstimator{}
	}
	p.replay.Record(h.PacketNumber)
	p.lastRecv = now
	c.stats.PacketsReceived++

	frames, err := wire.ParseFrames(c.frameBuf[:0], pt)
	if err != nil {
		return nil, err
	}
	c.frameBuf = frames
	ackEliciting, stream := false, false
	for _, f := range frames {
		ackEliciting = ackEliciting || f.Type().AckEliciting()
		stream = stream || f.Type() == wire.FrameStream
	}
	if top, ok := p.acks.largest(); !ok {
		p.recvLoss.record(now, 1, 0)
	} else if pn := h.PacketNumber; pn > top {
		gap := int(min(pn-top-1, 1<<20))
		if recovered {
			gap = 0 // packets the peer sent into the outage
		}
		p.recvLoss.record(now, gap+1, gap)
	} else {
		p.recvLoss.record(now, 0, -1) // late: counted as lost when the gap opened
	}
	p.acks.onReceive(h.PacketNumber, now, ackEliciting, stream)
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
	lossDelay := max(p.rtt.srtt(), p.rtt.latest) * timeThresholdNum / timeThresholdDen
	res := p.sent.onAck(now, ack, intervals, c.send.Epoch(), max(lossDelay, time.Millisecond))
	if res.hasRTT {
		p.rtt.update(now, res.rttSample, time.Duration(ack.AckDelayMicros)*time.Microsecond)
		p.cc.observeRTT(now, res.rttSample)
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
	if res.runCount > 0 {
		mean := float64(res.runSum) / float64(res.runCount)
		if p.burst == 0 {
			p.burst = mean
		} else {
			p.burst += lossGain * (mean - p.burst)
		}
	}
	if res.deliveredBytes > 0 {
		p.sendRate.add(now, res.deliveredBytes)
	}
	c.stats.PacketsLost += uint64(res.lostCount)
	if res.streamAcked > 0 || res.streamLost > 0 {
		var rtt time.Duration
		if res.hasRTT {
			rtt = res.rttSample
		}
		p.cc.onAck(now, res.streamAcked, res.streamLost, res.streamAckedBytes, rtt)
		for _, f := range res.streamFrames {
			if sf, ok := f.(wire.Stream); ok {
				c.onStreamAcked(sf)
			}
		}
	}
	c.requeue(p, res.lost)
}

func (c *conn) requeue(p *path, frames []wire.Frame) {
	for _, f := range frames {
		if pathBound(f) {
			p.control = append(p.control, f)
		} else {
			c.requeueFrame(p, f)
		}
	}
}

// requeueFrame retransmits an unbound frame that p lost: stream data
// through its stream, anything else as a control frame.
func (c *conn) requeueFrame(p *path, f wire.Frame) {
	if sf, ok := f.(wire.Stream); ok {
		c.onStreamLost(sf)
		return
	}
	c.control = append(c.control, f)
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
	c.sendStreams(now)
}

// sendStreams sends stream data on the primary path while its rate
// control allows (streamcc.go), noting when pacing will next allow more.
func (c *conn) sendStreams(now time.Time) {
	c.streamWake = time.Time{}
	if !c.streams.enabled {
		return
	}
	p := c.primary(now)
	if p == nil || !p.validated || len(c.streams.ready) == 0 && !p.cc.lossy() {
		return
	}
	srtt := p.rtt.srtt()
	p.cc.update(now, p.cc.baseRTT(p.rtt.minRTT()), srtt, p.maxPacket)
	budget := p.maxPacket - wire.DataHeaderLen - wire.AEADTagLen
	for {
		ok, wake := p.cc.canSend(now, p.sent.streamBytes, srtt, p.maxPacket)
		if !ok {
			c.streamWake = wake
			return
		}
		frames, used := c.streamFrames[:0], 0
		next := c.nextStreamFrame
		for budget-used > wire.FrameHeaderLen+13 {
			f, ok := next(budget - used)
			if !ok && len(frames) == 0 && p.cc.lossy() {
				next = c.nextRepeatFrame
				f, ok = next(budget - used)
			}
			if !ok {
				break
			}
			frames = append(frames, f)
			used += wire.FrameHeaderLen + 13 + len(f.Data)
		}
		c.streamFrames = frames[:0]
		if len(frames) == 0 {
			return
		}
		// The sent packet keeps the frames for retransmission.
		c.transmitPacket(now, p, nil, slices.Clone(frames), ipPayload{}, false)
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
	return c.transmitPacket(now, p, extra, nil, ip, toCandidate)
}

// transmitPacket is transmitTo with stream frames first, which (unlike
// extra) are retransmitted if lost, and which together with extra must fit.
func (c *conn) transmitPacket(now time.Time, p *path, extra, stream []wire.Frame, ip ipPayload, toCandidate bool) bool {
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
	for _, f := range stream {
		pt = wire.AppendFrame(pt, f)
	}
	for _, f := range extra {
		pt = wire.AppendFrame(pt, f)
	}
	if len(pt) > budget {
		panic("session: frames exceed path budget")
	}
	acked := false
	if p.acks.unacked > 0 { // piggyback a pending acknowledgement if it fits
		if next := wire.AppendFrame(pt, p.acks.peek(now, p.id)); len(next) <= budget {
			pt = next
			p.acks.sent()
			acked = true
		}
	}
	retx := stream
	pt, retx = takeFrames(pt, retx, &p.control, budget)
	pathBound := len(retx)
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
	ping := ip.pkt == nil && len(retx) == 0 && !carriesRepair(extra)
	c.sealPacket(now, p, pt, retx, ackEliciting, 0, ping, len(stream) > 0, toCandidate)
	if acked && !toCandidate {
		c.copyAck(now, p)
	}
	if len(stream) > 0 {
		n := 0
		for _, f := range stream {
			n += len(f.(wire.Stream).Data)
		}
		c.stats.StreamBytesSent += uint64(n)
	}
	if unbound := retx[pathBound:]; len(unbound) > 0 && !p.healthy(now, c.keepalive) {
		c.copyControl(now, p, unbound)
	}
	return true
}

// ackCopies is how many more times each acknowledgement goes out on a path
// losing at least half its packets: the peer learns of losses, and its
// stream rate control of anything, only from the acknowledgements that
// arrive, and at 90% loss one in ten does.
const ackCopies = 2

// copyAck sends ackCopies extra copies of the acknowledgement just sent on
// p, if p is that lossy.
func (c *conn) copyAck(now time.Time, p *path) {
	if loss, ok := p.loss(now); !ok || loss < ccLossy {
		return
	}
	pt := wire.AppendFrame(c.ackScratch[:0], p.acks.peek(now, p.id))
	c.ackScratch = pt
	for range ackCopies {
		c.seal(now, p, pt, nil, false, 0, false)
	}
}

// copyControl sends copies of unbound control frames on every validated
// path other than p, the unhealthy path that carries the tracked original.
// Copies are not retransmitted; the original is. Under heavy loss on every
// path this gets frames such as REDUNDANCY and PATH_ABANDON through several
// times faster (§15.2 item 4).
func (c *conn) copyControl(now time.Time, p *path, frames []wire.Frame) {
	n := 0
	for _, f := range frames {
		n += len(wire.AppendFrame(c.ptScratch[:0], f))
	}
	for _, q := range c.paths {
		if q != p && q.validated && q.joined && n <= q.maxPacket-wire.DataHeaderLen-wire.AEADTagLen {
			c.transmit(now, q, frames)
		}
	}
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
	c.sealPacket(now, p, pt, retx, ackEliciting, probe, false, false, toCandidate)
}

// sealPacket encrypts and sends one packet; ping marks a packet that
// carries no IP payload or control frame (see sentPacket.ping), and stream
// one that carries STREAM frames.
func (c *conn) sealPacket(now time.Time, p *path, pt []byte, retx []wire.Frame, ackEliciting bool, probe int, ping, stream, toCandidate bool) {
	pn := p.nextPN
	p.nextPN++
	epoch := c.send.Epoch()
	// The packet buffer comes from the pool; whoever sends it returns it.
	pkt := c.send.Seal(bufpool.Get(), wire.DataHeader{DestCID: p.remoteCID, PacketNumber: pn}, p.id, pt)
	if ackEliciting {
		p.sent.add(sentPacket{pn: pn, sentAt: now, epoch: epoch, frames: retx, probe: probe, size: len(pkt), ping: ping, stream: stream})
	}
	if stream {
		p.cc.onSent(now, len(pkt))
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

// carriesRepair reports whether frames include an FEC repair, whose loss
// says as much about a path as a data packet's.
func carriesRepair(frames []wire.Frame) bool {
	for _, f := range frames {
		if f.Type() == wire.FrameFECRepair {
			return true
		}
	}
	return false
}

// setProbeSizes sets the MTU probe sizes for a TUN MTU (§14.4). datagrams
// says whether IP_DATAGRAM may be sent (redundancy or FEC negotiated),
// whose packets and FEC repairs are 8 bytes larger.
func (c *conn) setProbeSizes(tunMTU uint16, datagrams bool) {
	c.probeSizes = []int{int(tunMTU) + dataOverhead}
	if datagrams {
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
	var p *path
	if c.pathFor != nil {
		p = c.pathFor(now, pkt)
	} else {
		p = c.primary(now)
	}
	if p == nil {
		return ErrNoPath
	}
	var q *path
	if c.redundant {
		q = c.secondPath(now, p)
	}
	c.fec.sent++
	protect := c.fecSending(now)
	ip := ipPayload{pkt: pkt}
	if q != nil || protect {
		ip.id, ip.hasID = c.nextDatagramID, true
		c.nextDatagramID++
	}
	c.sendOn(now, p, ip)
	if q != nil {
		c.sendOn(now, q, ip)
		c.stats.RedundantSent++
	}
	if protect {
		c.fecAdd(now, ip.id, pkt)
	}
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
// falling back, like bestPath, to any other validated path: when loss is
// heavy enough that no path counts as healthy, copies matter most. The
// choice is cached briefly, since it is made per packet.
func (c *conn) secondPath(now time.Time, p *path) *path {
	if q := c.second; q != nil && q != p && !q.removed && now.Before(c.secondAt) {
		return q
	}
	c.second, c.secondAt = nil, now.Add(secondPathRefresh)
	var fallback *path
	var bestCost float64
	for _, q := range c.paths {
		if q == p || !q.validated {
			continue
		}
		if fallback == nil {
			fallback = q
		}
		if !q.healthy(now, c.keepalive) {
			continue
		}
		if cost := q.cost(now); c.second == nil || cost < bestCost {
			c.second, bestCost = q, cost
		}
	}
	if c.second == nil {
		c.second = fallback
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
	c.fecTimers(now)
	c.flush(now)
}

func (c *conn) nextDeadline() time.Time {
	d := earliest(c.fecDeadline(), c.streamWake)
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
