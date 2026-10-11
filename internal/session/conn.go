// Package session implements ARC/1 client and relay sessions as
// deterministic, I/O-free state machines (spec §9–§14). Callers feed in
// received packets and the current time, then drain outgoing datagrams,
// events, and the next timer deadline. Nothing here reads a clock, sleeps,
// or touches a socket.
package session

import (
	"errors"
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
	sentHorizon          = 30 * time.Second
)

var (
	ErrClosed         = errors.New("session: closed")
	ErrNotActive      = errors.New("session: not active")
	ErrPacketTooLarge = errors.New("session: packet larger than tunnel MTU")
	ErrAuthFailed     = errors.New("session: authentication failed")
	ErrStatelessReset = errors.New("session: relay reset the session")
	ErrIdleTimeout    = errors.New("session: idle timeout")
	ErrIntegrityLimit = errors.New("session: too many authentication failures")
	errReplay         = errors.New("session: replayed or stale packet")
)

// PeerClosedError reports a CLOSE frame from the peer.
type PeerClosedError struct{ Code wire.ErrorCode }

func (e *PeerClosedError) Error() string { return "session: closed by peer" }

// path is one validated path. In this version only path 0 exists; the
// multipath frames arrive in a later change.
type path struct {
	id         uint32
	localCID   wire.CID // CID the peer puts on packets to us
	remoteCID  wire.CID // CID we put on packets to the peer
	resetToken wire.Token
	maxPacket  int
	nextPN     uint64
	replay     crypto.ReplayWindow
	acks       ackTracker
	sent       sentLog
	rtt        rttEstimator
	lastSend   time.Time
	lastRecv   time.Time
}

func newPath(id uint32, local, remote wire.CID, now time.Time) *path {
	return &path{id: id, localCID: local, remoteCID: remote, maxPacket: DefaultMaxPacketSize, lastRecv: now}
}

// conn is the state shared by both roles once traffic keys exist.
type conn struct {
	send  *crypto.SendKeys
	recv  *crypto.RecvKeys
	path0 *path

	ackedThisEpoch bool
	control        []wire.Frame // retransmittable control frames waiting to be sent
	nextDatagramID uint64
	reasm          *reassembly.IP
	emit           func(p *path, b []byte)

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
}

func newConn(keys crypto.TrafficKeys, p0 *path, now time.Time, emit func(*path, []byte)) *conn {
	return &conn{
		send:  crypto.NewSendKeys(keys.Send, now),
		recv:  crypto.NewRecvKeys(keys.Recv),
		path0: p0,
		reasm: reassembly.New(reassembly.DefaultConfig()),
		emit:  emit,
	}
}

func (c *conn) pathByCID(cid wire.CID) *path {
	if c.path0.localCID == cid {
		return c.path0
	}
	return nil
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

// onAck processes an ACK frame for one of our paths.
func (c *conn) onAck(now time.Time, ack *wire.Ack) {
	p := c.path0
	if ack.PathID != p.id {
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
	for _, e := range res.ackedEpochs {
		if e == c.send.Epoch() {
			c.ackedThisEpoch = true
		}
	}
	c.stats.PacketsLost += uint64(res.lostCount)
	c.control = append(c.control, res.lost...)
}

// queue adds a control frame that is retransmitted until acknowledged.
func (c *conn) queue(f wire.Frame) { c.control = append(c.control, f) }

// flush sends pending control frames and any due acknowledgement.
func (c *conn) flush(now time.Time) {
	p := c.path0
	for len(c.control) > 0 || p.acks.due(now) {
		if !c.transmit(now, p, nil) {
			return
		}
	}
}

// transmit builds and sends one packet on p carrying a due ACK, as many
// queued control frames as fit, and the frames in extra (which must fit).
// It reports whether a packet was sent.
func (c *conn) transmit(now time.Time, p *path, extra []wire.Frame) bool {
	budget := p.maxPacket - wire.DataHeaderLen - wire.AEADTagLen
	var pt []byte
	for _, f := range extra {
		pt = wire.AppendFrame(pt, f)
	}
	if len(pt) > budget {
		panic("session: frames exceed path budget")
	}
	if p.acks.unacked > 0 { // piggyback a pending acknowledgement if it fits
		ack := p.acks.peek(now, p.id)
		if next := wire.AppendFrame(pt, ack); len(next) <= budget {
			pt = next
			p.acks.sent()
		}
	}
	var retx []wire.Frame
	for len(c.control) > 0 {
		next := wire.AppendFrame(pt, c.control[0])
		if len(next) > budget {
			break
		}
		pt = next
		retx = append(retx, c.control[0])
		c.control = c.control[1:]
	}
	if len(pt) == 0 {
		return false
	}

	pn := p.nextPN
	p.nextPN++
	epoch := c.send.Epoch()
	pkt := c.send.Seal(nil, wire.DataHeader{DestCID: p.remoteCID, PacketNumber: pn}, p.id, pt)
	ackEliciting := len(retx) > 0
	for _, f := range extra {
		ackEliciting = ackEliciting || f.Type().AckEliciting()
	}
	if ackEliciting {
		p.sent.add(sentPacket{pn: pn, sentAt: now, epoch: epoch, frames: retx})
	}
	p.lastSend = now
	c.stats.PacketsSent++
	c.emit(p, pkt)
	c.maybeRekey(now)
	return true
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

// sendIP sends one IP packet, fragmenting it to fit the path.
func (c *conn) sendIP(now time.Time, pkt []byte) {
	p := c.path0
	budget := p.maxPacket - wire.DataHeaderLen - wire.AEADTagLen
	if wire.FrameHeaderLen+len(pkt) <= budget {
		c.transmit(now, p, []wire.Frame{wire.IPPacket{Packet: pkt}})
		return
	}
	maxData := budget - wire.FrameHeaderLen - 12
	c.fragBuf = reassembly.Fragment(c.fragBuf[:0], c.nextDatagramID, pkt, maxData)
	c.nextDatagramID++
	for _, f := range c.fragBuf {
		c.transmit(now, p, []wire.Frame{f})
	}
}

// receiveFragment adds an IP_FRAGMENT and returns a completed packet.
func (c *conn) receiveFragment(now time.Time, f wire.IPFragment) []byte {
	pkt, _ := c.reasm.Add(now, f)
	return pkt
}

// onTimers handles PTO expiry and pending acknowledgements.
func (c *conn) onTimers(now time.Time) {
	p := c.path0
	if d := p.sent.ptoDeadline(&p.rtt); !d.IsZero() && !now.Before(d) {
		c.control = append(c.control, p.sent.onPTO()...)
	}
	p.sent.expire(now, sentHorizon)
	c.reasm.Expire(now)
	c.flush(now)
}

func (c *conn) nextDeadline() time.Time {
	p := c.path0
	return earliest(p.acks.deadline(), p.sent.ptoDeadline(&p.rtt))
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
