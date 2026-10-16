package session

import (
	"time"

	"github.com/laneshetron/arc/internal/fec"
	"github.com/laneshetron/arc/internal/wire"
)

// Forward error correction (spec §11.2). Each endpoint protects the
// traffic it sends according to a mode: the client's from its
// configuration, the relay's from the client's FEC frame. While active,
// every IP packet carries a datagram ID and goes through a Reed-Solomon
// encoder whose repairs follow each block on the primary path. Sizing
// comes from the sender's own loss measurements: the repair count from the
// loss rate, the interleaving depth from the mean burst length.
const (
	// In auto mode FEC turns on at fecOn loss and off below fecOff.
	fecOn  = 0.005
	fecOff = 0.002
	// fecTarget is the residual loss repairs are sized for.
	fecTarget = 0.001
	// Blocks stay open about a quarter of the RTT, so rebuilt packets
	// arrive before TCP takes the gap for loss, but long enough to collect
	// fecMinBlock packets at the current send rate, within these bounds.
	// A block of one packet is just a duplicate on the same path, which
	// the same burst usually takes.
	fecMinWindow = 2 * time.Millisecond
	fecMaxWindow = 20 * time.Millisecond
	fecMinBlock  = 4
	// fecMaxBurstWindow bounds the window when interleaving for bursts,
	// and auto mode needs a group to span fecMinBursts mean bursts.
	fecMaxBurstWindow = 50 * time.Millisecond
	fecMinBursts      = 4
	// fecMaxBurst is the longest mean burst auto mode protects against:
	// interleaving spreads a burst over at most fec.MaxUsefulDepth blocks,
	// and beyond twice that each block loses more than its repairs cover.
	// netem, which drops whole GSO batches of up to 64 datagrams, measures
	// bursts of 12-47 under "uniform" 5% loss at a few hundred Mbit/s;
	// protecting them cost 27% of TCP goodput with redundancy on.
	fecMaxBurst = 2 * fec.MaxUsefulDepth
	// fecHeld is how long a receiver keeps sources for rebuilding after
	// the last repair it saw; it keeps none while no repairs arrive.
	fecHeld = 5 * time.Second
)

// fecState is a conn's forward error correction in both directions.
type fecState struct {
	mode    wire.FECMode // applied to what this endpoint sends
	active  bool         // auto mode's current state
	checkAt time.Time
	enc     *fec.Encoder
	loss    float64 // sizing inputs, refreshed with checkAt
	burst   float64
	sent    int // IP packets sent since the last refresh, for the send rate

	dec        *fec.Decoder
	lastRepair time.Time
}

// fecSending reports whether FEC protects packets sent now, refreshing the
// auto state and the encoder's sizing at most every lossCheckEvery.
func (c *conn) fecSending(now time.Time) bool {
	f := &c.fec
	if f.mode == wire.FECOff {
		return false
	}
	if now.Before(f.checkAt) {
		return f.active
	}
	rate := float64(f.sent) / lossCheckEvery.Seconds()
	if f.checkAt.IsZero() || now.Sub(f.checkAt) > lossCheckEvery {
		rate = 0 // no recent interval to measure
	}
	f.checkAt, f.sent = now.Add(lossCheckEvery), 0
	f.loss, f.burst = c.sendLossAndBurst(now)
	wasActive := f.active
	switch f.mode {
	case wire.FECAlways:
		f.active = true
	default:
		f.active = f.loss >= fecOn || (f.active && f.loss >= fecOff)
	}
	if !f.active {
		if wasActive && f.enc != nil {
			c.sendRepairs(now, f.enc.Flush(now.Add(fecMaxWindow)))
		}
		return false
	}
	if f.enc == nil {
		f.enc = &fec.Encoder{}
	}
	depth := fec.DepthFor(f.burst)
	f.enc.Depth = depth
	f.enc.MaxK = 32
	if depth > 1 {
		f.enc.MaxK = 16
	}
	window, srtt := fecMaxWindow, fecMaxWindow
	if p := c.primary(now); p != nil {
		srtt = p.rtt.srtt()
		window = srtt / 4
	}
	limit := fecMaxWindow
	if depth > 1 {
		// Long bursts need a group spanning several of them, so blocks may
		// stay open up to an RTT: a rebuilt packet then comes late enough
		// for TCP to have retransmitted it, but Linux undoes the window
		// reduction once it learns the original arrived (DSACK), and
		// widens its reordering tolerance.
		limit = max(limit, min(srtt, fecMaxBurstWindow))
	}
	// Interleaving spreads a burst only across a group spanning several
	// bursts, so the window collects that many packets too, if it can.
	group := float64(fecMinBlock * depth)
	if f.burst > 2 {
		group = max(group, fecMinBursts*f.burst)
	}
	if rate > 0 {
		window = max(window, time.Duration(group/rate*float64(time.Second)))
	}
	f.enc.Window = min(max(window, fecMinWindow), limit)
	// When the send rate cannot fill such a group within the longest
	// window, auto mode stays off rather than spend repairs the bursts
	// would mostly take with them (on one path, 5% loss in bursts of 10 at
	// 1000 packets/s cost 48% overhead for half a point of delivery).
	if f.mode == wire.FECAuto && f.burst > 2 && (rate*limit.Seconds() < fecMinBursts*f.burst || f.burst > fecMaxBurst) {
		if wasActive {
			c.sendRepairs(now, f.enc.Flush(now.Add(fecMaxBurstWindow)))
		}
		f.active = false
		return false
	}
	loss, always := f.loss, f.mode == wire.FECAlways
	f.enc.Repairs = func(k int) int {
		m := fec.RepairsFor(k, loss, fecTarget)
		if always {
			m = max(m, 1)
		}
		return m
	}
	return true
}

// sendLossAndBurst returns the worst send-direction loss estimate among
// paths carrying traffic (the primary and paths with flows), and that
// path's mean burst length.
func (c *conn) sendLossAndBurst(now time.Time) (loss, burst float64) {
	burst = 1
	prim := c.primary(now)
	for _, p := range c.paths {
		if p != prim && p.flows == 0 {
			continue
		}
		if l, ok := p.sendLoss.estimate(now); ok && l >= loss {
			loss, burst = l, max(p.burst, 1)
		}
	}
	return loss, burst
}

// fecAdd feeds a sent IP packet to the encoder and sends any repairs.
func (c *conn) fecAdd(now time.Time, id uint64, pkt []byte) {
	if c.fec.enc != nil {
		c.sendRepairs(now, c.fec.enc.Add(now, id, pkt))
	}
}

// sendRepairs sends repair symbols on the primary path, skipping any that
// do not fit its packets.
func (c *conn) sendRepairs(now time.Time, repairs []fec.Repair) {
	if len(repairs) == 0 {
		return
	}
	p := c.primary(now)
	if p == nil {
		return
	}
	budget := p.maxPacket - wire.DataHeaderLen - wire.AEADTagLen
	for _, r := range repairs {
		if wire.FrameHeaderLen+8+len(r.Data) > budget {
			continue
		}
		c.transmit(now, p, []wire.Frame{wire.FECRepair{
			First32: uint32(r.First), Stride: uint8(r.Stride), K: uint8(r.K), M: uint8(r.M), Index: uint8(r.Index), Data: r.Data,
		}})
		c.stats.FECRepairsSent++
	}
}

// fecDeadline is when the open block must close, or zero.
func (c *conn) fecDeadline() time.Time {
	if c.fec.enc == nil {
		return time.Time{}
	}
	return c.fec.enc.Deadline()
}

// fecTimers closes a block whose window has passed.
func (c *conn) fecTimers(now time.Time) {
	if c.fec.enc != nil {
		c.sendRepairs(now, c.fec.enc.Flush(now))
	}
}

// fecRepair handles a received repair and returns packets it rebuilt that
// were not delivered yet.
func (c *conn) fecRepair(now time.Time, f wire.FECRepair) [][]byte {
	if c.fec.dec == nil {
		c.fec.dec = fec.NewDecoder(fec.DecoderConfig{})
	}
	c.fec.lastRepair = now
	first := c.expandID(f.First32)
	got := c.fec.dec.Repair(now, fec.Repair{First: first, Stride: int(f.Stride), K: int(f.K), M: int(f.M), Index: int(f.Index), Data: f.Data})
	return c.fecDeliverable(got)
}

// fecSource records a received datagram for rebuilding, while repairs are
// arriving, and returns packets it let the decoder rebuild.
func (c *conn) fecSource(now time.Time, id uint64, pkt []byte) [][]byte {
	if c.fec.dec == nil || now.Sub(c.fec.lastRepair) > fecHeld {
		return nil
	}
	return c.fecDeliverable(c.fec.dec.Source(now, id, pkt))
}

func (c *conn) fecDeliverable(got []fec.Recovered) [][]byte {
	var out [][]byte
	for _, r := range got {
		if c.dedup.Deliver(r.ID) {
			out = append(out, r.Pkt)
			c.stats.FECRecovered++
		}
	}
	return out
}

// expandID recovers a full datagram ID from its low 32 bits: the value
// closest to the highest ID delivered.
func (c *conn) expandID(low uint32) uint64 {
	hi, ok := c.dedup.Highest()
	if !ok {
		return uint64(low)
	}
	id := hi&^0xffffffff | uint64(low)
	switch {
	case id > hi && id-hi > 1<<31 && id >= 1<<32:
		id -= 1 << 32
	case id < hi && hi-id > 1<<31:
		id += 1 << 32
	}
	return id
}
