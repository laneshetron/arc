package session

import (
	"math"
	"time"
)

// Loss-aware path selection (spec §15.2). Each path estimates its packet
// loss rate in both directions: the sender from acknowledgements, the
// receiver from gaps in the packet numbers it receives. Paths are compared
// by a cost that follows the Mathis relation for loss-limited TCP,
// throughput ∝ 1 / (RTT · √loss), since most tunneled traffic is TCP.
const (
	// lossWindow and lossWindowTime bound a sample: at least this many
	// packet outcomes and this much time, so that busy paths average over
	// enough packets for a 1% loss rate to be distinguishable from noise.
	lossWindow     = 32
	lossWindowTime = 100 * time.Millisecond
	lossGain       = 0.125 // EWMA weight of each new window

	// lossStale is how long an estimate is trusted without new samples.
	// Only paths carrying traffic produce samples, so an idle path's old
	// estimate is eventually forgotten and the path gets another chance.
	lossStale = 30 * time.Second

	// lossFloor is the loss rate assumed for a path that measures less (or
	// nothing at all): congestion alone causes some loss, and a clean path
	// should not look infinitely better than a nearly clean one.
	lossFloor = 0.005

	// lossRTTOffset stands in for the rest of a tunneled flow's round trip,
	// from the relay to the destination, which all paths share.
	lossRTTOffset = 20 * time.Millisecond

	// A healthy primary is abandoned for loss only when another path's cost
	// is lossSwitchRatio times lower, and at most once per lossDwell, so
	// that flows are not reordered by paths of similar quality trading
	// places.
	lossSwitchRatio = 2
	lossDwell       = 2 * time.Second
	lossCheckEvery  = 250 * time.Millisecond

	// RedundancyAuto thresholds (§11.1).
	redundancyOn  = 0.01
	redundancyOff = 0.004
)

// lossEstimator is an exponentially weighted average of one direction's
// loss rate over windows of packet outcomes.
type lossEstimator struct {
	total, lost int // outcomes in the current window; lost may dip below 0
	start       time.Time
	rate        float64
	valid       bool
	updated     time.Time
}

// record adds total packet outcomes of which lost were lost. A packet
// first counted as lost and then received late is recorded as (0, -1).
func (l *lossEstimator) record(now time.Time, total, lost int) {
	if l.total == 0 && total > 0 {
		l.start = now
	}
	l.total += total
	l.lost += lost
	if l.total < lossWindow || now.Sub(l.start) < lossWindowTime {
		return
	}
	frac := min(max(float64(l.lost)/float64(l.total), 0), 1)
	if l.valid {
		l.rate += lossGain * (frac - l.rate)
	} else {
		l.rate, l.valid = frac, true
	}
	l.updated = now
	l.total, l.lost = 0, 0
}

// estimate returns the loss rate, or false if there is no recent one.
func (l *lossEstimator) estimate(now time.Time) (float64, bool) {
	if !l.valid || now.Sub(l.updated) > lossStale {
		return 0, false
	}
	return l.rate, true
}

// loss returns the path's loss rate in the worse of the two directions,
// and whether either direction has a recent estimate.
func (p *path) loss(now time.Time) (float64, bool) {
	s, sok := p.sendLoss.estimate(now)
	r, rok := p.recvLoss.estimate(now)
	return max(s, r), sok || rok
}

// cost ranks paths for carrying traffic; lower is better.
func (p *path) cost(now time.Time) float64 {
	loss, _ := p.loss(now)
	rtt := (p.rtt.srtt() + lossRTTOffset).Seconds()
	return rtt * math.Sqrt(max(loss, lossFloor))
}

// lossierThan reports whether a healthy path q is enough better than the
// healthy current path p to move traffic.
func lossierThan(now time.Time, p, q *path) bool {
	if _, ok := p.loss(now); !ok {
		return false // no evidence against the current path
	}
	return q.cost(now)*lossSwitchRatio < p.cost(now)
}
