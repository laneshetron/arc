package session

import (
	"math"
	"time"
)

// Rate control for stream data (spec §11.3). Loss-based congestion control
// would make streams as fragile as the TCP they replace: at 10% random
// loss Reno-style TCP manages a few packets per round trip, and at 50% it
// stalls. Each path instead paces stream data at a rate driven by two
// congestion signals that random loss does not produce:
//
//   - queueing delay: the lowest RTT sample in a round rising more than
//     queueTarget above the path's minimum RTT, as a filling bottleneck
//     queue causes;
//   - a loss spike: the loss rate of a round's stream packets rising well
//     above the path's baseline loss, as overrunning a policer or a
//     shallow buffer causes. Steady loss, however heavy, becomes the
//     baseline.
//
// Without either the rate grows each round, unless the streams did not use
// it: doubling until the first congestion signal, then by an eighth up to
// the rate delivered at the last backoff, then by 3%. With either it falls
// to what the round delivered, corrected for the baseline loss, which with
// a full queue is about the bottleneck's rate (by at most half, or three
// quarters ending slow start, if too little was acknowledged to tell), and
// it holds while the queue drains.
// A cap on bytes
// in flight stops sending into an outage, which produces no
// acknowledgements to clock it.
const (
	ccSlowStartGain = 2.0
	ccGrowth        = 1.125
	ccProbe         = 1.03
	ccBackoff       = 0.8
	ccMinRound      = 10 * time.Millisecond
	ccMinRate       = 16 << 10 // bytes per second
	// A round's loss is judged once it has this many outcomes; until then
	// outcomes accumulate across rounds.
	ccLossSample = 20
	// A loss spike is a round's loss this far above the baseline (or three
	// standard deviations of the sample, if more).
	ccLossSpike = 0.1
	ccMaxAckGap = time.Second
	// ccBaseWindow is how long an RTT sample counts toward the base RTT
	// that queueing delay is measured from, in two halves. The path's own
	// minimum lasts a minute (recovery.go), so a path whose RTT rose, as
	// when a network change adds delay, would look queued, and rate
	// control would hold at its floor for that long. The controller
	// drains its own queue at every backoff, so a short window does not
	// mistake its queue for the base.
	ccBaseWindow = 10 * time.Second
	// ccRebaseRounds is how many rounds in a row may show queueing delay
	// before the lowest RTT among them becomes the base: by then backoffs
	// would have drained a queue of the controller's own making, so the
	// delay is the path's.
	ccRebaseRounds = 8
	// ccLossy is the baseline loss at which spare sending capacity goes to
	// repeating stream data in flight (see conn.nextRepeatFrame).
	ccLossy = 0.5
)

// queueTarget is the queueing delay a path's minimum RTT tolerates before
// stream rate control backs off.
func queueTarget(minRTT time.Duration) time.Duration {
	return max(minRTT/4, 5*time.Millisecond)
}

type streamCC struct {
	rate      float64 // bytes per second; 0 until first used
	slowStart bool
	tokens    float64 // bytes that may be sent now; negative is debt
	tokensAt  time.Time

	roundStart, roundEnd time.Time
	roundMin             time.Duration // lowest RTT sample this round, 0 if none
	roundLast            time.Duration // latest RTT sample this round
	roundSent            int           // stream bytes sent this round
	roundAcked           int           // stream bytes acknowledged this round
	// The previous round's delay signal and lowest RTT sample, and
	// whether it backed off.
	lastDelay bool
	lastMin   time.Duration
	backedOff bool
	// capacity is the delivery rate when the rate last backed off.
	capacity float64

	acked, lost int     // stream packet outcomes not yet judged
	baseLoss    float64 // loss rate without congestion
	baseSet     bool

	lastAck time.Time
	ackGap  time.Duration // smoothed interval between acknowledgements

	// The lowest RTT sample in the current and previous half of
	// ccBaseWindow.
	baseStart         time.Time
	baseCur, basePrev time.Duration
	delayRounds       int           // consecutive rounds showing delay
	delayMin          time.Duration // lowest RTT sample in them
}

// observeRTT records an RTT sample of any packet on the path.
func (cc *streamCC) observeRTT(now time.Time, rtt time.Duration) {
	half := ccBaseWindow / 2
	switch {
	case cc.baseStart.IsZero() || now.Sub(cc.baseStart) >= 2*half:
		cc.baseStart, cc.baseCur, cc.basePrev = now, rtt, 0
	case now.Sub(cc.baseStart) >= half:
		cc.baseStart, cc.basePrev, cc.baseCur = cc.baseStart.Add(half), cc.baseCur, rtt
	}
	cc.baseCur = min(cc.baseCur, rtt)
}

// baseRTT is the lowest RTT sample of the last ccBaseWindow or so, or
// fallback without one.
func (cc *streamCC) baseRTT(fallback time.Duration) time.Duration {
	switch {
	case cc.baseStart.IsZero():
		return fallback
	case cc.basePrev > 0:
		return min(cc.baseCur, cc.basePrev)
	}
	return cc.baseCur
}

func (cc *streamCC) start(now time.Time, srtt time.Duration, mss int) {
	cc.rate = max(10*float64(mss)/srtt.Seconds(), ccMinRate)
	cc.slowStart = true
	cc.tokens, cc.tokensAt = 2*float64(mss), now
	cc.roundStart, cc.roundEnd = now, now.Add(max(srtt, ccMinRound))
}

// refill adds tokens for the time since the last refill, up to a burst of
// about 2 ms at the current rate.
func (cc *streamCC) refill(now time.Time, mss int) {
	if d := now.Sub(cc.tokensAt); d > 0 {
		burst := max(2*float64(mss), cc.rate*0.002)
		cc.tokens = min(cc.tokens+cc.rate*d.Seconds(), burst)
		cc.tokensAt = now
	}
}

// window caps stream bytes in flight: twice what the rate delivers in an
// RTT plus the usual wait for an acknowledgement, which on a link losing
// most acknowledgements is several RTTs.
func (cc *streamCC) window(srtt time.Duration, mss int) int {
	return max(int(2*cc.rate*(srtt+cc.ackGap).Seconds()), 4*mss)
}

// canSend reports whether a stream packet may go now, and if not because of
// pacing, when one may.
func (cc *streamCC) canSend(now time.Time, inflight int, srtt time.Duration, mss int) (bool, time.Time) {
	if cc.rate == 0 {
		cc.start(now, srtt, mss)
	}
	cc.refill(now, mss)
	if inflight >= cc.window(srtt, mss) {
		return false, time.Time{} // an acknowledgement or PTO comes first
	}
	if cc.tokens < 0 {
		wait := time.Duration(math.Ceil(-cc.tokens / cc.rate * float64(time.Second)))
		return false, now.Add(max(wait, time.Microsecond))
	}
	return true, time.Time{}
}

func (cc *streamCC) onSent(size int) {
	cc.tokens -= float64(size)
	cc.roundSent += size
}

// onAck records an acknowledgement's outcome for stream packets: how many
// were acknowledged and declared lost, and an RTT sample if it has one.
func (cc *streamCC) onAck(now time.Time, acked, lost, ackedBytes int, rtt time.Duration) {
	if cc.rate == 0 {
		return
	}
	cc.acked += acked
	cc.lost += lost
	cc.roundAcked += ackedBytes
	if rtt > 0 {
		cc.roundLast = rtt
		if cc.roundMin == 0 || rtt < cc.roundMin {
			cc.roundMin = rtt
		}
	}
	if acked > 0 {
		if !cc.lastAck.IsZero() {
			gap := min(now.Sub(cc.lastAck), ccMaxAckGap)
			cc.ackGap += (gap - cc.ackGap) / 8
		}
		cc.lastAck = now
	}
}

// update ends the round if it is over, adjusting the rate.
func (cc *streamCC) update(now time.Time, minRTT, srtt time.Duration, mss int) {
	if cc.rate == 0 || now.Before(cc.roundEnd) {
		return
	}
	// The round's lowest RTT sample shows a standing queue without
	// mistaking jitter for one. Slow start, which doubles the rate each
	// round, cannot wait for a whole round to show it and goes by the
	// latest sample (as HyStart does).
	target := queueTarget(minRTT)
	delay := cc.roundMin > 0 && cc.roundMin-minRTT > target ||
		cc.slowStart && cc.roundLast > 0 && cc.roundLast-minRTT > target
	spike, judged := cc.judgeLoss(delay)
	feedback := cc.roundMin > 0 || judged
	appLimited := float64(cc.roundSent) < cc.rate*now.Sub(cc.roundStart).Seconds()/2
	// For a round after a backoff the queue still holds what was sent
	// before it, and after that it may be draining: neither calls for
	// another backoff.
	settling := cc.backedOff || delay && cc.lastDelay &&
		cc.roundMin < cc.lastMin-max(time.Millisecond, (cc.lastMin-minRTT)/8)
	cc.lastDelay, cc.lastMin, cc.backedOff = delay, cc.roundMin, false
	if delay {
		cc.delayRounds++
		if cc.delayMin == 0 || cc.roundMin > 0 && cc.roundMin < cc.delayMin {
			cc.delayMin = cc.roundMin
		}
		if cc.delayRounds >= ccRebaseRounds && cc.delayMin > 0 {
			cc.baseStart, cc.baseCur, cc.basePrev = now, cc.delayMin, 0
			cc.delayRounds, cc.delayMin = 0, 0
			delay, settling = false, true
		}
	} else {
		cc.delayRounds, cc.delayMin = 0, 0
	}
	switch {
	case (delay || spike) && settling:
	case delay || spike:
		next, floor := cc.rate*ccBackoff, cc.rate/2
		if cc.slowStart {
			// Doubling overshot by up to the RTT the signal took to come
			// back.
			next, floor = cc.rate/ccSlowStartGain, cc.rate/4
			cc.slowStart = false
		}
		if d := cc.delivered(now); d > 0 {
			next = min(next, 0.9*d)
			cc.capacity = d
			if cc.roundAcked >= 8*mss {
				floor = 0 // enough acknowledged to trust
			}
		}
		cc.rate = max(next, floor)
		cc.backedOff = true
	case !feedback || appLimited:
	case cc.slowStart:
		cc.rate *= ccSlowStartGain
	case cc.rate < cc.capacity:
		cc.rate = min(cc.rate*ccGrowth, cc.capacity)
	default:
		// Past the rate that last filled the queue, probe gently.
		cc.rate *= ccProbe
	}
	cc.rate = max(cc.rate, ccMinRate, 4*float64(mss)/srtt.Seconds())
	cc.roundStart, cc.roundEnd = now, now.Add(max(srtt, ccMinRound))
	cc.roundMin, cc.roundLast, cc.roundSent, cc.roundAcked = 0, 0, 0, 0
}

// delivered estimates the rate the path carried this round: stream bytes
// acknowledged, plus what the baseline loss took.
func (cc *streamCC) delivered(now time.Time) float64 {
	d := now.Sub(cc.roundStart).Seconds()
	if d <= 0 || cc.roundAcked == 0 {
		return 0
	}
	return float64(cc.roundAcked) / d / (1 - min(cc.baseLoss, 0.95))
}

// lossy reports whether the path loses so much that stream data in flight
// is worth repeating while there is spare sending capacity.
func (cc *streamCC) lossy() bool { return cc.baseSet && cc.baseLoss >= ccLossy }

// judgeLoss compares the loss of the outcomes since the last judgment with
// the baseline, once there are enough of them, and moves the baseline
// toward it, halfway for a spike: a link that turned lossy stays lossy at
// any rate and becomes the baseline after a few backoffs, while overrunning
// a policer raises the loss again each time the rate recovers. Loss while
// the queue shows delay is the queue overflowing and leaves the baseline
// alone.
func (cc *streamCC) judgeLoss(delay bool) (spike, judged bool) {
	n := cc.acked + cc.lost
	if n < ccLossSample {
		return false, false
	}
	f := float64(cc.lost) / float64(n)
	cc.acked, cc.lost = 0, 0
	if delay {
		return false, true
	}
	if !cc.baseSet {
		cc.baseLoss, cc.baseSet = f, true
		return false, true
	}
	sigma := math.Sqrt(max(cc.baseLoss*(1-cc.baseLoss), 0.01) / float64(n))
	spike = f > cc.baseLoss+max(ccLossSpike, 3*sigma)
	gain := 0.25
	if spike {
		gain = 0.5
	}
	cc.baseLoss += (f - cc.baseLoss) * gain
	return spike, true
}
