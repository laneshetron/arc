package session

import (
	"math"
	"slices"
	"sort"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// Recovery parameters (spec §10.2; loss detection follows RFC 9002 in a
// simplified form).
const (
	MaxAckDelay     = 25 * time.Millisecond
	initialRTT      = 333 * time.Millisecond
	packetThreshold = 3
	// timeThreshold is RFC 9002's kTimeThreshold: a packet sent this
	// many RTTs before an acknowledged one is lost.
	timeThresholdNum, timeThresholdDen = 9, 8
	// maxPTOBackoff caps PTO doubling at 8x. Control packets are small,
	// and under heavy loss a longer wait only delays the frames that
	// recover the session, such as REDUNDANCY and PATH_ABANDON.
	maxPTOBackoff = 3
)

// ackTracker records received packet numbers on one path and decides when
// to acknowledge them.
type ackTracker struct {
	ranges       []wire.PacketRange // descending, disjoint, non-adjacent
	largestAt    time.Time          // when the largest packet number arrived
	unacked      int                // ack-eliciting packets not yet acknowledged
	firstUnacked time.Time
}

func (a *ackTracker) onReceive(pn uint64, now time.Time, ackEliciting bool) {
	if len(a.ranges) == 0 || pn > a.ranges[0].Hi {
		a.largestAt = now
	}
	a.insert(pn)
	if ackEliciting {
		if a.unacked == 0 {
			a.firstUnacked = now
		}
		a.unacked++
	}
}

func (a *ackTracker) insert(pn uint64) {
	i := sort.Search(len(a.ranges), func(i int) bool { return a.ranges[i].Lo <= pn })
	// a.ranges[i] is the first range at or below pn.
	if i < len(a.ranges) && pn <= a.ranges[i].Hi {
		return
	}
	extendsBelow := i < len(a.ranges) && a.ranges[i].Hi+1 == pn
	extendsAbove := i > 0 && a.ranges[i-1].Lo == pn+1
	switch {
	case extendsBelow && extendsAbove:
		a.ranges[i-1].Lo = a.ranges[i].Lo
		a.ranges = slices.Delete(a.ranges, i, i+1)
	case extendsBelow:
		a.ranges[i].Hi = pn
	case extendsAbove:
		a.ranges[i-1].Lo = pn
	default:
		a.ranges = slices.Insert(a.ranges, i, wire.PacketRange{Lo: pn, Hi: pn})
	}
	if len(a.ranges) > wire.MaxAckRanges+1 {
		a.ranges = a.ranges[:wire.MaxAckRanges+1]
	}
}

// largest returns the largest packet number received, if any.
func (a *ackTracker) largest() (uint64, bool) {
	if len(a.ranges) == 0 {
		return 0, false
	}
	return a.ranges[0].Hi, true
}

func (a *ackTracker) due(now time.Time) bool {
	return a.unacked >= 2 || (a.unacked > 0 && !now.Before(a.firstUnacked.Add(MaxAckDelay)))
}

func (a *ackTracker) deadline() time.Time {
	if a.unacked == 0 {
		return time.Time{}
	}
	return a.firstUnacked.Add(MaxAckDelay)
}

// frame builds an ACK frame and resets the acknowledgement timer.
func (a *ackTracker) frame(now time.Time, pathID uint32) wire.Ack {
	ack := a.peek(now, pathID)
	a.sent()
	return ack
}

// sent resets the acknowledgement timer after an ACK goes out.
func (a *ackTracker) sent() { a.unacked = 0 }

// peek builds an ACK frame without resetting the timer.
func (a *ackTracker) peek(now time.Time, pathID uint32) wire.Ack {
	top := a.ranges[0]
	ack := wire.Ack{
		PathID:         pathID,
		Largest:        top.Hi,
		AckDelayMicros: uint32(min(now.Sub(a.largestAt).Microseconds(), math.MaxUint32)),
		FirstRange:     uint32(min(top.Hi-top.Lo, math.MaxUint32)),
	}
	smallest := top.Hi - uint64(ack.FirstRange)
	for _, r := range a.ranges[1:] {
		gap, length := smallest-r.Hi-2, r.Hi-r.Lo
		if gap > math.MaxUint32 || length > math.MaxUint32 {
			break
		}
		ack.Ranges = append(ack.Ranges, wire.AckRange{Gap: uint32(gap), Length: uint32(length)})
		smallest = r.Lo
	}
	return ack
}

// rttEstimator follows RFC 9002 §5, plus a windowed minimum (as in BBR)
// for judging path latency and queueing: RFC 9002's min_rtt is a lifetime
// minimum, which never notices that a path got slower.
type rttEstimator struct {
	latest, min, smoothed, variance time.Duration
	hasSample                       bool

	// mins holds the lowest sample of each of the last minRTTBuckets
	// intervals of minRTTBucket, newest at minsNext-1.
	mins     [minRTTBuckets]rttBucket
	minsNext int
}

type rttBucket struct {
	index int64 // interval number since the Unix epoch; 0 if unused
	min   time.Duration
}

// minRTTWindow is how long a minimum RTT sample is trusted: a higher one
// replaces it once it is this old. It should outlast typical transfers: a
// TCP flow keeps a standing queue for as long as it saturates a path, and
// once the minimum re-anchors to the queued RTT, the busy path's cost
// rises and new flows prefer other paths (mild for a minute-long
// saturation; constant re-anchoring made the primary chase idle paths).
const (
	minRTTWindow  = time.Minute
	minRTTBucket  = 10 * time.Second
	minRTTBuckets = int(minRTTWindow / minRTTBucket)
)

func (r *rttEstimator) update(now time.Time, sample, ackDelay time.Duration) {
	r.latest = sample
	idx := now.UnixNano() / int64(minRTTBucket)
	last := &r.mins[(r.minsNext+minRTTBuckets-1)%minRTTBuckets]
	if last.index == idx {
		last.min = min(last.min, sample)
	} else {
		r.mins[r.minsNext] = rttBucket{index: idx, min: sample}
		r.minsNext = (r.minsNext + 1) % minRTTBuckets
	}
	if !r.hasSample {
		r.min, r.smoothed, r.variance, r.hasSample = sample, sample, sample/2, true
		return
	}
	r.min = min(r.min, sample)
	if sample-ackDelay >= r.min {
		sample -= ackDelay
	}
	diff := r.smoothed - sample
	if diff < 0 {
		diff = -diff
	}
	r.variance = (3*r.variance + diff) / 4
	r.smoothed = (7*r.smoothed + sample) / 8
}

func (r *rttEstimator) srtt() time.Duration {
	if !r.hasSample {
		return initialRTT
	}
	return r.smoothed
}

// minRTT is the path's recent latency without queueing: the lowest sample
// of the last minRTTWindow, or of the most recent interval with samples if
// none is that recent.
func (r *rttEstimator) minRTT() time.Duration {
	if !r.hasSample {
		return initialRTT
	}
	newest := r.mins[(r.minsNext+minRTTBuckets-1)%minRTTBuckets]
	best := newest.min
	for _, b := range r.mins {
		if b.index != 0 && b.index > newest.index-int64(minRTTBuckets) {
			best = min(best, b.min)
		}
	}
	return best
}

func (r *rttEstimator) pto() time.Duration {
	if !r.hasSample {
		return 2*initialRTT + MaxAckDelay
	}
	return r.smoothed + max(4*r.variance, time.Millisecond) + MaxAckDelay
}

// sentPacket is an ack-eliciting packet awaiting acknowledgement. Only
// control frames are retransmitted; IP payloads never are (§11).
type sentPacket struct {
	pn     uint64
	sentAt time.Time
	epoch  uint64
	frames []wire.Frame
	probe  int // MTU probe size, or 0: a probe's loss says nothing about path health
	size   int // bytes on the wire, for delivery rate
	// ping marks a packet carrying no IP payload or control frame, such as
	// a keepalive or a probe of a suspect path. Like MTU probes, pings
	// count for path health but not for loss or delivery rate: those sent
	// into an outage are all declared lost once the path recovers, which
	// would leave the path looking lossy long after health says it is back.
	ping  bool
	acked bool
}

// sentLog holds a path's outstanding ack-eliciting packets in packet-number
// (and therefore send-time) order. Retired packets stay in place, marked
// acked, until they reach the front; every walk stops as soon as the order
// says nothing further can match, so per-ACK work is proportional to what
// changed, not to the number of packets in flight.
type sentLog struct {
	packets      []sentPacket
	largestAcked uint64
	largestSent  time.Time // when largestAcked was sent, if known
	anyAcked     bool
	ptoCount     int
	control      int // outstanding packets that carry control frames
}

func (s *sentLog) add(p sentPacket) {
	if len(p.frames) > 0 {
		s.control++
	}
	s.packets = append(s.packets, p)
}

// retire marks an outstanding packet acknowledged, lost, or expired.
func (s *sentLog) retire(p *sentPacket) {
	p.acked = true
	if len(p.frames) > 0 {
		s.control--
	}
}

// ackResult summarizes what an ACK frame acknowledged.
type ackResult struct {
	newlyAcked        int
	delivered         int // newly acknowledged, not counting MTU probes
	deliveredBytes    int // their size
	ackedCurrentEpoch bool
	rttSample         time.Duration
	hasRTT            bool
	lost              []wire.Frame
	lostCount         int
	ackedProbe        int // largest MTU probe acknowledged
}

// onAck marks acknowledged packets and declares older ones lost by the
// packet threshold or, sent more than lossDelay before the largest
// acknowledged packet, by the time threshold (RFC 9002 §6.1). The time
// threshold matters on sparsely used paths: packets lost in an outage would
// otherwise wait for three later packets to be acknowledged, keeping the
// path suspect long after it recovered. epoch is the sender's current key
// epoch.
func (s *sentLog) onAck(now time.Time, ack *wire.Ack, intervals []wire.PacketRange, epoch uint64, lossDelay time.Duration) ackResult {
	var res ackResult
	for _, iv := range intervals {
		i := sort.Search(len(s.packets), func(i int) bool { return s.packets[i].pn >= iv.Lo })
		for ; i < len(s.packets) && s.packets[i].pn <= iv.Hi; i++ {
			p := &s.packets[i]
			if p.acked {
				continue
			}
			s.retire(p)
			res.newlyAcked++
			if p.probe == 0 {
				if !p.ping {
					res.delivered++
					res.deliveredBytes += p.size
				}
			}
			res.ackedProbe = max(res.ackedProbe, p.probe)
			res.ackedCurrentEpoch = res.ackedCurrentEpoch || p.epoch == epoch
			if p.pn == ack.Largest {
				res.rttSample, res.hasRTT = now.Sub(p.sentAt), true
				if !s.anyAcked || p.pn >= s.largestAcked {
					s.largestSent = p.sentAt
				}
			}
		}
	}
	if res.newlyAcked > 0 {
		s.ptoCount = 0
	}
	if !s.anyAcked || ack.Largest > s.largestAcked {
		s.largestAcked, s.anyAcked = ack.Largest, true
	}
	var cutoff time.Time // packets sent before this are lost
	if !s.largestSent.IsZero() && lossDelay > 0 {
		cutoff = s.largestSent.Add(-lossDelay)
	}
	for i := range s.packets {
		p := &s.packets[i]
		byCount := p.pn+packetThreshold <= s.largestAcked
		byTime := p.pn < s.largestAcked && p.sentAt.Before(cutoff)
		if !byCount && !byTime {
			break // later packets have higher numbers and send times
		}
		if p.acked {
			continue
		}
		s.retire(p) // lost
		if p.probe == 0 && !p.ping {
			res.lostCount++
		}
		res.lost = append(res.lost, p.frames...)
	}
	s.trim()
	return res
}

// onPTO retires the oldest outstanding packet carrying control frames and
// returns its frames for retransmission.
func (s *sentLog) onPTO() []wire.Frame {
	s.ptoCount = min(s.ptoCount+1, maxPTOBackoff)
	if s.control == 0 {
		return nil
	}
	for i := range s.packets {
		p := &s.packets[i]
		if !p.acked && len(p.frames) > 0 {
			s.retire(p)
			frames := p.frames
			s.trim()
			return frames
		}
	}
	return nil
}

// ptoDeadline is when the oldest outstanding control packet should be
// considered lost, or zero if none is outstanding.
func (s *sentLog) ptoDeadline(rtt *rttEstimator) time.Time {
	if s.control == 0 {
		return time.Time{}
	}
	for _, p := range s.packets {
		if !p.acked && len(p.frames) > 0 {
			return p.sentAt.Add(rtt.pto() << s.ptoCount)
		}
	}
	return time.Time{}
}

// oldestOutstanding returns when the oldest unacknowledged packet (other
// than an MTU probe) was sent.
func (s *sentLog) oldestOutstanding() (time.Time, bool) {
	for _, p := range s.packets {
		if !p.acked && p.probe == 0 {
			return p.sentAt, true
		}
	}
	return time.Time{}, false
}

// expire forgets packets without control frames that have been outstanding
// for so long that an acknowledgement no longer matters, bounding memory.
func (s *sentLog) expire(now time.Time, horizon time.Duration) {
	for i := range s.packets {
		p := &s.packets[i]
		if now.Sub(p.sentAt) <= horizon {
			break // later packets were sent later
		}
		if !p.acked && len(p.frames) == 0 {
			s.retire(p)
		}
	}
	s.trim()
}

// trim drops retired packets from the front. Reslicing avoids copying the
// rest; append reallocates, copying only live packets, when capacity runs
// out.
func (s *sentLog) trim() {
	i := 0
	for i < len(s.packets) && s.packets[i].acked {
		s.packets[i] = sentPacket{} // release frame references
		i++
	}
	s.packets = s.packets[i:]
}
