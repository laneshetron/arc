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
	maxPTOBackoff   = 6
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

// rttEstimator follows RFC 9002 §5.
type rttEstimator struct {
	latest, min, smoothed, variance time.Duration
	hasSample                       bool
}

func (r *rttEstimator) update(sample, ackDelay time.Duration) {
	r.latest = sample
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
	acked  bool
}

// sentLog holds a path's outstanding ack-eliciting packets in packet-number
// order.
type sentLog struct {
	packets      []sentPacket
	largestAcked uint64
	anyAcked     bool
	ptoCount     int
}

func (s *sentLog) add(p sentPacket) { s.packets = append(s.packets, p) }

// ackResult summarizes what an ACK frame acknowledged.
type ackResult struct {
	newlyAcked  int
	ackedEpochs []uint64
	rttSample   time.Duration
	hasRTT      bool
	lost        []wire.Frame
	lostCount   int
}

// onAck marks acknowledged packets and declares older ones lost by the
// packet threshold.
func (s *sentLog) onAck(now time.Time, ack *wire.Ack, intervals []wire.PacketRange) ackResult {
	var res ackResult
	for _, iv := range intervals {
		i := sort.Search(len(s.packets), func(i int) bool { return s.packets[i].pn >= iv.Lo })
		for ; i < len(s.packets) && s.packets[i].pn <= iv.Hi; i++ {
			p := &s.packets[i]
			if p.acked {
				continue
			}
			p.acked = true
			res.newlyAcked++
			res.ackedEpochs = append(res.ackedEpochs, p.epoch)
			if p.pn == ack.Largest {
				res.rttSample, res.hasRTT = now.Sub(p.sentAt), true
			}
		}
	}
	if res.newlyAcked > 0 {
		s.ptoCount = 0
	}
	if !s.anyAcked || ack.Largest > s.largestAcked {
		s.largestAcked, s.anyAcked = ack.Largest, true
	}
	for i := range s.packets {
		p := &s.packets[i]
		if p.acked || p.pn+packetThreshold > s.largestAcked {
			continue
		}
		p.acked = true // retired as lost
		res.lostCount++
		res.lost = append(res.lost, p.frames...)
	}
	s.trim()
	return res
}

// onPTO retires the oldest outstanding packet carrying control frames and
// returns its frames for retransmission.
func (s *sentLog) onPTO() []wire.Frame {
	s.ptoCount = min(s.ptoCount+1, maxPTOBackoff)
	for i := range s.packets {
		p := &s.packets[i]
		if !p.acked && len(p.frames) > 0 {
			p.acked = true
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
	for _, p := range s.packets {
		if !p.acked && len(p.frames) > 0 {
			return p.sentAt.Add(rtt.pto() << s.ptoCount)
		}
	}
	return time.Time{}
}

// expire forgets packets that have been outstanding for so long that an
// acknowledgement no longer matters, bounding memory.
func (s *sentLog) expire(now time.Time, horizon time.Duration) {
	for i := range s.packets {
		p := &s.packets[i]
		if !p.acked && len(p.frames) == 0 && now.Sub(p.sentAt) > horizon {
			p.acked = true
		}
	}
	s.trim()
}

func (s *sentLog) trim() {
	i := 0
	for i < len(s.packets) && s.packets[i].acked {
		i++
	}
	if i > 0 {
		s.packets = append(s.packets[:0], s.packets[i:]...)
	}
}
