package session

import (
	"math"
	"time"
)

// Flow scheduling across paths (spec §15.2 items 2, 3 and 7). IP traffic
// is pinned per flow (5-tuple) to one path, so a TCP flow is never striped
// and reordered; independent flows spread across paths in proportion to
// their measured capacity. The client assigns flows, and the relay sends
// each flow's downlink on the path its uplink last arrived on, so the
// client's choice steers both directions.
const (
	rateWindow  = 250 * time.Millisecond
	rateWindows = 40 // capacity is the best window in the last 10 s

	flowIdle      = 10 * time.Second // an entry unused this long is forgotten
	flowActive    = time.Second      // a flow counts toward its path's load this long after a packet
	flowSweep     = 250 * time.Millisecond
	maxFlows      = 4096 // per session
	eligibleCache = 100 * time.Millisecond

	// measuredRate is the delivery rate below which a path counts as
	// unmeasured: keepalives and acknowledgements alone produce a few
	// hundred bytes per second, which says nothing about capacity.
	measuredRate = 64 << 10
)

// rateMax tracks the highest rate a path achieved in any rateWindow over
// the last rateWindows windows. A path's delivery rate is only as high as
// the traffic offered to it, so this underestimates capacity until the
// path has been busy; see capacity.
type rateMax struct {
	start time.Time // of the current window
	bytes int       // in the current window
	ring  [rateWindows]float64
	next  int
}

func (r *rateMax) add(now time.Time, n int) {
	r.roll(now)
	r.bytes += n
}

// roll closes windows that have ended by now.
func (r *rateMax) roll(now time.Time) {
	if r.start.IsZero() {
		r.start = now
		return
	}
	if now.Sub(r.start) >= rateWindow*rateWindows {
		// Idle longer than the whole ring: every window, including the
		// one in progress, is too old to count. Closing them one by one
		// left the last busy window in the ring, so a path back from an
		// outage reported its old rate, measured and slow next to a busy
		// path, and new flows avoided it.
		*r = rateMax{start: now}
		return
	}
	for i := 0; i < rateWindows && now.Sub(r.start) >= rateWindow; i++ {
		r.ring[r.next] = float64(r.bytes) / rateWindow.Seconds()
		r.next = (r.next + 1) % rateWindows
		r.bytes = 0
		r.start = r.start.Add(rateWindow)
	}
	if now.Sub(r.start) >= rateWindow { // idle longer than the whole ring
		r.start = now
	}
}

// max returns the best complete window, in bytes per second.
func (r *rateMax) max(now time.Time) float64 {
	r.roll(now)
	best := 0.0
	for _, v := range r.ring {
		best = max(best, v)
	}
	return best
}

// capacity estimates what p can carry: its best recent delivery rate in
// either direction. Asymmetric links (cellular) are summarized by the
// faster direction, since a flow's heavy direction is not known when it
// is assigned.
func (p *path) capacity(now time.Time) float64 {
	return max(p.sendRate.max(now), p.recvRate.max(now))
}

// flowKey identifies a flow from the client's side: local is the client's
// tunnel address. Ports are zero for protocols without them and for IP
// fragments, which carry ports only in the first fragment.
type flowKey struct {
	proto         uint8
	local, remote [4]byte
	lport, rport  uint16
}

// flowKeyOf returns the flow of an IPv4 packet. fromClient says which end
// sent it: uplink packets have the client's address as source, downlink
// packets as destination.
func flowKeyOf(pkt []byte, fromClient bool) (flowKey, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return flowKey{}, false
	}
	var k flowKey
	k.proto = pkt[9]
	src, dst := [4]byte(pkt[12:16]), [4]byte(pkt[16:20])
	var sport, dport uint16
	ihl := int(pkt[0]&0x0f) * 4
	fragmented := pkt[6]&0x3f != 0 || pkt[7] != 0 // MF set or nonzero offset
	if (k.proto == 6 || k.proto == 17) && !fragmented && len(pkt) >= ihl+4 {
		sport = uint16(pkt[ihl])<<8 | uint16(pkt[ihl+1])
		dport = uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3])
	}
	if fromClient {
		k.local, k.remote, k.lport, k.rport = src, dst, sport, dport
	} else {
		k.local, k.remote, k.lport, k.rport = dst, src, dport, sport
	}
	return k, true
}

type flowEntry struct {
	path     *path
	lastSeen time.Time
	active   bool // counted in path.flows
}

// flowTable pins flows to paths. It is bounded: idle entries are swept,
// and when it is full new flows go unpinned.
type flowTable struct {
	m       map[flowKey]flowEntry
	sweepAt time.Time
}

func (t *flowTable) get(now time.Time, k flowKey) (*path, bool) {
	e, ok := t.m[k]
	if !ok || e.path.removed {
		return nil, false
	}
	if !e.active || now.Sub(e.lastSeen) >= time.Millisecond { // spare the map write per packet
		if !e.active {
			e.active = true
			e.path.flows++
		}
		e.lastSeen = now
		t.m[k] = e
	}
	return e.path, true
}

// put pins k to p, replacing any earlier pin.
func (t *flowTable) put(now time.Time, k flowKey, p *path) {
	if t.m == nil {
		t.m = make(map[flowKey]flowEntry)
	}
	if e, ok := t.m[k]; ok {
		if e.active {
			e.path.flows--
		}
	} else if len(t.m) >= maxFlows {
		t.sweep(now, true)
		if len(t.m) >= maxFlows {
			return
		}
	}
	t.m[k] = flowEntry{path: p, lastSeen: now, active: true}
	p.flows++
}

// sweep stops counting flows quiet for flowActive toward their path's load
// and forgets those idle for flowIdle or whose path is gone, at most once
// per flowSweep unless forced. Counting only active flows matters: a burst
// of short connections that just ended must not keep new flows off a path.
func (t *flowTable) sweep(now time.Time, force bool) {
	if !force && now.Before(t.sweepAt) {
		return
	}
	t.sweepAt = now.Add(flowSweep)
	for k, e := range t.m {
		idle := now.Sub(e.lastSeen)
		if e.active && (e.path.removed || idle >= flowActive) {
			e.active = false
			e.path.flows--
			t.m[k] = e
		}
		if e.path.removed || idle >= flowIdle {
			delete(t.m, k)
		}
	}
}

// keepFlowRatio is how much costlier than the primary a path may become
// before its flows are moved off it. It is above lossSwitchRatio, which
// bars new flows, so that a path whose estimate hovers near the line does
// not have its flows moved back and forth, reordering them.
const keepFlowRatio = 2.5

// costRatio compares q with the primary for carrying flows, returning the
// ratio of their loss terms of the cost (√max(loss, floor)) and whether q
// may carry flows at all. A fallback path carries flows only while the
// primary is one too (no other path is healthy). Otherwise both must be
// healthy (or q is the primary), and q's RTT not drastically worse (at
// most 4x the primary's plus 50 ms). RTT is otherwise left out: RTT estimates swing with queueing and lag changes in
// path delay, and capacity weighting already favors paths that deliver
// more. Cached briefly, since it is asked per packet.
func (c *conn) costRatio(now time.Time, q, prim *path) (float64, bool) {
	if q == prim {
		return 1, true
	}
	if q.removed || !q.validated || (q.fallback && !prim.fallback) {
		return 0, false
	}
	if now.Before(q.ratioAt) {
		return q.ratio, q.ratioOK
	}
	q.ratioAt = now.Add(eligibleCache)
	q.ratioOK = q.healthy(now, c.keepalive) && prim.healthy(now, c.keepalive) &&
		q.rtt.minRTT() <= 4*prim.rtt.minRTT()+50*time.Millisecond
	q.ratio = lossTerm(now, q) / lossTerm(now, prim)
	return q.ratio, q.ratioOK
}

// lossTerm is the loss factor of a path's cost.
func lossTerm(now time.Time, p *path) float64 {
	loss, _ := p.loss(now)
	return math.Sqrt(max(loss, lossFloor))
}

// eligible reports whether new flows may use q while prim is the primary
// path: q must be healthy and not much costlier than prim (the test that
// moves the primary off a lossy path).
func (c *conn) eligible(now time.Time, q, prim *path) bool {
	r, ok := c.costRatio(now, q, prim)
	return ok && r <= lossSwitchRatio
}

// evictGrace is how long a healthy path must stay over keepFlowRatio
// before its flows move. A burst of loss, such as TCP slow start
// overshooting a queue just after flows arrive on a path, decays below the
// line within about a second; sustained loss stays over it. Evicting on the
// burst moved flows off a good path for good, since nothing moves them back.
const evictGrace = 2 * time.Second

// keeps reports whether flows already on q stay there: while it is healthy
// and no more than keepFlowRatio costlier than the primary, or has been
// costlier for less than evictGrace.
func (c *conn) keeps(now time.Time, q, prim *path) bool {
	r, ok := c.costRatio(now, q, prim)
	switch {
	case !ok:
		return false
	case r <= keepFlowRatio:
		q.overSince = time.Time{}
		return true
	case q.overSince.IsZero():
		q.overSince = now
	}
	return now.Sub(q.overSince) < evictGrace
}

// assign picks the path for a new flow: among eligible paths, the one with
// the fewest flows per unit of capacity. A path without a capacity
// estimate (below measuredRate) is assumed as good as the best, so that it
// gets tried; paths slower than measuredRate therefore look faster than
// they are.
func (c *conn) assign(now time.Time, prim *path) *path {
	best := 0.0
	for _, q := range c.paths {
		if c.eligible(now, q, prim) {
			best = max(best, q.capacity(now))
		}
	}
	if best == 0 {
		best = 1
	}
	var choice *path
	var score float64
	for _, q := range c.paths {
		if !c.eligible(now, q, prim) {
			continue
		}
		capacity := q.capacity(now)
		if capacity < measuredRate {
			capacity = best
		}
		if s := float64(q.flows+1) / capacity; choice == nil || s < score {
			choice, score = q, s
		}
	}
	return choice
}

// multipath reports whether more than one validated path exists, the
// only case in which flows need scheduling.
func (c *conn) multipath() bool {
	n := 0
	for _, p := range c.paths {
		if p.validated && !p.removed {
			n++
		}
	}
	return n > 1
}
