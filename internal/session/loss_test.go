package session

import (
	"math"
	"testing"
	"time"
)

func TestLossEstimator(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var l lossEstimator
	if _, ok := l.estimate(now); ok {
		t.Fatal("estimate before any samples")
	}

	// A window closes only with enough outcomes and enough time.
	l.record(now, lossWindow, lossWindow/4)
	if _, ok := l.estimate(now); ok {
		t.Fatal("window closed before lossWindowTime")
	}
	now = now.Add(lossWindowTime)
	l.record(now, 0, 0)
	if r, ok := l.estimate(now); !ok || r != 0.25 {
		t.Fatalf("first window: %v %v, want 0.25", r, ok)
	}

	// Later windows move the estimate by lossGain.
	now = now.Add(lossWindowTime)
	l.record(now, 0, 0) // starts nothing: no outcomes
	l.record(now, lossWindow, 0)
	now = now.Add(lossWindowTime)
	l.record(now, lossWindow, 0)
	if r, _ := l.estimate(now); math.Abs(r-0.25*(1-lossGain)) > 1e-9 {
		t.Fatalf("second window: %v", r)
	}

	// A late arrival cancels a loss; a window cannot go below zero.
	var m lossEstimator
	m.record(now, 4, 2)
	m.record(now, 0, -1)
	m.record(now, 0, -1)
	m.record(now, 0, -1)
	m.record(now.Add(lossWindowTime), lossWindow, 0)
	if r, ok := m.estimate(now.Add(lossWindowTime)); !ok || r != 0 {
		t.Fatalf("late arrivals: %v %v", r, ok)
	}

	// Estimates are forgotten when no new samples arrive.
	if _, ok := l.estimate(now.Add(lossStale + time.Nanosecond)); ok {
		t.Fatal("stale estimate still trusted")
	}
}

// lossTraffic sends 200 packets per second each way for d and returns how
// many times the client's primary path changed and the final primaries of
// the client and the relay.
func lossTraffic(n *network, s *RelaySession, seq *uint32, d time.Duration) (moves int, client, relay uint32) {
	prim := func(paths []PathInfo) uint32 {
		for _, p := range paths {
			if p.Primary {
				return p.ID
			}
		}
		return math.MaxUint32
	}
	last := prim(n.client.Paths(n.now))
	for end := n.now.Add(d); n.now.Before(end); {
		*seq++
		n.client.SendIP(n.now, ipPacket(lease, internet, 600, *seq))
		s.SendIP(n.now, ipPacket(internet, lease, 1000, *seq))
		n.runFor(5 * time.Millisecond)
		if p := prim(n.client.Paths(n.now)); p != last {
			moves++
			last = p
		}
	}
	return moves, last, prim(s.Paths(n.now))
}

func TestLossyPathLosesTraffic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		up, down float64
	}{
		{"both directions 30%", 0.3, 0.3},
		{"uplink 20%", 0.2, 0},
		{"downlink 20%", 0, 0.2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, s, id, _ := establishTwoPaths(t, 40, 30*time.Millisecond)
			var seq uint32
			if _, c, r := lossTraffic(n, s, &seq, time.Second); c != 0 || r != 0 {
				t.Fatalf("primary before loss: client %d, relay %d", c, r)
			}
			n.up.loss, n.down.loss = tc.up, tc.down
			// The primary moves within about a second; the flow, and with
			// it the relay's downlink, follows after evictGrace.
			moves, c, r := lossTraffic(n, s, &seq, 5*time.Second)
			if c != id || r != id || moves != 1 {
				t.Fatalf("after 5 s of loss: client on %d, relay on %d, %d moves; want both on %d after one move", c, r, moves, id)
			}
			// Path 0's estimate is no longer refreshed, so it stays bad
			// until it goes stale; nothing should move in the meantime.
			if moves, c, r := lossTraffic(n, s, &seq, 20*time.Second); moves != 0 || c != id || r != id {
				t.Fatalf("later: %d moves, client on %d, relay on %d", moves, c, r)
			}
		})
	}
}

func TestMildLossKeepsFasterPath(t *testing.T) {
	// 2% loss on the 20 ms path is better for TCP than a clean 60 ms path,
	// and in any case not worth reordering flows over.
	n, s, _, _ := establishTwoPaths(t, 41, 30*time.Millisecond)
	n.up.loss, n.down.loss = 0.02, 0.02
	var seq uint32
	var sum float64
	for range 20 {
		moves, c, r := lossTraffic(n, s, &seq, time.Second)
		if moves != 0 || c != 0 || r != 0 {
			t.Fatalf("%d moves; client on %d, relay on %d", moves, c, r)
		}
		p, _ := pathByID(n.client.Paths(n.now), 0)
		sum += p.Loss
	}
	// The worse of two noisy directions reads a little high on average.
	if mean := sum / 20; mean < 0.015 || mean > 0.035 {
		t.Errorf("path 0 mean loss estimate %.3f, want about 0.02", mean)
	}
}

func TestStandbyKeepaliveDoesNotMoveDownlink(t *testing.T) {
	n, s, id, _ := establishTwoPaths(t, 42, 30*time.Millisecond)
	var seq uint32
	lossTraffic(n, s, &seq, time.Second)
	sent := map[uint32]int{}
	n.pathTap = func(toRelay bool, pathID uint32, data []byte) {
		if !toRelay && len(data) > 1000 {
			sent[pathID]++
		}
	}
	// Several keepalive intervals: path 1 sends PINGs, but downlink data
	// must stay on path 0, where the uplink data is.
	lossTraffic(n, s, &seq, 3*DefaultKeepalive)
	if sent[id] != 0 || sent[0] == 0 {
		t.Fatalf("downlink data packets per path: %v", sent)
	}
}

func TestEquallyLossyPathsDoNotFlap(t *testing.T) {
	// What flapping costs is a flow's packets switching paths, reordering
	// them, so that is what is counted: switches of the path carrying the
	// flow's uplink data. Each path's estimate is forgotten lossStale after
	// it stops carrying traffic, so loss-driven switches come at most about
	// that often.
	n, s, _, c := establishTwoPaths(t, 43, 10*time.Millisecond)
	n.up.loss, n.down.loss = 0.1, 0.1
	c.up.loss, c.down.loss = 0.1, 0.1
	switches, last := 0, uint32(1<<31)
	n.pathTap = func(toRelay bool, pathID uint32, data []byte) {
		if toRelay && len(data) > 500 && pathID != last {
			if last != 1<<31 {
				switches++
			}
			last = pathID
		}
	}
	var seq uint32
	lossTraffic(n, s, &seq, 2*time.Minute)
	t.Logf("%d switches of the flow's path", switches)
	if limit := int(2*time.Minute/lossStale) + 1; switches > limit {
		t.Errorf("the flow switched paths %d times in 2 minutes, want at most %d", switches, limit)
	}
}
