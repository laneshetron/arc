package session

import (
	"testing"
	"time"
)

func TestStreamCCRegularSlowAcksNotStalls(t *testing.T) {
	// One acknowledgement every 40 ms, with a send between each: a
	// regular cadence, never a stall.
	const mss = 1300
	now := time.Unix(1_000_000, 0)
	var cc streamCC
	cc.observeRTT(now, 400*time.Millisecond)
	cc.start(now, 400*time.Millisecond, mss)
	for range 100 {
		now = now.Add(20 * time.Millisecond)
		cc.onSent(now, mss)
		now = now.Add(20 * time.Millisecond)
		cc.onAck(now, 1, 0, mss, 400*time.Millisecond, mss)
	}
	if cc.stalls > 2 {
		t.Errorf("%d stalls in 100 regular acknowledgements 40 ms apart (ackGap %v)", cc.stalls, cc.ackGap)
	}
}

func TestStreamCCIdleRoundsDontBackOff(t *testing.T) {
	// Between transfers a path carries light background traffic, whose
	// few RTT samples on a jittery link can look like a queue two rounds
	// running. A round that didn't use its rate didn't build that queue:
	// backing off for it halved the rate each time (8.7 -> 1.1 Mbit/s on a
	// Mac's Wi-Fi between speed tests), and the next transfer started
	// there.
	const mss = 1300
	now := time.Unix(1_000_000, 0)
	minRTT, srtt := 20*time.Millisecond, 25*time.Millisecond
	var cc streamCC
	cc.observeRTT(now, minRTT)
	cc.start(now, srtt, mss)
	cc.slowStart = false
	cc.rate = 10e6 / 8 // 10 Mbit/s
	before := cc.rate
	for range 10 {
		// One small packet per round, acknowledged with an RTT sample well
		// above the queue target.
		cc.onSent(now, mss)
		now = now.Add(srtt)
		cc.onAck(now, 1, 0, mss, minRTT+40*time.Millisecond, 0)
		cc.update(now, minRTT, srtt, mss)
	}
	if cc.rate < before {
		t.Errorf("app-limited rounds took the rate from %.1f to %.1f Mbit/s", before*8/1e6, cc.rate*8/1e6)
	}
	if cc.backoffsIdle != 0 {
		t.Errorf("%d backoffs in app-limited rounds", cc.backoffsIdle)
	}
}
