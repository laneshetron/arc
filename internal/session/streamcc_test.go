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
