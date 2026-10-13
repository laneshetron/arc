package session

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// TestSentLogInvariants drives a sent log through random sends, ACKs,
// PTOs, and expiry and checks the bookkeeping the fast paths rely on
// against a slow reference scan.
func TestSentLogInvariants(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	var s sentLog
	var rtt rttEstimator
	now := time.Unix(0, 0)
	var next uint64
	ping := []wire.Frame{wire.Ping{}}

	check := func(step int) {
		t.Helper()
		control := 0
		for i, p := range s.packets {
			if i > 0 && p.pn <= s.packets[i-1].pn {
				t.Fatalf("step %d: packets out of order", step)
			}
			if !p.acked && len(p.frames) > 0 {
				control++
			}
		}
		if control != s.control {
			t.Fatalf("step %d: control counter %d, actual %d", step, s.control, control)
		}
		if (s.ptoDeadline(&rtt).IsZero()) != (control == 0) {
			t.Fatalf("step %d: ptoDeadline disagrees with %d outstanding control packets", step, control)
		}
		if len(s.packets) > 0 && s.packets[0].acked {
			t.Fatalf("step %d: retired packet left at the front", step)
		}
	}

	for step := range 20000 {
		now = now.Add(time.Duration(rng.IntN(5)) * time.Millisecond)
		switch r := rng.IntN(100); {
		case r < 55: // send
			p := sentPacket{pn: next, sentAt: now, probe: max(0, 1300*(rng.IntN(50)-48))}
			if rng.IntN(4) == 0 {
				p.frames = ping
			}
			s.add(p)
			next++
		case r < 90 && next > 0: // ACK a random recent range
			hi := next - 1 - uint64(rng.IntN(int(min(next, 20))))
			lo := hi - min(hi, uint64(rng.IntN(10)))
			ack := wire.Ack{Largest: hi}
			const lossDelay = 10 * time.Millisecond
			s.onAck(now, &ack, []wire.PacketRange{{Lo: lo, Hi: hi}}, 0, lossDelay)
			for _, p := range s.packets {
				if !p.acked && p.pn+packetThreshold <= s.largestAcked {
					t.Fatalf("step %d: packet %d outstanding below the loss threshold", step, p.pn)
				}
				if !p.acked && p.pn < s.largestAcked && p.sentAt.Before(s.largestSent.Add(-lossDelay)) {
					t.Fatalf("step %d: packet %d outstanding past the time threshold", step, p.pn)
				}
			}
		case r < 95:
			s.onPTO()
		default:
			s.expire(now, 50*time.Millisecond)
		}
		check(step)
	}
}

func TestMinRTTWindow(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var r rttEstimator
	r.update(now, 20*time.Millisecond, 0)
	// A standing queue for 50 s: the base RTT is still the minimum.
	for i := 1; i <= 50; i++ {
		r.update(now.Add(time.Duration(i)*time.Second), 150*time.Millisecond, 0)
	}
	if got := r.minRTT(); got != 20*time.Millisecond {
		t.Fatalf("after 50 s of queueing: min %v, want 20ms", got)
	}
	// Once the base sample is over a minute old, the window moves on.
	r.update(now.Add(75*time.Second), 150*time.Millisecond, 0)
	if got := r.minRTT(); got != 150*time.Millisecond {
		t.Fatalf("after the window: min %v, want 150ms", got)
	}
	// A lower sample takes over at once.
	r.update(now.Add(76*time.Second), 30*time.Millisecond, 0)
	if got := r.minRTT(); got != 30*time.Millisecond {
		t.Fatalf("new lower sample: min %v, want 30ms", got)
	}
}
