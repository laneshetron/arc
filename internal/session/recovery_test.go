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
			s.onAck(now, &ack, []wire.PacketRange{{Lo: lo, Hi: hi}}, 0)
			for _, p := range s.packets {
				if !p.acked && p.pn+packetThreshold <= s.largestAcked {
					t.Fatalf("step %d: packet %d outstanding below the loss threshold", step, p.pn)
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
