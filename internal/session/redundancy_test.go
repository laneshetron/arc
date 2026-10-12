package session

import (
	"sort"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// redundancyRun sends count packets each way, 5 ms apart, and returns the
// fraction delivered in each direction. It fails the test if any packet is
// delivered twice.
func redundancyRun(t *testing.T, n *network, s *RelaySession, size, count int) (up, down float64) {
	t.Helper()
	base := uint32(len(n.relayIPs()) + len(n.clientIPs()) + 1_000_000) // distinct from earlier runs
	upBefore, downBefore := len(n.relayIPs()), len(n.clientIPs())
	for i := range count {
		n.client.SendIP(n.now, ipPacket(lease, internet, size, base+uint32(i)))
		s.SendIP(n.now, ipPacket(internet, lease, size, base+uint32(i)))
		n.runFor(5 * time.Millisecond)
	}
	n.runFor(time.Second)
	for _, got := range [][][]byte{n.relayIPs()[upBefore:], n.clientIPs()[downBefore:]} {
		seen := map[uint32]bool{}
		for _, p := range got {
			if seen[seqOf(p)] {
				t.Fatalf("packet %d delivered twice", seqOf(p))
			}
			seen[seqOf(p)] = true
		}
	}
	return float64(len(n.relayIPs())-upBefore) / float64(count),
		float64(len(n.clientIPs())-downBefore) / float64(count)
}

func lossyPaths(t *testing.T, seed uint64, cc ClientConfig, rc RelayConfig, loss float64) (*network, *RelaySession, *carrier) {
	t.Helper()
	n := newNetwork(t, seed, rc, cc)
	s := n.establish()
	n.runFor(200 * time.Millisecond)
	id, c := n.openPath("198.51.100.20:5000", 10*time.Millisecond)
	if !n.runUntil(2*time.Second, func() bool {
		return n.clientEventsOf(func(e ClientEvent) bool { v, ok := e.(PathValidated); return ok && v.ID == id }) == 1
	}) {
		t.Fatal("path 1 not validated")
	}
	n.runFor(200 * time.Millisecond)
	n.up.loss, n.down.loss, c.up.loss, c.down.loss = loss, loss, loss, loss
	return n, s, c
}

func TestRedundancyAlways(t *testing.T) {
	// Two paths each losing 10% independently: one copy of each packet
	// gets through about 99% of the time.
	n, s, _ := lossyPaths(t, 60, ClientConfig{Redundancy: RedundancyAlways}, defaultRelayConfig(), 0.1)
	up, down := redundancyRun(t, n, s, 600, 2000)
	t.Logf("delivered: uplink %.3f, downlink %.3f", up, down)
	if up < 0.97 || down < 0.97 {
		t.Errorf("delivered uplink %.3f, downlink %.3f; want about 0.99", up, down)
	}
	if n.client.Stats().RedundantSent == 0 || s.Stats().RedundantSent == 0 ||
		n.client.Stats().DuplicatesDropped == 0 || s.Stats().DuplicatesDropped == 0 {
		t.Errorf("client stats %+v, relay stats %+v", n.client.Stats(), s.Stats())
	}
}

func TestRedundancyOff(t *testing.T) {
	n, s, _ := lossyPaths(t, 60, ClientConfig{}, defaultRelayConfig(), 0.1)
	up, down := redundancyRun(t, n, s, 600, 2000)
	if up > 0.93 || down > 0.93 {
		t.Errorf("delivered uplink %.3f, downlink %.3f without redundancy; want about 0.9", up, down)
	}
	if n.client.Stats().RedundantSent != 0 || s.Stats().RedundantSent != 0 {
		t.Error("sent copies with redundancy off")
	}
}

func TestRedundancyAuto(t *testing.T) {
	n, s, c := lossyPaths(t, 61, ClientConfig{Redundancy: RedundancyAuto}, defaultRelayConfig(), 0.05)
	changed := func() []RedundancyChanged {
		var out []RedundancyChanged
		for _, e := range n.clientEvents {
			if r, ok := e.(RedundancyChanged); ok {
				out = append(out, r)
			}
		}
		return out
	}
	up, down := redundancyRun(t, n, s, 600, 2000)
	t.Logf("at 5%% loss: uplink %.3f, downlink %.3f; changes %v", up, down, changed())
	if ch := changed(); len(ch) == 0 || ch[len(ch)-1] != (RedundancyChanged{true, true}) {
		t.Fatalf("redundancy changes %v; want on in both directions", ch)
	}
	if up < 0.98 || down < 0.98 {
		t.Errorf("delivered uplink %.3f, downlink %.3f; want about 0.997", up, down)
	}

	// The loss clears: redundancy turns off once the estimates fall.
	n.up.loss, n.down.loss, c.up.loss, c.down.loss = 0, 0, 0, 0
	redundancyRun(t, n, s, 600, 1000)
	if ch := changed(); ch[len(ch)-1] != (RedundancyChanged{false, false}) {
		t.Fatalf("redundancy changes %v; want off after the loss cleared", ch)
	}
	sent := s.Stats().RedundantSent
	redundancyRun(t, n, s, 600, 200)
	if s.Stats().RedundantSent != sent {
		t.Error("relay still duplicates downlink after the client turned it off")
	}
}

func TestRedundancyOnlyDownlink(t *testing.T) {
	// Downlink-only loss turns on downlink redundancy alone.
	n, s, c := lossyPaths(t, 62, ClientConfig{Redundancy: RedundancyAuto}, defaultRelayConfig(), 0)
	n.down.loss, c.down.loss = 0.05, 0.05
	redundancyRun(t, n, s, 600, 2000)
	if n.client.Stats().RedundantSent != 0 || s.Stats().RedundantSent == 0 {
		t.Errorf("copies sent: uplink %d, downlink %d; want downlink only",
			n.client.Stats().RedundantSent, s.Stats().RedundantSent)
	}
}

func TestRedundancyDeclinedByRelay(t *testing.T) {
	rc := defaultRelayConfig()
	rc.NoRedundancy = true
	n, s, _ := lossyPaths(t, 63, ClientConfig{Redundancy: RedundancyAlways}, rc, 0)
	redundancyRun(t, n, s, 600, 200)
	if n.client.Stats().RedundantSent != 0 || s.Stats().RedundantSent != 0 {
		t.Error("copies sent although the relay does not support redundancy")
	}
	if p, _ := pathByID(n.client.Paths(n.now), 0); p.MaxPacket != 1280+dataOverhead {
		t.Errorf("max packet %d: probed for IP_DATAGRAM without redundancy", p.MaxPacket)
	}
}

func TestRedundancyWithFragments(t *testing.T) {
	// Full-size packets: path 0 carries them whole as IP_DATAGRAM, path 1
	// (smaller MTU) in IP_FRAGMENTs with the same datagram ID. Each is
	// delivered once whichever copy completes first.
	n := newNetwork(t, 64, defaultRelayConfig(), ClientConfig{Redundancy: RedundancyAlways})
	s := n.establish()
	n.runFor(200 * time.Millisecond)
	id, c := n.openPath("198.51.100.20:5000", 3*time.Millisecond)
	c.up.mtu, c.down.mtu = DefaultMaxPacketSize, DefaultMaxPacketSize
	n.runUntil(2*time.Second, func() bool {
		return n.clientEventsOf(func(e ClientEvent) bool { v, ok := e.(PathValidated); return ok && v.ID == id }) == 1
	})
	n.runFor(time.Second)
	if p, _ := pathByID(n.client.Paths(n.now), id); p.MaxPacket != DefaultMaxPacketSize {
		t.Fatalf("path 1 max packet %d; the test needs it to fragment", p.MaxPacket)
	}
	n.up.loss, n.down.loss, c.up.loss, c.down.loss = 0.1, 0.1, 0.1, 0.1
	up, down := redundancyRun(t, n, s, 1280, 1000)
	t.Logf("delivered: uplink %.3f, downlink %.3f", up, down)
	if up < 0.95 || down < 0.95 {
		t.Errorf("delivered uplink %.3f, downlink %.3f", up, down)
	}
}

func TestStaleRedundancyRequestIgnored(t *testing.T) {
	_, s, _ := lossyPaths(t, 65, ClientConfig{}, defaultRelayConfig(), 0)
	s.onRedundancy(wire.Redundancy{Seq: 2, Mode: wire.RedundancyDuplicate})
	s.onRedundancy(wire.Redundancy{Seq: 1, Mode: wire.RedundancyNone}) // retransmitted, older
	if !s.conn.redundant {
		t.Error("an older request overrode a newer one")
	}
	s.onRedundancy(wire.Redundancy{Seq: 3, Mode: wire.RedundancyNone})
	if s.conn.redundant {
		t.Error("a newer request was ignored")
	}
}

func TestRedundancyWithNoHealthyPath(t *testing.T) {
	// At 90% loss with sparse traffic (5 packets per second, like pings)
	// neither path counts as healthy; copies must still go out on both,
	// since that is when they matter most: about 19% of packets get
	// through each way instead of 10%.
	n, s, _ := lossyPaths(t, 66, ClientConfig{Redundancy: RedundancyAlways}, defaultRelayConfig(), 0.9)
	const count = 3000
	upBefore, downBefore, healthy := len(n.relayIPs()), len(n.clientIPs()), 0
	for i := range count {
		n.client.SendIP(n.now, ipPacket(lease, internet, 100, uint32(i)))
		s.SendIP(n.now, ipPacket(internet, lease, 100, uint32(i)))
		n.runFor(200 * time.Millisecond)
		for _, p := range n.client.Paths(n.now) {
			if p.Healthy {
				healthy++
				break
			}
		}
	}
	up := float64(len(n.relayIPs())-upBefore) / count
	down := float64(len(n.clientIPs())-downBefore) / count
	t.Logf("delivered: uplink %.3f, downlink %.3f; a healthy path existed %d%% of the time", up, down, healthy*100/count)
	if up < 0.16 || down < 0.16 {
		t.Errorf("delivered uplink %.3f, downlink %.3f; want about 0.19", up, down)
	}
}

// TestRedundancyAutoEngagesQuicklyUnderHeavyLoss: at 90% loss on every
// path with sparse traffic (5 packets per second each way), auto
// redundancy must be on at both ends within a few seconds. The loss
// estimates update slowly when acknowledgements barely arrive, and the
// REDUNDANCY request must get through the same loss.
func TestRedundancyAutoEngagesQuicklyUnderHeavyLoss(t *testing.T) {
	var times []time.Duration
	for seed := range uint64(10) {
		n, s, _ := lossyPaths(t, 200+seed, ClientConfig{Redundancy: RedundancyAuto}, defaultRelayConfig(), 0.9)
		start, engaged := n.now, time.Duration(0)
		for i := range 300 { // up to 60 s
			n.client.SendIP(n.now, ipPacket(lease, internet, 100, uint32(i)))
			s.SendIP(n.now, ipPacket(internet, lease, 100, uint32(i)))
			n.runFor(200 * time.Millisecond)
			if n.client.conn.redundant && s.conn.redundant {
				engaged = n.now.Sub(start)
				break
			}
		}
		if engaged == 0 {
			t.Fatalf("seed %d: redundancy not on at both ends within 60 s", seed)
		}
		times = append(times, engaged)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	t.Logf("on at both ends after %v", times)
	// Before control-frame copies and the unhealthy-primary rule: 5-37 s.
	if median, worst := times[len(times)/2], times[len(times)-1]; median > 3*time.Second || worst > 10*time.Second {
		t.Errorf("median %v, worst %v; want at most 3 s and 10 s", median, worst)
	}
}
