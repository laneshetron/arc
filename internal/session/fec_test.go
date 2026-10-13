package session

import (
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// fecRun establishes a single-path session with the given FEC mode,
// applies loss to its link, and returns the fraction of packets delivered
// each way (redundancyRun also fails on any duplicate delivery).
func fecRun(t *testing.T, seed uint64, mode wire.FECMode, rc RelayConfig, setLoss func(up, down *link), count int) (up, down float64, n *network, s *RelaySession) {
	t.Helper()
	n = newNetwork(t, seed, rc, ClientConfig{FEC: mode})
	s = n.establish()
	n.runFor(time.Second) // MTU probes complete
	setLoss(n.up, n.down)
	up, down = bulkRun(t, n, s, count)
	return up, down, n, s
}

// bulkRun sends count packets each way, 1 ms apart (a bulk-transfer rate,
// unlike redundancyRun's 5 ms), and returns the fraction delivered each
// way, failing on any packet delivered twice.
func bulkRun(t *testing.T, n *network, s *RelaySession, count int) (up, down float64) {
	t.Helper()
	upBefore, downBefore := len(n.relayIPs()), len(n.clientIPs())
	for i := range count {
		n.client.SendIP(n.now, ipPacket(lease, internet, 1200, uint32(i)))
		s.SendIP(n.now, ipPacket(internet, lease, 1200, uint32(i)))
		n.runFor(time.Millisecond)
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

func TestFECRecoversLoss(t *testing.T) {
	uniform := func(p float64) func(up, down *link) {
		return func(up, down *link) { up.loss, down.loss = p, p }
	}
	for _, tc := range []struct {
		name    string
		mode    wire.FECMode
		loss    func(up, down *link)
		atLeast float64 // delivered fraction each way
	}{
		{"off, uniform 5%", wire.FECOff, uniform(0.05), 0.93},
		{"auto, uniform 5%", wire.FECAuto, uniform(0.05), 0.99},
		{"always, uniform 1%", wire.FECAlways, uniform(0.01), 0.995},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, down, n, s := fecRun(t, 50, tc.mode, defaultRelayConfig(), tc.loss, 20000)
			t.Logf("delivered up %.4f, down %.4f; repairs per packet %.2f/%.2f, recovered %d/%d",
				up, down, float64(n.client.Stats().FECRepairsSent)/20000, float64(s.Stats().FECRepairsSent)/20000,
				s.Stats().FECRecovered, n.client.Stats().FECRecovered)
			if up < tc.atLeast || down < tc.atLeast {
				t.Errorf("delivered up %.4f, down %.4f; want at least %.3f", up, down, tc.atLeast)
			}
			if tc.mode == wire.FECOff && (n.client.Stats().FECRepairsSent != 0 || s.Stats().FECRepairsSent != 0) {
				t.Error("repairs sent with FEC off")
			}
		})
	}
}

func TestFECAutoIdleOnCleanPath(t *testing.T) {
	// Auto sends no repairs, and no datagram IDs, without loss.
	var ids int
	_, _, n, s := fecRun(t, 51, wire.FECAuto, defaultRelayConfig(), func(up, down *link) {}, 2000)
	n.tap = func(toRelay bool, data []byte) { ids++ }
	if n.client.Stats().FECRepairsSent != 0 || s.Stats().FECRepairsSent != 0 {
		t.Errorf("repairs sent on a clean path: %d up, %d down",
			n.client.Stats().FECRepairsSent, s.Stats().FECRepairsSent)
	}
}

func TestFECDeclinedByRelay(t *testing.T) {
	rc := defaultRelayConfig()
	rc.NoFEC = true
	up, down, n, s := fecRun(t, 52, wire.FECAlways, rc, func(up, down *link) { up.loss, down.loss = 0.05, 0.05 }, 2000)
	if n.client.Stats().FECRepairsSent != 0 || s.Stats().FECRepairsSent != 0 {
		t.Error("repairs sent although the relay declined FEC")
	}
	if up > 0.97 || down > 0.97 {
		t.Errorf("delivered %.3f up and %.3f down without FEC at 5%% loss", up, down)
	}
}

func TestExpandID(t *testing.T) {
	c := &conn{}
	if got := c.expandID(7); got != 7 {
		t.Errorf("before any delivery: %d", got)
	}
	base := uint64(5)<<32 + 0xfffffff0
	c.dedup.Deliver(base)
	for _, tc := range []struct {
		low  uint32
		want uint64
	}{
		{0xffffffe0, base - 0x10}, // just below
		{0xfffffff8, base + 8},    // just above
		{0x00000010, base + 0x20}, // wrapped past 2^32
	} {
		if got := c.expandID(tc.low); got != tc.want {
			t.Errorf("expandID(%#x) = %#x, want %#x", tc.low, got, tc.want)
		}
	}
}

func TestFECBurstyLoss(t *testing.T) {
	// Long bursts (5% in bursts of 10) need deep interleaving, which needs
	// a group of packets spanning several bursts within the block window.
	bursty := func(up, down *link) { up.bursty(0.05, 10); down.bursty(0.05, 10) }

	// At 1000 packets/s and a 20 ms RTT a group cannot, so once auto has
	// measured the bursts it stays off rather than spend repairs the
	// bursts would take with them. (Before then it protects as for short
	// bursts, which is where these repairs come from.)
	_, _, n, s := fecRun(t, 53, wire.FECAuto, defaultRelayConfig(), bursty, 20000)
	if sent := n.client.Stats().FECRepairsSent + s.Stats().FECRepairsSent; sent > 8000 {
		t.Errorf("%d repairs for 40000 packets at a rate too low to spread bursts; want at most 20%%", sent)
	}

	// At 4000 packets/s it can, and FEC recovers part of the loss: long
	// bursts are hard on one path even then (the codec alone, with larger
	// groups, leaves about a sixth of it).
	run := func(mode wire.FECMode) (float64, float64, Stats, Stats) {
		n := newNetwork(t, 54, defaultRelayConfig(), ClientConfig{FEC: mode})
		s := n.establish()
		n.runFor(time.Second)
		bursty(n.up, n.down)
		upBefore, downBefore := len(n.relayIPs()), len(n.clientIPs())
		const count = 40000
		for i := range count {
			n.client.SendIP(n.now, ipPacket(lease, internet, 1200, uint32(i)))
			s.SendIP(n.now, ipPacket(internet, lease, 1200, uint32(i)))
			n.runFor(250 * time.Microsecond)
		}
		n.runFor(time.Second)
		return float64(len(n.relayIPs())-upBefore) / count, float64(len(n.clientIPs())-downBefore) / count,
			n.client.Stats(), s.Stats()
	}
	offUp, offDown, _, _ := run(wire.FECOff)
	up, down, cs, rs := run(wire.FECAuto)
	t.Logf("at 4000 packets/s: delivered without FEC %.4f/%.4f, with %.4f/%.4f; repairs per packet %.2f/%.2f",
		offUp, offDown, up, down, float64(cs.FECRepairsSent)/40000, float64(rs.FECRepairsSent)/40000)
	if 1-up > 0.7*(1-offUp) || 1-down > 0.7*(1-offDown) {
		t.Errorf("FEC left loss at %.4f/%.4f, against %.4f/%.4f without; want it cut by at least 30%%",
			1-up, 1-down, 1-offUp, 1-offDown)
	}
}
