package session

import (
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

func TestFlowKey(t *testing.T) {
	up := flowPacket(lease, internet, 40000, 443, 100, 1)
	down := flowPacket(internet, lease, 443, 40000, 100, 1)
	ku, ok1 := flowKeyOf(up, true)
	kd, ok2 := flowKeyOf(down, false)
	if !ok1 || !ok2 || ku != kd {
		t.Fatalf("uplink key %+v and downlink key %+v of one flow differ", ku, kd)
	}
	if ku.lport != 40000 || ku.rport != 443 || ku.local != lease || ku.proto != 17 {
		t.Errorf("key %+v", ku)
	}
	other, _ := flowKeyOf(flowPacket(lease, internet, 40001, 443, 100, 1), true)
	if other == ku {
		t.Error("different source ports share a key")
	}
	frag := flowPacket(lease, internet, 40000, 443, 100, 1)
	frag[6] = 0x20 // more fragments: ports are not trustworthy
	if k, _ := flowKeyOf(frag, true); k.lport != 0 || k.rport != 0 {
		t.Errorf("fragment key has ports: %+v", k)
	}
	if _, ok := flowKeyOf([]byte{0x60, 0, 0, 0}, true); ok {
		t.Error("non-IPv4 packet keyed")
	}
}

func TestRateMax(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var r rateMax
	for i := range 8 { // 1 s at 100 kB per 250 ms window
		r.add(now.Add(time.Duration(i)*rateWindow/2), 50_000)
	}
	now = now.Add(time.Second)
	if got := r.max(now); got != 400_000 {
		t.Fatalf("max = %v, want 400000 B/s", got)
	}
	if got := r.max(now.Add(rateWindows * rateWindow)); got != 0 {
		t.Errorf("after the whole ring idle: max = %v, want 0", got)
	}
}

// flowLoad offers flows open-loop traffic each way for d: each flow sends
// a 1000-byte packet each way every interval. It returns bytes delivered
// up and down.
func flowLoad(n *network, s *RelaySession, flows int, interval, d time.Duration) (up, down int) {
	upBefore, downBefore := ipBytes(n.relayIPs()), ipBytes(n.clientIPs())
	var seq uint32
	for end := n.now.Add(d); n.now.Before(end); {
		for i := range flows {
			seq++
			n.client.SendIP(n.now, flowPacket(lease, internet, uint16(40000+i), 443, 1000, seq))
			s.SendIP(n.now, flowPacket(internet, lease, 443, uint16(40000+i), 1000, seq))
		}
		n.runFor(interval)
	}
	return ipBytes(n.relayIPs()) - upBefore, ipBytes(n.clientIPs()) - downBefore
}

func ipBytes(pkts [][]byte) int {
	n := 0
	for _, p := range pkts {
		n += len(p)
	}
	return n
}

// rateLimitedPaths returns two validated paths, each limited to rate bytes
// per second in both directions with the given one-way delays.
func rateLimitedPaths(t *testing.T, seed uint64, rate0, rate1 int, cc ClientConfig) (*network, *RelaySession, *carrier) {
	t.Helper()
	n, s, c := lossyPaths(t, seed, cc, defaultRelayConfig(), 0)
	n.up.rate, n.down.rate = rate0, rate0
	c.up.rate, c.down.rate = rate1, rate1
	return n, s, c
}

func TestFlowsSpreadAcrossPaths(t *testing.T) {
	// Two 1 MB/s paths and 8 flows offering 3.2 MB/s each way: with flows
	// pinned to one path the tunnel carries 1 MB/s, spread it carries 2.
	n, s, _ := rateLimitedPaths(t, 100, 1_000_000, 1_000_000, ClientConfig{})
	up, down := flowLoad(n, s, 8, 2500*time.Microsecond, 5*time.Second)
	upRate, downRate := float64(up)/5, float64(down)/5
	t.Logf("delivered %.2f MB/s up, %.2f MB/s down; flows per path %d/%d",
		upRate/1e6, downRate/1e6, n.client.conn.path(0).flows, n.client.conn.path(1).flows)
	if upRate < 1.4e6 || downRate < 1.4e6 {
		t.Errorf("delivered %.2f MB/s up and %.2f down; want about 2 each, more than one path's 1", upRate/1e6, downRate/1e6)
	}
}

func TestFlowsWeightedByCapacity(t *testing.T) {
	// Paths of 2 MB/s and 0.5 MB/s. Once both have been measured busy, new
	// flows go about four to one.
	n, s, _ := rateLimitedPaths(t, 101, 2_000_000, 500_000, ClientConfig{})
	flowLoad(n, s, 4, 1*time.Millisecond, 3*time.Second) // saturates both
	before := [2]int{n.client.conn.path(0).flows, n.client.conn.path(1).flows}
	var seq uint32
	for i := range 20 { // 20 new flows, one packet each
		seq++
		n.client.SendIP(n.now, flowPacket(lease, internet, uint16(50000+i), 443, 200, seq))
	}
	got := [2]int{n.client.conn.path(0).flows - before[0], n.client.conn.path(1).flows - before[1]}
	t.Logf("capacity %.2f / %.2f MB/s; new flows %v", n.client.conn.path(0).capacity(n.now)/1e6,
		n.client.conn.path(1).capacity(n.now)/1e6, got)
	if got[0] < 2*got[1] {
		t.Errorf("new flows %v; want most on the faster path", got)
	}
}

func TestSingleFlowStaysOnOnePath(t *testing.T) {
	n, s, _ := rateLimitedPaths(t, 102, 1_000_000, 1_000_000, ClientConfig{})
	sent := map[uint32]int{}
	n.pathTap = func(toRelay bool, pathID uint32, data []byte) {
		if toRelay && len(data) > 900 {
			sent[pathID]++
		}
	}
	flowLoad(n, s, 1, 2*time.Millisecond, 3*time.Second)
	if len(sent) != 1 {
		t.Errorf("one flow's packets went out on %d paths: %v", len(sent), sent)
	}
}

func TestFlowsAvoidLossyPath(t *testing.T) {
	// Path 1 turns 30% lossy: its flows move to path 0 and new flows avoid
	// it. The load (0.6 MB/s) fits on one path; open-loop overload would
	// add congestion loss that TCP would back off from.
	n, s, c := rateLimitedPaths(t, 103, 1_000_000, 1_000_000, ClientConfig{})
	flowLoad(n, s, 6, 10*time.Millisecond, 2*time.Second)
	if n.client.conn.path(1).flows == 0 {
		t.Fatal("no flows on path 1 to begin with")
	}
	c.up.loss, c.down.loss = 0.3, 0.3
	flowLoad(n, s, 6, 10*time.Millisecond, 3*time.Second)
	sent := 0
	n.pathTap = func(toRelay bool, pathID uint32, data []byte) {
		if toRelay && pathID == 1 && len(data) > 900 {
			sent++
		}
	}
	flowLoad(n, s, 12, 20*time.Millisecond, time.Second)
	if sent != 0 {
		t.Errorf("%d data packets still sent on the lossy path", sent)
	}
}

func TestFlowTableBounded(t *testing.T) {
	n, s, _ := rateLimitedPaths(t, 104, 0, 0, ClientConfig{})
	_ = s
	var seq uint32
	for i := range maxFlows + 500 {
		seq++
		n.client.SendIP(n.now, flowPacket(lease, [4]byte{198, 51, byte(i >> 8), byte(i)}, 40000, 443, 100, seq))
	}
	if got := len(n.client.flows.m); got > maxFlows {
		t.Fatalf("flow table holds %d entries, limit %d", got, maxFlows)
	}
	n.runFor(flowIdle + 2*flowSweep)
	if got := len(n.client.flows.m); got != 0 {
		t.Errorf("%d idle flows not swept", got)
	}
	total := 0
	for _, p := range n.client.conn.paths {
		total += p.flows
	}
	if total != 0 {
		t.Errorf("per-path flow counts sum to %d after the sweep", total)
	}
}

func TestPingLossNotCounted(t *testing.T) {
	// Pings sent into an outage are all declared lost once the path
	// recovers; counting them left a recovered path looking lossy, so it
	// took no flows for 30 s (seen in the degraded suite). Pings count for
	// health only, like MTU probes; data and control packets count for loss.
	now := time.Unix(1_000_000, 0)
	var s sentLog
	for pn := range uint64(20) {
		s.add(sentPacket{pn: pn, sentAt: now, ping: pn < 10, size: 100})
	}
	ack := wire.Ack{Largest: 19}
	res := s.onAck(now, &ack, []wire.PacketRange{{Lo: 19, Hi: 19}}, 0, 0)
	if res.lostCount != 7 { // data packets 10..16 lost; 17 and 18 within the threshold
		t.Errorf("lost %d, want 7: pings must not count", res.lostCount)
	}
	if res.delivered != 1 || res.deliveredBytes != 100 {
		t.Errorf("delivered %d (%d bytes), want 1 (100)", res.delivered, res.deliveredBytes)
	}
}

func TestEndedFlowsDoNotRepelNewOnes(t *testing.T) {
	// Flows that ended a moment ago must not count toward their path's
	// load, or a burst of short connections keeps new flows off it.
	n, s, c := rateLimitedPaths(t, 112, 1_000_000, 1_000_000, ClientConfig{})
	c.up.down, c.down.down = true, true
	flowLoad(n, s, 6, 10*time.Millisecond, 2*time.Second) // all on path 0
	c.up.down, c.down.down = false, false
	n.runFor(2 * time.Second) // path 1 recovers; the 6 flows have ended
	var seq uint32
	for i := range 4 {
		seq++
		n.client.SendIP(n.now, flowPacket(lease, internet, uint16(50000+i), 443, 200, seq))
	}
	got := [2]int{n.client.conn.path(0).flows, n.client.conn.path(1).flows}
	if got != [2]int{2, 2} { // counts refresh when a flow is assigned
		t.Errorf("4 new flows went %v, want 2 and 2", got)
	}
}

func TestFallbackPathCarriesTrafficOnlyWhenNeeded(t *testing.T) {
	// Path 1 is a fallback (TLS/TCP): flows stay off it while path 0 is
	// healthy, move to it when path 0 dies, and come back when it returns.
	n, s, _ := rateLimitedPaths(t, 120, 1_000_000, 1_000_000, ClientConfig{})
	n.client.SetFallback(1, true)
	sent := map[uint32]int{}
	n.pathTap = func(toRelay bool, pathID uint32, data []byte) {
		if len(data) > 900 {
			sent[pathID]++
		}
	}
	flowLoad(n, s, 6, 10*time.Millisecond, 2*time.Second)
	if sent[1] != 0 || sent[0] == 0 {
		t.Fatalf("with path 0 healthy, data packets per path %v", sent)
	}
	n.up.down, n.down.down = true, true
	flowLoad(n, s, 6, 10*time.Millisecond, 2*time.Second) // failover
	clear(sent)
	up, down := flowLoad(n, s, 6, 10*time.Millisecond, 2*time.Second)
	if sent[0] != 0 || up == 0 || down == 0 {
		t.Fatalf("with path 0 dead: per path %v, delivered %d up and %d down", sent, up, down)
	}
	n.up.down, n.down.down = false, false
	flowLoad(n, s, 6, 10*time.Millisecond, 3*time.Second) // path 0 recovers
	clear(sent)
	flowLoad(n, s, 6, 10*time.Millisecond, time.Second)
	if sent[1] != 0 {
		t.Errorf("after path 0 recovered, %d data packets still on the fallback", sent[1])
	}
}
