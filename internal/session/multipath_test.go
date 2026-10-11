package session

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

func pathByID(paths []PathInfo, id uint32) (PathInfo, bool) {
	for _, p := range paths {
		if p.ID == id {
			return p, true
		}
	}
	return PathInfo{}, false
}

// establishTwoPaths returns a network with path 0 and a validated path 1.
func establishTwoPaths(t *testing.T, seed uint64, delay1 time.Duration) (*network, *RelaySession, uint32, *carrier) {
	t.Helper()
	n := newNetwork(t, seed, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	n.runFor(200 * time.Millisecond) // NEW_PATH slots arrive
	id, c := n.openPath("198.51.100.20:5000", delay1)
	ok := n.runUntil(2*time.Second, func() bool {
		return n.clientEventsOf(func(e ClientEvent) bool { v, ok := e.(PathValidated); return ok && v.ID == id }) == 1
	})
	if !ok {
		t.Fatal("path 1 not validated")
	}
	n.runFor(200 * time.Millisecond)
	return n, s, id, c
}

func TestOpenPathValidates(t *testing.T) {
	n, s, id, _ := establishTwoPaths(t, 30, 20*time.Millisecond)
	if id != 1 {
		t.Errorf("first path ID = %d", id)
	}
	for _, side := range [][]PathInfo{n.client.Paths(n.now), s.Paths(n.now)} {
		p, ok := pathByID(side, id)
		if !ok || !p.Validated || !p.Healthy {
			t.Errorf("path %d = %+v (found %v)", id, p, ok)
		}
	}
	if len(n.client.slots) != spareSlots {
		t.Errorf("client holds %d spare slots, want %d", len(n.client.slots), spareSlots)
	}
	if n.relay.Stats().Handshakes != 1 {
		t.Error("joining a path cost a handshake")
	}
}

func TestOpenPathNeedsSlotsAndActiveSession(t *testing.T) {
	n := newNetwork(t, 31, defaultRelayConfig(), ClientConfig{})
	if _, err := n.client.OpenPath(n.now); !errors.Is(err, ErrNotActive) {
		t.Errorf("before establishment: %v", err)
	}
	n.establish()
	n.runFor(time.Second)
	for range spareSlots {
		if _, err := n.client.OpenPath(n.now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := n.client.OpenPath(n.now); !errors.Is(err, ErrNoPathSlots) {
		t.Errorf("with slots exhausted: %v", err)
	}
}

func TestFailover(t *testing.T) {
	n, s, id, _ := establishTwoPaths(t, 32, 30*time.Millisecond)

	var seq uint32
	tick := func() {
		seq++
		n.client.SendIP(n.now, ipPacket(lease, internet, 200, seq))
		s.SendIP(n.now, ipPacket(internet, lease, 200, seq))
		n.runFor(10 * time.Millisecond)
	}
	for range 100 {
		tick()
	}
	if p, _ := pathByID(n.client.Paths(n.now), 0); !p.Primary {
		t.Fatal("path 0 should be primary before the failure")
	}

	n.up.down, n.down.down = true, true
	failedAt, upBefore, downBefore := n.now, len(n.relayIPs()), len(n.clientIPs())
	var upAt, downAt time.Time
	for n.now.Sub(failedAt) < 5*time.Second && (upAt.IsZero() || downAt.IsZero()) {
		tick()
		if upAt.IsZero() && len(n.relayIPs()) > upBefore+1 {
			upAt = n.now
		}
		if downAt.IsZero() && len(n.clientIPs()) > downBefore+1 {
			downAt = n.now
		}
	}
	if upAt.IsZero() || downAt.IsZero() {
		t.Fatalf("traffic did not recover: up %v, down %v", upAt, downAt)
	}
	// §22 target: sub-2-second recovery onto an already-validated path.
	if d := upAt.Sub(failedAt); d > 2*time.Second {
		t.Errorf("uplink recovered after %v", d)
	}
	if d := downAt.Sub(failedAt); d > 2*time.Second {
		t.Errorf("downlink recovered after %v", d)
	}
	t.Logf("recovery: uplink %v, downlink %v", upAt.Sub(failedAt), downAt.Sub(failedAt))
	if p, _ := pathByID(n.client.Paths(n.now), id); !p.Primary {
		t.Error("path 1 is not primary after failover")
	}
	if n.relay.Stats().Handshakes != 1 || s.Config().IPv4 != lease || n.client.State() != StateActive {
		t.Error("failover changed the session")
	}

	// After PathTimeout the dead path is abandoned on both sides.
	n.runFor(PathTimeout + 5*time.Second)
	if n.clientEventsOf(func(e ClientEvent) bool { c, ok := e.(PathClosed); return ok && c.ID == 0 }) != 1 {
		t.Error("client did not close dead path 0")
	}
	if _, ok := pathByID(s.Paths(n.now), 0); ok {
		t.Error("relay kept dead path 0")
	}
}

func TestNATRebinding(t *testing.T) {
	n := newNetwork(t, 33, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	n.rebind(0, "192.0.2.10:41000")

	var seq uint32
	for range 100 {
		seq++
		n.client.SendIP(n.now, ipPacket(lease, internet, 100, seq))
		s.SendIP(n.now, ipPacket(internet, lease, 100, seq))
		n.runFor(10 * time.Millisecond)
	}
	if n.relay.Stats().Migrations != 1 {
		t.Fatalf("migrations = %d", n.relay.Stats().Migrations)
	}
	if got := s.Addr(n.now); got != netip.MustParseAddrPort("192.0.2.10:41000") {
		t.Errorf("relay downlink address = %v", got)
	}
	// Downlink sent before validation went to the old mapping and was lost;
	// everything after it arrives.
	if n.misrouted == 0 {
		t.Error("expected some downlink to the old mapping before validation")
	}
	if got := len(n.clientIPs()); got < 90 {
		t.Errorf("client received %d/100 packets", got)
	}
}

func TestSpoofedAddressCannotHijackPath(t *testing.T) {
	n := newNetwork(t, 34, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	attacker := netip.MustParseAddrPort("203.0.113.66:666")
	n.pastAddrs[attacker] = true

	// An on-path attacker races copies of the client's packets from its own
	// address, so its copy arrives first.
	injected := 0
	n.tap = func(toRelay bool, d []byte) {
		if toRelay && d[0] == byte(wire.TypeData) {
			injected += len(d)
			n.relay.HandlePacket(n.now, attacker, d)
		}
	}
	for i := range uint32(50) {
		n.client.SendIP(n.now, ipPacket(lease, internet, 100, i))
		s.SendIP(n.now, ipPacket(internet, lease, 100, i))
		n.runFor(20 * time.Millisecond)
	}
	if n.relay.Stats().Migrations != 0 || s.Addr(n.now) != n.clientAddr {
		t.Fatalf("path moved to %v", s.Addr(n.now))
	}
	if sent := n.bytesTo[attacker]; sent > amplificationFactor*injected {
		t.Errorf("sent %d bytes to the attacker for %d received", sent, injected)
	}
	if got := len(n.clientIPs()); got != 50 {
		t.Errorf("client received %d/50 packets", got)
	}
}

func TestMTUProbe(t *testing.T) {
	n := newNetwork(t, 35, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	n.runFor(time.Second)
	want := 1280 + dataOverhead
	for _, side := range [][]PathInfo{n.client.Paths(n.now), s.Paths(n.now)} {
		if p, _ := pathByID(side, 0); p.MaxPacket != want {
			t.Errorf("max packet = %d, want %d", p.MaxPacket, want)
		}
	}
	var sizes []int
	n.tap = func(_ bool, d []byte) { sizes = append(sizes, len(d)) }
	n.client.SendIP(n.now, ipPacket(lease, internet, 1280, 1))
	s.SendIP(n.now, ipPacket(internet, lease, 1280, 2))
	n.runFor(time.Second)
	if len(n.relayIPs()) != 1 || len(n.clientIPs()) != 1 {
		t.Fatal("full-size packets not delivered")
	}
	full := 0
	for _, sz := range sizes {
		if sz == want {
			full++
		}
	}
	if full != 2 {
		t.Errorf("sizes %v: want two unfragmented %d-byte datagrams", sizes, want)
	}
}

func TestLostMTUProbeKeepsPathHealthy(t *testing.T) {
	n := newNetwork(t, 36, defaultRelayConfig(), ClientConfig{})
	n.up.mtu, n.down.mtu = DefaultMaxPacketSize, DefaultMaxPacketSize
	n.establish()
	n.runFor(30 * time.Second)
	p, _ := pathByID(n.client.Paths(n.now), 0)
	if p.MaxPacket != DefaultMaxPacketSize || !p.Healthy {
		t.Errorf("path 0 = %+v", p)
	}
	if n.client.Stats().PacketsLost != 0 {
		t.Errorf("lost probe counted as loss: %d", n.client.Stats().PacketsLost)
	}
}

func TestOutageRecoveredOnNewPath(t *testing.T) {
	n := newNetwork(t, 37, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	n.runFor(time.Second)
	// Total outage: the only path dies. The session survives while within
	// the idle timeout, and a new carrier rejoins without a handshake.
	n.up.down, n.down.down = true, true
	n.runFor(20 * time.Second)
	if n.client.State() != StateActive {
		t.Fatal("session ended during the outage")
	}
	id, _ := n.openPath("198.51.100.30:6000", 15*time.Millisecond)
	n.runUntil(2*time.Second, func() bool {
		return n.clientEventsOf(func(e ClientEvent) bool { _, ok := e.(PathValidated); return ok }) == 1
	})
	// The relay validates one round trip after the client does.
	n.runUntil(time.Second, func() bool { p, _ := pathByID(s.Paths(n.now), id); return p.Validated })
	n.client.SendIP(n.now, ipPacket(lease, internet, 100, 1))
	s.SendIP(n.now, ipPacket(internet, lease, 100, 2))
	n.runFor(time.Second)
	if len(n.relayIPs()) != 1 || len(n.clientIPs()) != 1 {
		t.Fatalf("after rejoining on path %d: %d up, %d down", id, len(n.relayIPs()), len(n.clientIPs()))
	}
	if n.relay.Stats().Handshakes != 1 {
		t.Error("recovery cost a handshake")
	}
}

func TestClosePath(t *testing.T) {
	n, s, id, _ := establishTwoPaths(t, 38, 20*time.Millisecond)
	n.client.ClosePath(n.now, id)
	n.runFor(time.Second)
	if _, ok := pathByID(s.Paths(n.now), id); ok {
		t.Error("relay kept the abandoned path")
	}
	if _, ok := pathByID(n.client.Paths(n.now), id); ok {
		t.Error("client kept the abandoned path")
	}
	n.client.ClosePath(n.now, 0) // the last path cannot be closed
	if _, ok := pathByID(n.client.Paths(n.now), 0); !ok {
		t.Error("last path was closed")
	}
}

func TestJoinWithDifferentCIDIsRejected(t *testing.T) {
	n, s, id, _ := establishTwoPaths(t, 39, 20*time.Millisecond)
	cp := n.client.conn.path(id)
	cp.control = append(cp.control, wire.PathJoin{CID: wire.CID{0xEE}})
	n.client.conn.flush(n.now)
	n.runFor(time.Second)
	if _, ok := pathByID(s.Paths(n.now), id); ok {
		t.Error("relay kept a path after a conflicting PATH_JOIN")
	}
}
