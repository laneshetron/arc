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
	n.runFor(DefaultPathTimeout + 5*time.Second)
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
	// Probes are sent for a full TUN packet in IP_PACKET and, since the
	// relay supports redundancy, in IP_DATAGRAM; a link that carries only
	// the first leaves paths at that size.
	n := newNetwork(t, 35, defaultRelayConfig(), ClientConfig{})
	want := 1280 + dataOverhead
	n.up.mtu, n.down.mtu = want, want
	s := n.establish()
	n.runFor(time.Second)
	for _, side := range [][]PathInfo{n.client.Paths(n.now), s.Paths(n.now)} {
		if p, _ := pathByID(side, 0); p.MaxPacket != want {
			t.Errorf("max packet = %d, want %d", p.MaxPacket, want)
		}
	}
	n.up.mtu, n.down.mtu = 0, 0
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

// A standby path that recovers from an outage must be noticed quickly, so
// that a later failure of the primary can fail over to it. Suspect paths
// are probed every PTO rather than every keepalive interval (§14.1).
func TestRecoveredStandbyPathIsUsableQuickly(t *testing.T) {
	n, s, id, c1 := establishTwoPaths(t, 40, 20*time.Millisecond)
	if p, _ := pathByID(n.client.Paths(n.now), 0); !p.Primary {
		t.Fatal("path 0 should be primary")
	}
	// The standby path goes dark long enough to turn suspect, then recovers.
	c1.up.down, c1.down.down = true, true
	n.runFor(15 * time.Second)
	if p, _ := pathByID(n.client.Paths(n.now), id); p.Healthy {
		t.Fatal("standby path should be suspect while dark")
	}
	c1.up.down, c1.down.down = false, false
	n.runFor(time.Second)
	if p, _ := pathByID(n.client.Paths(n.now), id); !p.Healthy {
		t.Fatal("standby path still suspect 1 s after recovering")
	}

	// Now the primary dies: traffic must move to the recovered standby.
	n.up.down, n.down.down = true, true
	before := len(n.relayIPs())
	failedAt := n.now
	for seq := uint32(1); n.now.Sub(failedAt) < 3*time.Second; seq++ {
		n.client.SendIP(n.now, ipPacket(lease, internet, 100, seq))
		s.SendIP(n.now, ipPacket(internet, lease, 100, seq))
		n.runFor(10 * time.Millisecond)
		if len(n.relayIPs()) > before {
			break
		}
	}
	if d := n.now.Sub(failedAt); len(n.relayIPs()) == before || d > time.Second {
		t.Fatalf("failover to the recovered standby took %v", d)
	}
}

// TestSharedOutageKeepsPaths: when every path is silent at once, neither
// side abandons any of them, so traffic resumes on the existing paths as
// soon as packets get through again. Abandoning them would leave rejoins,
// which take several round trips, to the same bad network.
func TestSharedOutageKeepsPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		loss float64
		down bool
	}{{"90% loss", 0.9, false}, {"blackout", 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			n, s, id, c := establishTwoPaths(t, 90, 20*time.Millisecond)
			for _, l := range []*link{n.up, n.down, c.up, c.down} {
				l.loss, l.down = tc.loss, tc.down
			}
			var seq uint32
			for range 6000 { // 60 s of light traffic
				seq++
				n.client.SendIP(n.now, ipPacket(lease, internet, 200, seq))
				s.SendIP(n.now, ipPacket(internet, lease, 200, seq))
				n.runFor(10 * time.Millisecond)
			}
			for _, l := range []*link{n.up, n.down, c.up, c.down} {
				l.loss, l.down = 0, false
			}
			if k := n.clientEventsOf(func(e ClientEvent) bool { _, ok := e.(PathClosed); return ok }); k != 0 {
				t.Fatalf("client closed %d paths during the outage", k)
			}
			if got := len(s.Paths(n.now)); got != 2 {
				t.Fatalf("relay has %d paths after the outage, want 2", got)
			}
			upBefore, downBefore, cleared := len(n.relayIPs()), len(n.clientIPs()), n.now
			for len(n.relayIPs()) == upBefore || len(n.clientIPs()) == downBefore {
				if n.now.Sub(cleared) > 2*time.Second {
					t.Fatal("no traffic within 2 s of the outage ending")
				}
				seq++
				n.client.SendIP(n.now, ipPacket(lease, internet, 200, seq))
				s.SendIP(n.now, ipPacket(internet, lease, 200, seq))
				n.runFor(10 * time.Millisecond)
			}
			t.Logf("traffic both ways %v after the outage; paths %d and %d kept", n.now.Sub(cleared), 0, id)
		})
	}
}

// TestRetiredPathDoesNotResetSession: when the relay abandons a path and
// the client has not yet heard (its PATH_ABANDON lost, as it may be under
// heavy loss), the client's packets on that path must not draw a
// stateless reset, which would end the whole session.
func TestRetiredPathDoesNotResetSession(t *testing.T) {
	n, s, id, _ := establishTwoPaths(t, 91, 20*time.Millisecond)
	p := s.conn.path(id)
	s.removePath(p) // as on the relay, minus the PATH_ABANDON reaching the client
	var seq uint32
	for range 300 {
		seq++
		n.client.SendIP(n.now, ipPacket(lease, internet, 200, seq))
		n.runFor(100 * time.Millisecond)
	}
	if n.client.State() != StateActive {
		t.Fatalf("session ended: %v", n.clientClosed())
	}
	if n.relay.Stats().ResetsSent != 0 {
		t.Errorf("relay sent %d stateless resets for a retired path", n.relay.Stats().ResetsSent)
	}
}

func TestRelayAbandonTellsClient(t *testing.T) {
	// Path 1 goes silent toward the relay; the relay abandons it and says
	// so, and the client, whose own timeout is longer, closes it on that.
	n, s, c := lossyPaths(t, 92, ClientConfig{PathTimeout: time.Minute}, defaultRelayConfig(), 0)
	const id = 1
	c.up.down = true
	var seq uint32
	for range 400 { // 40 s
		seq++
		n.client.SendIP(n.now, ipPacket(lease, internet, 200, seq))
		n.runFor(100 * time.Millisecond)
	}
	if _, ok := pathByID(s.Paths(n.now), id); ok {
		t.Fatal("relay kept the silent path")
	}
	closed := n.clientEventsOf(func(e ClientEvent) bool {
		pc, ok := e.(PathClosed)
		return ok && pc.ID == id && errors.Is(pc.Err, ErrPathAbandoned)
	})
	if closed != 1 {
		t.Errorf("client did not close path %d on the relay's PATH_ABANDON; events %v", id, n.clientEvents)
	}
}

func TestIdlePathToleratesLateKeepalive(t *testing.T) {
	// A standby path hears from the peer about once per keepalive. A
	// keepalive 200 ms late on a busy host must not make it unhealthy,
	// which a margin of only a few PTOs (here about 80 ms) did.
	now := time.Unix(1_000_000, 0)
	p := newPath(1, wire.CID{}, wire.CID{}, now)
	p.validated = true
	p.rtt.update(now, time.Millisecond, 0)
	if !p.healthy(now.Add(DefaultKeepalive+200*time.Millisecond), DefaultKeepalive) {
		t.Error("idle path unhealthy 200 ms after a keepalive was due")
	}
	if p.healthy(now.Add(DefaultKeepalive*3/2+time.Millisecond), DefaultKeepalive) {
		t.Error("idle path still healthy after 1.5 keepalive intervals of silence")
	}
}

// TestRecoveryAfterOutageIsPrompt: pings lost in an outage used to stay
// outstanding until three later packets were acknowledged; on an idle path
// that probes only while suspect, that kept it flapping between healthy and
// suspect for seconds after it recovered, so new flows avoided it. The
// time threshold declares them lost at the first acknowledgement.
func TestRecoveryAfterOutageIsPrompt(t *testing.T) {
	n, s, c := rateLimitedPaths(t, 131, 1_000_000, 1_000_000, ClientConfig{})
	c.up.queue, c.down.queue = 200*time.Millisecond, 200*time.Millisecond
	n.client.SetFallback(0, true)                      // put the load on path 1 first
	flowLoad(n, s, 4, time.Millisecond, 3*time.Second) // a standing queue inflates its RTT
	n.client.SetFallback(0, false)
	flowLoad(n, s, 4, 10*time.Millisecond, 2*time.Second)
	c.up.down, c.down.down = true, true
	flowLoad(n, s, 1, 10*time.Millisecond, 15*time.Second)
	c.up.down, c.down.down = false, false
	start, stableFrom := n.now, time.Duration(-1)
	for n.now.Sub(start) < 5*time.Second {
		n.runFor(20 * time.Millisecond)
		healthy := n.client.conn.path(1).healthy(n.now, n.client.conn.keepalive)
		switch {
		case !healthy:
			stableFrom = -1
		case stableFrom < 0:
			stableFrom = n.now.Sub(start)
		}
	}
	t.Logf("path 1 healthy for good %v after the outage ended (srtt %v)", stableFrom, n.client.conn.path(1).rtt.srtt())
	if stableFrom < 0 || stableFrom > time.Second {
		t.Errorf("path 1 healthy for good only after %v", stableFrom)
	}
}

// TestRelayRecoveryAfterOutageIsPrompt: packets the relay sent on a path
// during an outage stayed outstanding afterwards, since the relay sends
// nothing acknowledged on an idle path, so it judged the path suspect
// except just after each of the client's keepalives and kept new downlink
// flows off it. A relay that hears from such a path now pings it.
func TestRelayRecoveryAfterOutageIsPrompt(t *testing.T) {
	n, s, c := rateLimitedPaths(t, 132, 1_000_000, 1_000_000, ClientConfig{})
	c.up.queue, c.down.queue = 200*time.Millisecond, 200*time.Millisecond
	n.client.SetFallback(0, true)                      // the relay's downlink follows the uplink to path 1
	flowLoad(n, s, 4, time.Millisecond, 3*time.Second) // a standing queue inflates its RTT
	c.up.down, c.down.down = true, true                // cut while the relay still sends there
	n.client.SetFallback(0, false)
	flowLoad(n, s, 1, 10*time.Millisecond, 15*time.Second)
	c.up.down, c.down.down = false, false
	start, stableFrom := n.now, time.Duration(-1)
	for n.now.Sub(start) < 15*time.Second {
		n.runFor(20 * time.Millisecond)
		healthy := s.conn.path(1).healthy(n.now, s.conn.keepalive)
		switch {
		case !healthy:
			stableFrom = -1
		case stableFrom < 0:
			stableFrom = n.now.Sub(start)
		}
	}
	t.Logf("relay: path 1 healthy for good %v after the outage ended (srtt %v)", stableFrom, s.conn.path(1).rtt.srtt())
	if stableFrom < 0 || stableFrom > 2*time.Second {
		t.Errorf("relay: path 1 healthy for good only after %v", stableFrom)
	}
}

func TestCapacityForgottenAfterOutage(t *testing.T) {
	// Flows run on path 1 until it goes dark for 12 s, longer than the
	// capacity estimate's window. Coming back, it must count as unmeasured:
	// keeping its old rate made it look measured and slow next to the busy
	// path, and new flows avoided it (degraded.sh's 4-flow downlink).
	n, _, id, c := establishTwoPaths(t, 80, 10*time.Millisecond)
	for i := range 5000 {
		n.client.SendIP(n.now, flowPacket(lease, internet, uint16(40000+i%4), 4000, 1200, uint32(i)))
		n.runFor(500 * time.Microsecond)
	}
	c.up.down, c.down.down = true, true
	n.runFor(12 * time.Second)
	c.up.down, c.down.down = false, false
	for range 12 {
		n.runFor(250 * time.Millisecond)
		if p, _ := pathByID(n.client.Paths(n.now), id); p.Capacity >= measuredRate {
			t.Fatalf("path %d measured at %.2f Mbit/s right after an outage", id, p.Capacity*8/1e6)
		}
	}
}
