package session

import (
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

func TestNewPathRetransmissionCannotReuseNonce(t *testing.T) {
	n := newNetwork(t, 301, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	slot := n.client.slots[0]
	announce := func() {
		s.conn.transmit(n.now, s.conn.path(0), []wire.Frame{wire.NewPath{PathID: slot.id, CID: slot.cid, ResetToken: slot.token}})
		for d, ok := n.relay.PollTransmit(); ok; d, ok = n.relay.PollTransmit() {
			n.client.HandlePacket(n.now, 0, d.Data)
		}
	}
	announce()
	announce()
	if len(n.client.slots) != 2 {
		t.Fatalf("duplicate announcements left %d slots, want 2", len(n.client.slots))
	}
	seen := map[[3]uint64]bool{}
	for len(n.client.slots) > 0 {
		id, err := n.client.OpenPath(n.now)
		if err != nil {
			t.Fatal(err)
		}
		for d, ok := n.client.PollTransmit(); ok; d, ok = n.client.PollTransmit() {
			h, _, _, err := wire.ParseData(d.Data)
			if err != nil {
				continue
			}
			k := [3]uint64{uint64(h.EpochLow), uint64(d.PathID), h.PacketNumber}
			if seen[k] {
				t.Fatalf("reused nonce tuple %v", k)
			}
			seen[k] = true
		}
		if id == slot.id {
			n.client.ClosePath(n.now, id)
			announce()
		}
	}
	if len(seen) == 0 {
		t.Fatal("no encryption events observed")
	}
	announce()
	if len(n.client.slots) != 0 {
		t.Fatal("retired path ID was offered again")
	}
	// Even an internal stale queue cannot recreate a retired nonce space.
	n.client.slots = append(n.client.slots, slot)
	if _, err := n.client.OpenPath(n.now); err != ErrNoPathSlots {
		t.Fatalf("stale slot: %v", err)
	}
}

func TestPathIDsNeverReusedWithoutHistory(t *testing.T) {
	n := newNetwork(t, 303, defaultRelayConfig(), ClientConfig{})
	n.establish()
	c := n.client.conn
	p := newPath(100, wire.CID{100}, wire.CID{101}, n.now)
	if !c.addPath(p) {
		t.Fatal("new path rejected")
	}
	c.removePath(p)
	if c.addPath(newPath(100, wire.CID{102}, wire.CID{103}, n.now)) {
		t.Fatal("retired nonce space recreated")
	}
	if c.addPath(newPath(50, wire.CID{104}, wire.CID{105}, n.now)) {
		t.Fatal("lower path ID accepted")
	}
	// Paths can come and go indefinitely: no history accumulates.
	for id := uint32(101); id < 101+20000; id++ {
		q := newPath(id, wire.CID{byte(id), byte(id >> 8), 1}, wire.CID{2}, n.now)
		if !c.addPath(q) {
			t.Fatalf("path %d rejected", id)
		}
		c.removePath(q)
	}
}

func TestInvalidInitWorkIsRateLimited(t *testing.T) {
	n := newNetwork(t, 302, defaultRelayConfig(), ClientConfig{})
	d, _ := n.client.PollTransmit()
	d.Data[len(d.Data)-1] ^= 1
	for range 100 {
		n.relay.HandlePacket(n.now, n.clientAddr, d.Data)
	}
	if got := n.relay.Stats().HandshakeFailures; got != uint64(n.relay.cfg.HandshakesPerSource) {
		t.Fatalf("per-source work = %d", got)
	}
	if got := n.relay.Stats().InitsRefusedLimited; got != uint64(100-n.relay.cfg.HandshakesPerSource) {
		t.Fatalf("rate-limited INITs counted %d", got)
	}
	n.relay.HandlePacket(n.now.Add(time.Second), n.clientAddr, d.Data)
	if got := n.relay.Stats().HandshakeFailures; got != uint64(n.relay.cfg.HandshakesPerSource+1) {
		t.Fatalf("refill: %d", got)
	}
}

func TestHandshakeAdmissionGlobalLimitAndBoundedSources(t *testing.T) {
	var a handshakeAdmission
	now := time.Unix(1000, 0)
	for i := range 1000 {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		if got := a.allow(now, ip, 10, 2, false); got != (i < 10) {
			t.Fatalf("global admission %d = %v", i, got)
		}
	}
	if len(a.sources) > 10 {
		t.Fatal("denied global requests allocated source state")
	}
	a = handshakeAdmission{}
	for i := range maxHandshakeSources + 100 {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		a.allow(now, ip, maxHandshakeSources+100, 1, false)
	}
	if len(a.sources) != maxHandshakeSources {
		t.Fatalf("source entries = %d", len(a.sources))
	}
	if !a.allow(now.Add(2*time.Minute), netip.MustParseAddr("203.0.113.1"), maxHandshakeSources+100, 1, false) {
		t.Fatal("stale source entries did not expire")
	}
}

func TestRelayTotalSessionLimit(t *testing.T) {
	cfg := defaultRelayConfig()
	cfg.MaxSessions = 1
	n := newNetwork(t, 304, cfg, ClientConfig{})
	n.establish()
	c := n.newClient(ClientConfig{})
	d, _ := c.PollTransmit()
	n.relay.HandlePacket(n.now, n.clientAddr, d.Data)
	if n.relay.Sessions() != 1 {
		t.Fatal("active session did not count toward total limit")
	}
	if got := n.relay.Stats().InitsRefusedFull; got != 1 {
		t.Fatalf("refused INITs counted %d", got)
	}
}

func TestRelayReconnectsWhenPathIDsAreExhausted(t *testing.T) {
	n := newNetwork(t, 305, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	s.conn.highestPathID = ^uint32(0) // the next slot's ID would wrap
	p := s.conn.path(1)
	if s.onJoin(n.now, p, wire.PathJoin{CID: wire.CID{77}}) {
		t.Fatal("relay kept session after exhausting path IDs")
	}
	if s.State() != StateClosed || n.relay.Sessions() != 0 {
		t.Fatal("exhausted session was not released")
	}
}

func TestFullSourceTableChallengesAndAdmitsReachableNewcomer(t *testing.T) {
	n := newNetwork(t, 306, defaultRelayConfig(), ClientConfig{})
	r := n.relay
	r.admission.sources = make(map[netip.Addr]*handshakeBucket)
	for i := range maxHandshakeSources {
		r.admission.sources[netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})] = &handshakeBucket{tokens: 0, at: n.now}
	}
	d, _ := n.client.PollTransmit()
	r.HandlePacket(n.now, n.clientAddr, d.Data)
	reply, ok := r.PollTransmit()
	if !ok || reply.Data[0] != byte(wire.TypeCookieReply) || r.Stats().Handshakes != 0 {
		t.Fatal("unknown source was not challenged before DH")
	}
	n.client.HandlePacket(n.now, 0, reply.Data)
	retried, _ := n.client.PollTransmit()
	r.HandlePacket(n.now, n.clientAddr, retried.Data)
	if r.pending != 1 || r.Stats().Handshakes != 1 || len(r.admission.sources) > maxHandshakeSources {
		t.Fatal("cookie-valid newcomer was locked out or exceeded source budget")
	}
}

func TestFullyRefilledSourceBucketsExpireAfterOneSecond(t *testing.T) {
	now := time.Unix(1000, 0)
	a := handshakeAdmission{}
	for i := range maxHandshakeSources {
		a.allow(now, netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 10000, 8, false)
	}
	if !a.allow(now.Add(time.Second), netip.MustParseAddr("203.0.113.1"), 10000, 8, false) || len(a.sources) != 1 {
		t.Fatalf("refilled buckets retained: %d", len(a.sources))
	}
}

func TestPendingBudgetReplacementLeavesActiveCapacityAvailable(t *testing.T) {
	cfg := defaultRelayConfig()
	cfg.MaxSessions = 1
	cfg.MaxPending = 1
	n := newNetwork(t, 307, cfg, ClientConfig{})
	init, _ := n.client.PollTransmit()
	n.relay.HandlePacket(n.now, n.clientAddr, init.Data)
	n.relay.PollTransmit() // old unauthenticated handshake's response
	old := n.relay.live[0]
	c := n.newClient(ClientConfig{})
	d, _ := c.PollTransmit()
	n.relay.HandlePacket(n.now, n.clientAddr, d.Data)
	cookie, _ := n.relay.PollTransmit()
	c.HandlePacket(n.now, 0, cookie.Data)
	d, _ = c.PollTransmit()
	n.relay.HandlePacket(n.now, n.clientAddr, d.Data)
	resp, _ := n.relay.PollTransmit()
	c.HandlePacket(n.now, 0, resp.Data)
	auth, _ := c.PollTransmit()
	n.relay.HandlePacket(n.now, n.clientAddr, auth.Data)
	if old.State() != StateClosed || n.relay.pending != 0 || len(n.relay.live) != 1 || n.relay.live[0].State() != StateActive {
		t.Fatal("pending handshakes blocked authenticated capacity")
	}
}

func TestAuthChecksActiveCapacityBeforeLeasing(t *testing.T) {
	calls := 0
	cfg := defaultRelayConfig()
	cfg.MaxSessions = 1
	cfg.Authorize = func(c, k []byte, prior *wire.AuthResult) (Authorization, error) {
		calls++
		return testAuthorizer(c, k, prior)
	}
	n := newNetwork(t, 308, cfg, ClientConfig{})
	first, _ := n.client.PollTransmit()
	n.relay.HandlePacket(n.now, n.clientAddr, first.Data)
	c := n.newClient(ClientConfig{})
	second, _ := c.PollTransmit()
	n.relay.HandlePacket(n.now, n.clientAddr, second.Data)
	s1, s2 := n.relay.live[0], n.relay.live[1]
	if !s1.onAuth(n.now, []byte("good")) {
		t.Fatal("first authorization failed")
	}
	if s2.onAuth(n.now, []byte("good")) || calls != 1 || s2.State() != StateClosed {
		t.Fatal("capacity race allocated another lease")
	}
}

func TestCapacityResultRemainsRetryable(t *testing.T) {
	n := newNetwork(t, 309, defaultRelayConfig(), ClientConfig{})
	n.client.state = StateAuthenticating
	n.client.onAuthResult(n.now, wire.AuthResult{Status: uint8(wire.CodeCapacity)})
	if n.client.err != ErrCapacity || n.client.State() != StateClosed {
		t.Fatal("capacity rejection became a permanent auth failure")
	}
}

func TestReorderedNewPathKeepsBothSlots(t *testing.T) {
	// A NEW_PATH retransmitted after a later one still gives a slot, and
	// slots open lowest first.
	n := newNetwork(t, 307, defaultRelayConfig(), ClientConfig{})
	n.establish()
	c := n.client
	if len(c.slots) != 2 {
		t.Fatalf("%d slots", len(c.slots))
	}
	a, b := c.slots[0], c.slots[1]
	c.slots = nil
	for _, sl := range []pathSlot{b, a, b} { // later first, then a duplicate
		c.conn.transmit(n.now, c.conn.path(0), nil) // keep the harness moving
		s := n.relaySession()
		s.conn.transmit(n.now, s.conn.path(0), []wire.Frame{wire.NewPath{PathID: sl.id, CID: sl.cid, ResetToken: sl.token}})
		for d, ok := n.relay.PollTransmit(); ok; d, ok = n.relay.PollTransmit() {
			c.HandlePacket(n.now, 0, d.Data)
		}
	}
	if len(c.slots) != 2 || c.slots[0].id != a.id || c.slots[1].id != b.id {
		t.Fatalf("slots %+v, want %d then %d", c.slots, a.id, b.id)
	}
}

func TestRelayReplacesSlotsTheClientNeverGot(t *testing.T) {
	// The client never received the first slot (its NEW_PATH was lost
	// for good, or arrived after the client opened a later one) and
	// joins the second: the relay stops counting the first as a spare,
	// keeps two spares outstanding, and retires it after the path timeout.
	n := newNetwork(t, 308, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	n.runFor(200 * time.Millisecond)
	lost := n.client.slots[0].id
	n.client.slots = n.client.slots[1:]
	id, _ := n.openPath("198.51.100.20:5000", 10*time.Millisecond)
	if !n.runUntil(2*time.Second, func() bool {
		return n.clientEventsOf(func(e ClientEvent) bool { v, ok := e.(PathValidated); return ok && v.ID == id }) == 1
	}) {
		t.Fatal("path not validated")
	}
	n.runFor(500 * time.Millisecond)
	spare := 0
	for _, p := range s.conn.paths {
		if !p.joined && p.skippedAt.IsZero() {
			spare++
		}
	}
	if spare != spareSlots || len(n.client.slots) != spareSlots {
		t.Fatalf("relay holds %d spare slots and the client %d, want %d", spare, len(n.client.slots), spareSlots)
	}
	n.runFor(DefaultPathTimeout)
	for _, p := range s.conn.paths {
		if p.id == lost {
			t.Fatalf("slot %d the client never got is still held after the path timeout", lost)
		}
	}
}

func TestReorderedJoinsKeepBothPaths(t *testing.T) {
	// JOINs travel over independent carriers: the second path's JOIN can
	// arrive first. The relay must not retire the first path's slot while
	// its JOIN is still in flight.
	n := newNetwork(t, 309, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	n.runFor(200 * time.Millisecond)
	slow, _ := n.openPath("198.51.100.30:5000", 200*time.Millisecond)
	fast, _ := n.openPath("198.51.100.31:5000", time.Millisecond)
	n.runFor(3 * time.Second)
	for _, id := range []uint32{slow, fast} {
		if n.clientEventsOf(func(e ClientEvent) bool { v, ok := e.(PathValidated); return ok && v.ID == id }) != 1 {
			t.Errorf("path %d not validated", id)
		}
	}
	spare := 0
	for _, p := range s.conn.paths {
		if !p.joined && p.skippedAt.IsZero() {
			spare++
		}
	}
	if spare != spareSlots {
		t.Errorf("relay holds %d spare slots, want %d", spare, spareSlots)
	}
}

func TestSkippedSlotsRefillAfterExpiry(t *testing.T) {
	// Skipped slots fill maxPaths, and the client uses its last slot.
	// When they expire, the relay must issue new spares: the client has
	// no slot left to send the JOIN that would otherwise refill them.
	n := newNetwork(t, 902, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	n.runFor(200 * time.Millisecond)
	for range 3 {
		if len(n.client.slots) < 2 {
			t.Fatalf("need two slots, got %d", len(n.client.slots))
		}
		n.client.slots = n.client.slots[1:] // the first NEW_PATH never reached the client
		n.openPath("198.51.100.20:5000", time.Millisecond)
		n.runFor(500 * time.Millisecond)
	}
	n.openPath("198.51.100.21:5000", time.Millisecond)
	n.runFor(500 * time.Millisecond)
	n.runFor(DefaultPathTimeout + time.Second)
	if s.State() != StateActive || len(n.client.slots) != spareSlots {
		t.Fatalf("session %v with %d client slots after expiry, want active with %d", s.State(), len(n.client.slots), spareSlots)
	}
}

// A refresh hands the Authorizer the session's configuration, so it can
// hold the credential to the principal the session was leased to, and its
// rejection ends the session.
func TestRefreshSeesTheSessionsLease(t *testing.T) {
	cfg := defaultRelayConfig()
	var priors []*wire.AuthResult
	cfg.Authorize = func(c, k []byte, prior *wire.AuthResult) (Authorization, error) {
		priors = append(priors, prior)
		if prior != nil && string(c) != "good" {
			return Authorization{Result: wire.AuthResult{Status: uint8(wire.CodeAuthFailed)}}, nil // another principal's
		}
		return testAuthorizer(c, k, prior)
	}
	n := newNetwork(t, 310, cfg, ClientConfig{})
	s := n.establish()
	if len(priors) != 1 || priors[0] != nil {
		t.Fatalf("first authentication saw prior %v", priors)
	}
	if s.onAuth(n.now, []byte("other")) || s.State() != StateClosed {
		t.Fatal("refresh with another principal's credential kept the session")
	}
	if len(priors) != 2 || priors[1] == nil || priors[1].IPv4 != lease {
		t.Fatalf("refresh saw prior %+v, want the session's lease", priors[1:])
	}
}

// Diagnostics uploads are negotiated apart from connecting streams: a
// relay may accept one without the other, and the client opens only what
// the relay advertised (§11.4).
func TestDiagnosticsNegotiation(t *testing.T) {
	cfg := defaultRelayConfig()
	cfg.NoStreams, cfg.Diagnostics = true, true
	n := newNetwork(t, 311, cfg, ClientConfig{})
	n.establish()
	if n.client.StreamsSupported() || !n.client.DiagnosticsSupported() {
		t.Fatal("negotiated streams without diagnostics")
	}
	if _, err := n.client.OpenStream(n.now, netip.MustParseAddrPort("198.51.100.7:443")); err != ErrStreamsUnsupported {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := n.client.OpenDiagnostics(n.now); err != nil {
		t.Fatalf("OpenDiagnostics: %v", err)
	}

	n = newNetwork(t, 312, defaultRelayConfig(), ClientConfig{})
	n.establish()
	if !n.client.StreamsSupported() || n.client.DiagnosticsSupported() {
		t.Fatal("a relay without diagnostics advertised them")
	}
	if _, err := n.client.OpenDiagnostics(n.now); err != ErrDiagnosticsUnsupported {
		t.Fatalf("OpenDiagnostics: %v", err)
	}
}
