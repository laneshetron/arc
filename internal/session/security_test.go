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

func TestPathHistoryIsBoundedAndNeverReused(t *testing.T) {
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
	for id := uint32(1000); len(c.usedPathIDs) < maxSessionPathIDs; id++ {
		c.usedPathIDs[id] = true
	}
	if _, err := n.client.OpenPath(n.now); err != ErrPathLimit || n.client.State() != StateClosed {
		t.Fatalf("path budget: %v, %v", err, n.client.State())
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
		if got := a.allow(now, ip, 10, 2); got != (i < 10) {
			t.Fatalf("global admission %d = %v", i, got)
		}
	}
	if len(a.sources) > 10 {
		t.Fatal("denied global requests allocated source state")
	}
	a = handshakeAdmission{}
	for i := range maxHandshakeSources + 100 {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		a.allow(now, ip, maxHandshakeSources+100, 1)
	}
	if len(a.sources) != maxHandshakeSources {
		t.Fatalf("source entries = %d", len(a.sources))
	}
	if !a.allow(now.Add(2*time.Minute), netip.MustParseAddr("203.0.113.1"), maxHandshakeSources+100, 1) {
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
}

func TestRelayReconnectsWhenPathHistoryIsExhausted(t *testing.T) {
	n := newNetwork(t, 305, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	for id := uint32(1000); len(s.conn.usedPathIDs) < maxSessionPathIDs; id++ {
		s.conn.usedPathIDs[id] = true
	}
	p := s.conn.path(1)
	if s.onJoin(n.now, p, wire.PathJoin{CID: wire.CID{77}}) {
		t.Fatal("relay kept session after exhausting path nonce-space history")
	}
	if s.State() != StateClosed || n.relay.Sessions() != 0 {
		t.Fatal("exhausted session was not released")
	}
}
