package session

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

func TestEstablishAndExchange(t *testing.T) {
	n := newNetwork(t, 1, defaultRelayConfig(), ClientConfig{})
	s := n.establish()

	est := n.clientEvents[0].(Established)
	if est.Config.IPv4 != lease || est.Config.TunMTU != 1280 {
		t.Errorf("client config = %+v", est.Config)
	}
	if !bytes.Equal(s.ClientStatic(), clientKey.Public) {
		t.Error("relay saw the wrong client static key")
	}

	up := ipPacket(lease, internet, 100, 1)
	down := ipPacket(internet, lease, 200, 2)
	if err := n.client.SendIP(n.now, up); err != nil {
		t.Fatal(err)
	}
	if err := s.SendIP(n.now, down); err != nil {
		t.Fatal(err)
	}
	n.runFor(time.Second)
	if got := n.relayIPs(); len(got) != 1 || !bytes.Equal(got[0], up) {
		t.Errorf("relay received %d packets", len(got))
	}
	if got := n.clientIPs(); len(got) != 1 || !bytes.Equal(got[0], down) {
		t.Errorf("client received %d packets", len(got))
	}
	if st := n.relay.Stats(); st.Handshakes != 1 || st.CookiesSent != 0 {
		t.Errorf("relay stats = %+v", st)
	}
}

func TestFullSizePacketsAreFragmented(t *testing.T) {
	n := newNetwork(t, 2, defaultRelayConfig(), ClientConfig{})
	// An unprobeable link: the MTU probe is dropped, so packets stay fragmented.
	n.up.mtu, n.down.mtu = DefaultMaxPacketSize, DefaultMaxPacketSize
	s := n.establish()
	n.runFor(5 * time.Second)
	var sizes []int
	n.tap = func(_ bool, d []byte) { sizes = append(sizes, len(d)) }

	for i := range uint32(5) {
		if err := n.client.SendIP(n.now, ipPacket(lease, internet, 1280, i)); err != nil {
			t.Fatal(err)
		}
		if err := s.SendIP(n.now, ipPacket(internet, lease, 1280, i)); err != nil {
			t.Fatal(err)
		}
	}
	n.runFor(time.Second)
	if len(n.relayIPs()) != 5 || len(n.clientIPs()) != 5 {
		t.Fatalf("delivered %d up, %d down", len(n.relayIPs()), len(n.clientIPs()))
	}
	for _, p := range n.relayIPs() {
		if !bytes.Equal(p, ipPacket(lease, internet, 1280, seqOf(p))) {
			t.Fatal("corrupted reassembly")
		}
	}
	for _, sz := range sizes {
		if sz > DefaultMaxPacketSize {
			t.Fatalf("sent a %d-byte datagram, above the %d path limit", sz, DefaultMaxPacketSize)
		}
	}
	if err := n.client.SendIP(n.now, ipPacket(lease, internet, 1281, 0)); !errors.Is(err, ErrPacketTooLarge) {
		t.Errorf("packet above tun_mtu: %v", err)
	}
}

func TestImpairedLink(t *testing.T) {
	for seed := range uint64(10) {
		n := newNetwork(t, 100+seed, defaultRelayConfig(), ClientConfig{})
		for _, l := range []*link{n.up, n.down} {
			l.loss, l.dup, l.delay, l.jitter = 0.2, 0.1, 30*time.Millisecond, 40*time.Millisecond
		}
		s := n.establish()

		const count = 300
		for i := range uint32(count) {
			size := 60 + int(i*37)%1220
			n.client.SendIP(n.now, ipPacket(lease, internet, size, i))
			s.SendIP(n.now, ipPacket(internet, lease, size, i))
			n.runFor(5 * time.Millisecond)
		}
		n.runFor(2 * time.Second)

		for name, got := range map[string][][]byte{"uplink": n.relayIPs(), "downlink": n.clientIPs()} {
			seen := map[uint32]bool{}
			for _, p := range got {
				if seen[seqOf(p)] {
					t.Fatalf("seed %d %s: packet %d delivered twice", seed, name, seqOf(p))
				}
				seen[seqOf(p)] = true
			}
			// Losses are expected (no IP retransmission); most must arrive.
			if len(got) < count/2 {
				t.Errorf("seed %d %s: only %d/%d delivered", seed, name, len(got), count)
			}
		}
		if st := n.client.Stats(); st.ReplaysDropped == 0 {
			t.Errorf("seed %d: duplicated link produced no replay drops", seed)
		}
	}
}

func TestWrongRelayKeyNeverEstablishes(t *testing.T) {
	n := newNetwork(t, 3, defaultRelayConfig(), ClientConfig{RelayPublic: mustKey(7).Public})
	if n.runUntil(25*time.Second, func() bool { return n.client.State() == StateActive }) {
		t.Fatal("client established with an unpinned relay")
	}
	if n.relay.Sessions() != 0 || n.relay.Stats().HandshakeFailures == 0 {
		t.Errorf("relay sessions %d, stats %+v", n.relay.Sessions(), n.relay.Stats())
	}
}

func TestAuthFailure(t *testing.T) {
	n := newNetwork(t, 4, defaultRelayConfig(), ClientConfig{Credential: []byte("bad")})
	n.runUntil(5*time.Second, func() bool { return n.client.State() == StateClosed })
	if err := n.clientClosed(); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("client closed with %v", err)
	}
	if n.relay.Sessions() != 0 {
		t.Error("relay kept a rejected session")
	}
}

func TestAuthResultLossIsRecovered(t *testing.T) {
	n := newNetwork(t, 5, defaultRelayConfig(), ClientConfig{})
	dropped := 0
	n.tap = func(toRelay bool, d []byte) {
		// Drop the relay's first two DATA packets (AUTH_RESULT and its first retransmission).
		if !toRelay && d[0] == byte(wire.TypeData) && dropped < 2 {
			dropped++
			n.down.down = true
		} else {
			n.down.down = false
		}
	}
	n.establish()
	if dropped != 2 {
		t.Errorf("dropped %d packets", dropped)
	}
}

func TestCookiesUnderLoad(t *testing.T) {
	rc := defaultRelayConfig()
	rc.AlwaysRequireCookie = true
	n := newNetwork(t, 6, rc, ClientConfig{})
	n.establish()
	if st := n.relay.Stats(); st.CookiesSent != 1 || st.Handshakes != 1 {
		t.Errorf("relay stats = %+v", st)
	}

	// Spoofed INITs without cookies never cost Diffie-Hellman.
	for i := range 50 {
		c := n.newClient(ClientConfig{})
		d, _ := c.PollTransmit()
		n.relay.HandlePacket(n.now, n.clientAddr, d.Data)
		_ = i
	}
	if st := n.relay.Stats(); st.Handshakes != 1 || st.CookiesSent != 51 {
		t.Errorf("after flood: %+v", st)
	}
}

func TestDuplicateInitUsesCachedResponse(t *testing.T) {
	n := newNetwork(t, 7, defaultRelayConfig(), ClientConfig{})
	d, _ := n.client.PollTransmit()
	n.relay.HandlePacket(n.now, n.clientAddr, d.Data)
	n.relay.HandlePacket(n.now, n.clientAddr, d.Data)
	r1, _ := n.relay.PollTransmit()
	r2, _ := n.relay.PollTransmit()
	if !bytes.Equal(r1.Data, r2.Data) {
		t.Error("retransmitted INIT got a different response")
	}
	if st := n.relay.Stats(); st.Handshakes != 1 || st.RespRetransmits != 1 || n.relay.Sessions() != 1 {
		t.Errorf("stats %+v, sessions %d", st, n.relay.Sessions())
	}
}

func TestHandshakeRetransmitsAndRestarts(t *testing.T) {
	n := newNetwork(t, 8, defaultRelayConfig(), ClientConfig{})
	var inits [][]byte
	n.tap = func(toRelay bool, d []byte) {
		if toRelay && d[0] == byte(wire.TypeHandshakeInit) {
			inits = append(inits, d)
		}
	}
	n.up.down = true
	n.runFor(12 * time.Second)
	// 1 s, 2 s, 4 s backoff within the first 10 s attempt, then a new attempt.
	if len(inits) < 5 {
		t.Fatalf("sent %d INITs", len(inits))
	}
	if !bytes.Equal(inits[0], inits[1]) || !bytes.Equal(inits[0], inits[3]) {
		t.Error("retransmissions within an attempt differ")
	}
	if bytes.Equal(inits[0][2:10], inits[len(inits)-1][2:10]) {
		t.Error("new attempt reused the sender CID")
	}
	n.up.down = false
	n.establish()
}

func TestReplayedDataIsDropped(t *testing.T) {
	n := newNetwork(t, 9, defaultRelayConfig(), ClientConfig{})
	n.establish()
	var captured []byte
	n.tap = func(toRelay bool, d []byte) {
		if toRelay && d[0] == byte(wire.TypeData) && captured == nil {
			captured = bytes.Clone(d)
		}
	}
	n.client.SendIP(n.now, ipPacket(lease, internet, 100, 1))
	n.runFor(time.Second)
	for range 3 {
		n.relay.HandlePacket(n.now, n.clientAddr, captured)
	}
	n.runFor(time.Second)
	if got := len(n.relayIPs()); got != 1 {
		t.Errorf("relay delivered %d packets", got)
	}
}

func TestSpoofedInnerSourceDropped(t *testing.T) {
	n := newNetwork(t, 10, defaultRelayConfig(), ClientConfig{})
	n.establish()
	n.client.SendIP(n.now, ipPacket([4]byte{10, 77, 0, 99}, internet, 100, 1))
	n.runFor(time.Second)
	if len(n.relayIPs()) != 0 || n.relay.Stats().SpoofedDropped != 1 {
		t.Errorf("delivered %d, stats %+v", len(n.relayIPs()), n.relay.Stats())
	}
}

func TestStatelessResetAfterRelayRestart(t *testing.T) {
	n := newNetwork(t, 11, defaultRelayConfig(), ClientConfig{})
	n.establish()
	n.relay = NewRelay(defaultRelayConfig(), n.now) // restart: state lost, secret kept
	n.client.SendIP(n.now, ipPacket(lease, internet, 100, 1))
	n.runUntil(time.Second, func() bool { return n.client.State() == StateClosed })
	if err := n.clientClosed(); !errors.Is(err, ErrStatelessReset) {
		t.Fatalf("client closed with %v", err)
	}

	// A relay with a different secret cannot reset the session.
	n = newNetwork(t, 12, defaultRelayConfig(), ClientConfig{})
	n.establish()
	rc := defaultRelayConfig()
	rc.ResetSecret = [32]byte{10}
	n.relay = NewRelay(rc, n.now)
	n.client.SendIP(n.now, ipPacket(lease, internet, 100, 1))
	n.runFor(time.Second)
	if n.client.State() != StateActive {
		t.Errorf("forged reset closed the session: %v", n.clientClosed())
	}
}

func TestRekeyKeepsTrafficFlowing(t *testing.T) {
	n := newNetwork(t, 13, defaultRelayConfig(), ClientConfig{})
	n.down.jitter = 20 * time.Millisecond
	s := n.establish()
	for i := range uint32(400) {
		n.client.SendIP(n.now, ipPacket(lease, internet, 100, i))
		s.SendIP(n.now, ipPacket(internet, lease, 100, i))
		n.runFor(time.Second)
	}
	if n.client.Stats().Rekeys < 2 || s.Stats().Rekeys < 2 {
		t.Errorf("rekeys: client %d, relay %d", n.client.Stats().Rekeys, s.Stats().Rekeys)
	}
	if up, down := len(n.relayIPs()), len(n.clientIPs()); up != 400 || down != 400 {
		t.Errorf("delivered %d up, %d down", up, down)
	}
}

func TestKeepaliveAndIdleTimeout(t *testing.T) {
	n := newNetwork(t, 14, defaultRelayConfig(), ClientConfig{})
	n.establish()
	n.runFor(5 * time.Minute) // keepalives hold an idle session open
	if n.client.State() != StateActive || n.relay.Sessions() != 1 {
		t.Fatalf("idle session dropped: %v", n.clientClosed())
	}
	n.up.down, n.down.down = true, true
	n.runFor(DefaultIdleTimeout + time.Second)
	if err := n.clientClosed(); !errors.Is(err, ErrIdleTimeout) || n.relay.Sessions() != 0 {
		t.Errorf("client err %v, relay sessions %d", err, n.relay.Sessions())
	}
}

func TestClose(t *testing.T) {
	n := newNetwork(t, 15, defaultRelayConfig(), ClientConfig{})
	n.establish()
	n.client.Close(n.now)
	n.runFor(time.Second)
	if n.relay.Sessions() != 0 {
		t.Error("relay kept a closed session")
	}
	var peerErr *PeerClosedError
	for _, e := range n.relayEvents {
		if e, ok := e.(SessionClosed); ok && errors.As(e.Err, &peerErr) {
			return
		}
	}
	t.Error("relay did not report a peer close")
}

func TestAckTrackerRanges(t *testing.T) {
	var a ackTracker
	now := time.Unix(0, 0)
	for _, pn := range []uint64{1, 2, 3, 7, 5, 9, 8, 0, 3} {
		a.onReceive(pn, now, true, false)
	}
	got := a.ranges
	want := []wire.PacketRange{{Lo: 7, Hi: 9}, {Lo: 5, Hi: 5}, {Lo: 0, Hi: 3}}
	if len(got) != len(want) {
		t.Fatalf("ranges = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ranges = %v, want %v", got, want)
		}
	}
	ack := a.frame(now, 0)
	iv, err := ack.AppendIntervals(nil)
	if err != nil || len(iv) != 3 || iv[1] != (wire.PacketRange{Lo: 5, Hi: 5}) || iv[2] != (wire.PacketRange{Lo: 0, Hi: 3}) {
		t.Errorf("ACK intervals = %v, %v", iv, err)
	}
}

func TestCredentialLimits(t *testing.T) {
	cfg := ClientConfig{Static: clientKey, RelayPublic: relayKey.Public}
	for _, n := range []int{0, MaxCredentialLen + 1} {
		cfg.Credential = make([]byte, n)
		if _, err := NewClient(cfg, time.Unix(0, 0)); err == nil {
			t.Errorf("credential of %d bytes accepted", n)
		}
	}
	rc := defaultRelayConfig()
	rc.Authorize = func(_, _ []byte, _ *wire.AuthResult) (wire.AuthResult, error) {
		return wire.AuthResult{IPv4: lease, Prefix4: 16, TunMTU: 1280}, nil
	}
	n := newNetwork(t, 16, rc, ClientConfig{Credential: bytes.Repeat([]byte{'x'}, MaxCredentialLen)})
	n.establish()
}
