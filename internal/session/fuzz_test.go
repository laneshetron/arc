package session

import (
	"net/netip"
	"testing"
	"time"
)

// FuzzHandlePacket feeds arbitrary datagrams to an established relay and
// client. Neither may panic, and the session must survive garbage.
func FuzzHandlePacket(f *testing.F) {
	n := newNetwork(&testing.T{}, 17, defaultRelayConfig(), ClientConfig{})
	n.establish()
	n.tap = func(_ bool, d []byte) { f.Add(append([]byte(nil), d...)) }
	s := n.relaySession()
	n.client.SendIP(n.now, ipPacket(lease, internet, 1280, 1))
	s.SendIP(n.now, ipPacket(internet, lease, 100, 2))
	n.runFor(time.Second)
	n.tap = nil

	attacker := netip.MustParseAddrPort("203.0.113.5:1234")
	f.Fuzz(func(t *testing.T, b []byte) {
		n.relay.HandlePacket(n.now, attacker, b)
		n.relay.HandlePacket(n.now, n.clientAddr, b)
		n.client.HandlePacket(n.now, 0, b)
		// Drain directly: replies to the attacker address are expected here.
		for _, ok := n.relay.PollTransmit(); ok; _, ok = n.relay.PollTransmit() {
		}
		for _, ok := n.client.PollTransmit(); ok; _, ok = n.client.PollTransmit() {
		}
		for e, ok := n.client.PollEvent(); ok; e, ok = n.client.PollEvent() {
			if c, closed := e.(Closed); closed {
				t.Fatalf("garbage closed the client: %v", c.Err)
			}
		}
		for _, ok := n.relay.PollEvent(); ok; _, ok = n.relay.PollEvent() {
		}
		for _, ok := n.client.PollIP(); ok; _, ok = n.client.PollIP() {
		}
		for _, _, ok := n.relay.PollIP(); ok; _, _, ok = n.relay.PollIP() {
		}
		if n.client.State() != StateActive || s.State() != StateActive {
			t.Fatal("garbage closed the session")
		}
	})
}
