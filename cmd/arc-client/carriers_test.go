package main

import (
	"log/slog"
	"net/netip"
	"testing"
)

// TestCensorshipHoldsUDPBack: under the censorship posture, no UDP
// carrier goes to an address a stream carrier uses, while UDP to another
// address, or with no stream carrier to protect, is kept.
func TestCensorshipHoldsUDPBack(t *testing.T) {
	relay := netip.MustParseAddrPort("203.0.113.7:4433")
	for _, tc := range []struct {
		name    string
		o       carrierOptions
		wantUDP bool
	}{
		{"front on the relay's address", carrierOptions{Censorship: true, Front: "203.0.113.7:443"}, false},
		{"tls on the relay's address", carrierOptions{Censorship: true, TLS: "203.0.113.7:443"}, false},
		{"front elsewhere", carrierOptions{Censorship: true, Front: "198.51.100.9:443"}, true},
		{"no stream carrier", carrierOptions{Censorship: true}, true},
		{"no posture", carrierOptions{Front: "203.0.113.7:443"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.o.Relay = relay
			carriers, closeAll, err := openCarriers(slog.New(slog.DiscardHandler), tc.o)
			if err != nil {
				t.Fatal(err)
			}
			defer closeAll()
			udp := false
			for _, c := range carriers {
				udp = udp || !c.Fallback
			}
			if udp != tc.wantUDP {
				t.Errorf("UDP carrier opened: %v, want %v (carriers %+v)", udp, tc.wantUDP, carriers)
			}
		})
	}
}
