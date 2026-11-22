package client

import (
	"context"
	"errors"
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
		o       CarrierOptions
		wantUDP bool
	}{
		{"front on the relay's address", CarrierOptions{Censorship: true, Front: "203.0.113.7:443"}, false},
		{"tls on the relay's address", CarrierOptions{Censorship: true, TLS: "203.0.113.7:443"}, false},
		{"front elsewhere", CarrierOptions{Censorship: true, Front: "198.51.100.9:443"}, true},
		{"no stream carrier", CarrierOptions{Censorship: true}, true},
		{"no posture", CarrierOptions{Front: "203.0.113.7:443"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.o.Relay = relay
			carriers, closeAll, err := OpenCarriers(slog.New(slog.DiscardHandler), tc.o)
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

// TestCensorshipUsesOneResolution: the hold-back decision and the stream
// carrier share one lookup of the stream endpoint, so a resolver whose
// answers change between lookups cannot open UDP to the address the
// stream carrier then dials. A failed lookup holds UDP back.
func TestCensorshipUsesOneResolution(t *testing.T) {
	relay := netip.MustParseAddrPort("203.0.113.7:4433")
	answers := []netip.AddrPort{ // first a distinct address, then the relay's
		netip.MustParseAddrPort("198.51.100.9:443"), netip.MustParseAddrPort("203.0.113.7:443"),
	}
	var calls int
	old := resolveEndpoints
	t.Cleanup(func() { resolveEndpoints = old })
	resolveEndpoints = func(context.Context, string) ([]netip.AddrPort, error) {
		a := answers[min(calls, len(answers)-1)]
		calls++
		return []netip.AddrPort{a}, nil
	}
	carriers, closeAll, err := OpenCarriers(slog.New(slog.DiscardHandler), CarrierOptions{
		Relay: relay, Censorship: true, Front: "relay.example:443"})
	if err != nil {
		t.Fatal(err)
	}
	closeAll()
	if calls != 1 {
		t.Errorf("stream endpoint resolved %d times, want once", calls)
	}
	if len(carriers) != 2 { // UDP (the answer was distinct) and the front
		t.Errorf("carriers %+v, want UDP and the front", carriers)
	}

	resolveEndpoints = func(context.Context, string) ([]netip.AddrPort, error) {
		return nil, errors.New("no DNS")
	}
	carriers, closeAll, err = OpenCarriers(slog.New(slog.DiscardHandler), CarrierOptions{
		Relay: relay, Censorship: true, Front: "relay.example:443"})
	if err != nil {
		t.Fatal(err)
	}
	closeAll()
	for _, c := range carriers {
		if !c.Fallback {
			t.Errorf("UDP carrier opened though the stream endpoint did not resolve")
		}
	}
}
