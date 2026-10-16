package gateway

import (
	"errors"
	"net/netip"
	"testing"
)

func newGateway(t *testing.T, network string) *Gateway {
	t.Helper()
	g, err := New(Config{Network: netip.MustParsePrefix(network), TunMTU: 1280, Tokens: [][]byte{[]byte("tok")}})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestLeasesSkipReservedAddresses(t *testing.T) {
	g := newGateway(t, "10.9.0.1/29") // hosts .1–.6; .1 is the relay
	var got []string
	for {
		r, err := g.Authorize([]byte("tok"), nil, false)
		if errors.Is(err, ErrPoolExhausted) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if r.Prefix4 != 29 || r.TunMTU != 1280 {
			t.Errorf("result = %+v", r)
		}
		got = append(got, netip.AddrFrom4(r.IPv4).String())
	}
	want := []string{"10.9.0.2", "10.9.0.3", "10.9.0.4", "10.9.0.5", "10.9.0.6"}
	if len(got) != len(want) {
		t.Fatalf("leased %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("leased %v, want %v", got, want)
		}
	}
}

func TestRefreshDoesNotLease(t *testing.T) {
	g := newGateway(t, "10.9.0.1/30") // exactly one client address
	if _, err := g.Authorize([]byte("tok"), nil, false); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := g.Authorize([]byte("tok"), nil, true); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	if _, err := g.Authorize([]byte("bad"), nil, true); !errors.Is(err, ErrBadCredential) {
		t.Errorf("refresh with a bad token: %v", err)
	}
}

func TestBadToken(t *testing.T) {
	g := newGateway(t, "10.9.0.1/24")
	for _, tok := range []string{"", "to", "tok2", "TOK"} {
		if _, err := g.Authorize([]byte(tok), nil, false); !errors.Is(err, ErrBadCredential) {
			t.Errorf("token %q: %v", tok, err)
		}
	}
}

func TestLookupIgnoresUnleasedAndNonIPv4(t *testing.T) {
	g := newGateway(t, "10.9.0.1/24")
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[16:20], []byte{10, 9, 0, 2})
	if g.Lookup(pkt) != nil || g.Lookup(pkt[:19]) != nil {
		t.Error("lookup matched without a bound session")
	}
	pkt[0] = 0x60
	if g.Lookup(pkt) != nil {
		t.Error("lookup matched an IPv6 packet")
	}
}

func TestNetworkValidation(t *testing.T) {
	for _, n := range []string{"10.9.0.1/31", "fd00::1/64"} {
		if _, err := New(Config{Network: netip.MustParsePrefix(n)}); err == nil {
			t.Errorf("accepted %s", n)
		}
	}
}

func TestAllowDial(t *testing.T) {
	g, err := New(Config{Network: netip.MustParsePrefix("10.77.0.1/16"), TunMTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	for dst, want := range map[string]bool{
		"198.51.100.7:443":   true,
		"192.168.1.10:22":    true,
		"10.77.0.1:53":       true,  // the relay's tunnel address
		"10.77.0.5:22":       false, // another client
		"127.0.0.1:80":       false,
		"0.0.0.0:80":         false,
		"224.0.0.1:80":       false,
		"169.254.169.254:80": false,
		"255.255.255.255:80": false,
		"[2001:db8::1]:443":  false,
		"198.51.100.7:0":     false,
	} {
		if got := g.AllowDial(netip.MustParseAddrPort(dst)); got != want {
			t.Errorf("AllowDial(%s) = %v, want %v", dst, got, want)
		}
	}
}
