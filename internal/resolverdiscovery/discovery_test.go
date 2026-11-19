package resolverdiscovery

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestEligibleAcceptsARoutableResolver(t *testing.T) {
	for _, s := range []string{"9.9.9.9", "8.8.8.8", "1.1.1.1", "192.0.2.53"} {
		if !Eligible(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
}

func TestEligibleRefusesStubs(t *testing.T) {
	// §5.2's whole point: these are what the platform usually hands over,
	// and pinning a socket to one pins nothing.
	for _, s := range []string{
		"127.0.0.53", // systemd-resolved's stub
		"127.0.0.1",  // dnsmasq, macOS
		"127.1.2.3",
		"169.254.169.254", // cloud metadata, never a resolver
		"100.64.0.1",      // CGNAT, which the tunnel may own
		"100.127.255.254",
	} {
		if Eligible(netip.MustParseAddr(s)) {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestEligibleRefusesNonIPv4(t *testing.T) {
	for _, s := range []string{
		"::1",
		"fe80::1",      // the macOS link-local stub
		"2001:db8::53", // global IPv6: §3.1 makes relays IPv4-only
		"0.0.0.0",
		"255.255.255.255",
		"224.0.0.1", // multicast
	} {
		if Eligible(netip.MustParseAddr(s)) {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestEligibleRefusesInvalid(t *testing.T) {
	if Eligible(netip.Addr{}) {
		t.Error("the zero address was accepted")
	}
}

func TestEligibleUnmapsIPv4InIPv6(t *testing.T) {
	// A resolver address may arrive as a v4-mapped v6 address; it is the
	// same resolver and must be judged as one.
	if !Eligible(netip.MustParseAddr("::ffff:9.9.9.9")) {
		t.Error("v4-mapped routable address refused")
	}
	if Eligible(netip.MustParseAddr("::ffff:127.0.0.53")) {
		t.Error("v4-mapped stub accepted")
	}
}

func TestChooseKeepsPlatformOrder(t *testing.T) {
	// The platform's order is its preference, and eligibility is the only
	// thing discovery disagrees about.
	got, err := Choose([]netip.Addr{
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("1.1.1.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "9.9.9.9" {
		t.Errorf("chose %s, want the first", got)
	}
}

func TestChooseSkipsStubs(t *testing.T) {
	// The common real case: a stub first, the actual upstream behind it.
	got, err := Choose([]netip.Addr{
		netip.MustParseAddr("127.0.0.53"),
		netip.MustParseAddr("192.168.1.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "192.168.1.1" {
		t.Errorf("chose %s", got)
	}
}

func TestChooseCollapsesDuplicates(t *testing.T) {
	// Two services listing the same resolver must not cost two attempts.
	cands := []netip.Addr{
		netip.MustParseAddr("127.0.0.53"),
		netip.MustParseAddr("127.0.0.53"),
		netip.MustParseAddr("9.9.9.9"),
	}
	got, err := Choose(cands)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "9.9.9.9" {
		t.Errorf("chose %s", got)
	}
	// A v4-mapped duplicate of an eligible address is the same resolver.
	got, err = Choose([]netip.Addr{
		netip.MustParseAddr("::ffff:9.9.9.9"),
		netip.MustParseAddr("9.9.9.9"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "9.9.9.9" {
		t.Errorf("chose %s", got)
	}
}

func TestChooseReportsUnavailable(t *testing.T) {
	// §5.2: a DoH/DoT-only network exposes no plain resolver, and that is a
	// correct "unsupported" rather than a reason to use the stub.
	_, err := Choose([]netip.Addr{
		netip.MustParseAddr("127.0.0.53"),
		netip.MustParseAddr("fe80::1"),
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
	if _, err := Choose(nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("empty candidates: %v", err)
	}
}

func TestExplainNamesEachRefusal(t *testing.T) {
	// §5.2 requires the client to say why the lifeline is unavailable;
	// "the only resolver was 127.0.0.53" is the sentence a user needs.
	got := Explain([]netip.Addr{
		netip.MustParseAddr("127.0.0.53"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("2001:db8::53"),
		netip.MustParseAddr("9.9.9.9"),
	})
	if len(got) != 4 {
		t.Fatalf("%d explanations", len(got))
	}
	checks := []string{"stub", "link-local", "not IPv4", "eligible"}
	for i, want := range checks {
		if !strings.Contains(got[i], want) {
			t.Errorf("explanation %d is %q, want it to mention %q", i, got[i], want)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
