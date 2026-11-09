package gateway

import (
	"errors"
	"net/netip"
	"reflect"
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
		r, err := g.Authorize([]byte("tok"), nil, nil)
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
	r, err := g.Authorize([]byte("tok"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := g.Authorize([]byte("tok"), nil, &r); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	if _, err := g.Authorize([]byte("bad"), nil, &r); !errors.Is(err, ErrBadCredential) {
		t.Errorf("refresh with a bad token: %v", err)
	}
}

func TestBadToken(t *testing.T) {
	g := newGateway(t, "10.9.0.1/24")
	for _, tok := range []string{"", "to", "tok2", "TOK"} {
		if _, err := g.Authorize([]byte(tok), nil, nil); !errors.Is(err, ErrBadCredential) {
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

// newAccounts returns a gateway on 10.77.0.1/16 with accounts a (two
// tokens, relay access) and b (one token, none).
func newAccounts(t *testing.T) *Gateway {
	t.Helper()
	g, err := New(Config{Network: netip.MustParsePrefix("10.77.0.1/16"), TunMTU: 1280, Accounts: []Account{
		{Name: "a", Tokens: [][]byte{[]byte("a1"), []byte("a2")}, RelayAccess: true},
		{Name: "b", Tokens: [][]byte{[]byte("b1")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func authorize(t *testing.T, g *Gateway, token string) netip.Addr {
	t.Helper()
	r, err := g.Authorize([]byte(token), nil, nil)
	if err != nil {
		t.Fatalf("authorize %s: %v", token, err)
	}
	return netip.AddrFrom4(r.IPv4)
}

func packet(src, dst netip.Addr) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	return pkt
}

func TestAccountsLeaseToTheirOwner(t *testing.T) {
	g := newAccounts(t)
	for token, want := range map[string]string{"a1": "a", "a2": "a", "b1": "b"} {
		if got := g.AccountName(authorize(t, g, token)); got != want {
			t.Errorf("token %s leased to account %q, want %q", token, got, want)
		}
	}
	if g.AccountName(netip.MustParseAddr("10.77.9.9")) != "" {
		t.Error("an unleased address has an account")
	}
	if _, err := g.Authorize([]byte("a"), nil, nil); !errors.Is(err, ErrBadCredential) {
		t.Errorf("an account name authorized: %v", err)
	}
	if got := len(g.Tokens()); got != 3 {
		t.Errorf("Tokens() returned %d tokens, want 3", got)
	}
}

func TestAllowForwardIsolatesAccounts(t *testing.T) {
	g := newAccounts(t)
	a1, a2, b := authorize(t, g, "a1"), authorize(t, g, "a2"), authorize(t, g, "b1")
	relay := netip.MustParseAddr("10.77.0.1")
	for _, c := range []struct {
		name     string
		src, dst netip.Addr
		want     bool
	}{
		{"internet", b, netip.MustParseAddr("198.51.100.7"), true},
		{"same account", a1, a2, true},
		{"other account", a1, b, false},
		{"other account, reverse", b, a2, false},
		{"relay with access", a1, relay, true},
		{"relay without access", b, relay, false},
		{"unleased address", a1, netip.MustParseAddr("10.77.9.9"), false},
		{"network address", a1, netip.MustParseAddr("10.77.0.0"), false},
		{"broadcast", a1, netip.MustParseAddr("10.77.255.255"), false},
		{"unleased source", netip.MustParseAddr("10.77.9.9"), a1, false},
	} {
		if got := g.allowForward(c.src, packet(c.src, c.dst)); got != c.want {
			t.Errorf("%s: AllowForward(%v -> %v) = %v, want %v", c.name, c.src, c.dst, got, c.want)
		}
	}
	if g.allowForward(a1, packet(a1, a2)[:19]) {
		t.Error("forwarded a truncated packet")
	}
}

func TestReleasedLeaseLosesItsAccount(t *testing.T) {
	g, err := New(Config{Network: netip.MustParsePrefix("10.9.0.1/29"), Accounts: []Account{
		{Name: "a", Tokens: [][]byte{[]byte("a")}}, {Name: "b", Tokens: [][]byte{[]byte("b")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a := authorize(t, g, "a")
	b := authorize(t, g, "b")
	if g.allowForward(a, packet(a, b)) {
		t.Fatal("accounts not isolated")
	}
	// Free a's lease (as Release does) and lease it again to b's account.
	g.mu.Lock()
	delete(g.leased, a)
	g.free = append(g.free, a)
	g.mu.Unlock()
	if again := authorize(t, g, "b"); again != a {
		t.Fatalf("reused %v, want %v", again, a)
	}
	if !g.allowForward(a, packet(a, b)) || g.AccountName(a) != "b" {
		t.Error("a reused address kept its previous account")
	}
}

func TestTokensShorthandAccounts(t *testing.T) {
	g, err := New(Config{Network: netip.MustParsePrefix("10.77.0.1/16"), Tokens: [][]byte{[]byte("x"), []byte("y")}})
	if err != nil {
		t.Fatal(err)
	}
	x, y := authorize(t, g, "x"), authorize(t, g, "y")
	if g.AccountName(x) != "token1" || g.AccountName(y) != "token2" {
		t.Errorf("accounts %q, %q", g.AccountName(x), g.AccountName(y))
	}
	if g.allowForward(x, packet(x, y)) || g.allowForward(x, packet(x, netip.MustParseAddr("10.77.0.1"))) {
		t.Error("shorthand tokens are not isolated accounts without relay access")
	}
}

func TestConfigRejectsDuplicates(t *testing.T) {
	n := netip.MustParsePrefix("10.77.0.1/16")
	for name, accounts := range map[string][]Account{
		"name":  {{Name: "a", Tokens: [][]byte{[]byte("1")}}, {Name: "a", Tokens: [][]byte{[]byte("2")}}},
		"token": {{Name: "a", Tokens: [][]byte{[]byte("1")}}, {Name: "b", Tokens: [][]byte{[]byte("1")}}},
		"empty": {{Name: "a", Tokens: [][]byte{{}}}},
		"none":  {{Name: "a"}},
	} {
		if _, err := New(Config{Network: n, Accounts: accounts}); err == nil {
			t.Errorf("%s: accepted %+v", name, accounts)
		}
	}
	if _, err := New(Config{Network: n, Accounts: []Account{{Name: "token1", Tokens: [][]byte{[]byte("1")}}}, Tokens: [][]byte{[]byte("2")}}); err == nil {
		t.Error("a shorthand token's name collided with an account's")
	}
}

func TestParseAccounts(t *testing.T) {
	got, err := ParseAccounts([]string{"lane tokA relay", "friend tokB", "bare", "lane tokC relay"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Account{
		{Name: "lane", Tokens: [][]byte{[]byte("tokA"), []byte("tokC")}, RelayAccess: true},
		{Name: "friend", Tokens: [][]byte{[]byte("tokB")}},
		{Name: "line3", Tokens: [][]byte{[]byte("bare")}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseAccounts = %+v, want %+v", got, want)
	}
	for _, lines := range [][]string{
		{"a tok relays"},           // unknown option
		{"a tok relay extra"},      // too many fields
		{"a/b tok"},                // invalid name
		{"a tok1 relay", "a tok2"}, // relay access differs
		{"a tok1", "b tok1"},       // token repeated
		{"tok", "line1 other"},     // name of a bare line taken
		{"line2 x", "tok"},         // bare line's name taken
	} {
		if _, err := ParseAccounts(lines); err == nil {
			t.Errorf("ParseAccounts(%q) accepted", lines)
		}
	}
}

func TestAllowDial(t *testing.T) {
	g := newAccounts(t)
	a, b := authorize(t, g, "a1"), authorize(t, g, "b1")
	a2 := authorize(t, g, "a2")
	for dst, want := range map[string]bool{
		"198.51.100.7:443":   true,
		"192.168.1.10:22":    true,
		"10.77.0.1:53":       true,  // the relay's tunnel address, with relay access
		"10.77.0.5:22":       false, // an unleased client address
		"127.0.0.1:80":       false,
		"0.0.0.0:80":         false,
		"224.0.0.1:80":       false,
		"169.254.169.254:80": false,
		"255.255.255.255:80": false,
		"[2001:db8::1]:443":  false,
		"198.51.100.7:0":     false,
	} {
		if got := g.allowDial(a, netip.MustParseAddrPort(dst)); got != want {
			t.Errorf("AllowDial(%s) = %v, want %v", dst, got, want)
		}
	}
	for _, c := range []struct {
		src netip.Addr
		dst string
	}{
		{b, "10.77.0.1:53"},                      // the relay, without relay access
		{a, netip.AddrPortFrom(a2, 22).String()}, // another client of the same account
		{a, netip.AddrPortFrom(b, 22).String()},  // another account's client
	} {
		if g.allowDial(c.src, netip.MustParseAddrPort(c.dst)) {
			t.Errorf("AllowDial(%v -> %s) allowed", c.src, c.dst)
		}
	}
	if !g.allowDial(b, netip.MustParseAddrPort("198.51.100.7:443")) {
		t.Error("an account without relay access cannot dial the internet")
	}
}

func TestRefreshKeepsTheAccount(t *testing.T) {
	g := newAccounts(t)
	r, err := g.Authorize([]byte("a1"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Authorize([]byte("a2"), nil, &r); err != nil {
		t.Errorf("refresh with another token of the same account: %v", err)
	}
	if _, err := g.Authorize([]byte("b1"), nil, &r); !errors.Is(err, ErrWrongAccount) {
		t.Errorf("refresh with another account's token: %v", err)
	}
	stale := r
	stale.IPv4 = [4]byte{10, 77, 9, 9}
	if _, err := g.Authorize([]byte("a1"), nil, &stale); !errors.Is(err, ErrWrongAccount) {
		t.Errorf("refresh of an unleased address: %v", err)
	}
}

func TestHostAddrsAndDeny(t *testing.T) {
	host, vpcPeer := netip.MustParseAddr("172.31.5.9"), netip.MustParseAddr("172.31.7.1")
	g, err := New(Config{Network: netip.MustParsePrefix("10.77.0.1/16"), Accounts: []Account{
		{Name: "a", Tokens: [][]byte{[]byte("a1")}, RelayAccess: true},
		{Name: "b", Tokens: [][]byte{[]byte("b1")}},
	}, HostAddrs: []netip.Addr{host}, Deny: []netip.Prefix{netip.MustParsePrefix("172.31.0.0/16")}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := authorize(t, g, "a1"), authorize(t, g, "b1")
	internet := netip.MustParseAddr("198.51.100.7")
	for _, c := range []struct {
		name     string
		src, dst netip.Addr
		want     bool
	}{
		{"host with relay access", a, host, true},
		{"host without relay access", b, host, false},
		{"denied network", a, vpcPeer, false},
		{"denied network, no relay access", b, vpcPeer, false},
		{"metadata service", a, netip.MustParseAddr("169.254.169.254"), false},
		{"multicast", a, netip.MustParseAddr("224.0.0.1"), false},
		{"internet", b, internet, true},
		{"unleased source to the host", netip.MustParseAddr("10.77.9.9"), host, false},
	} {
		if got := g.allowForward(c.src, packet(c.src, c.dst)); got != c.want {
			t.Errorf("%s: allowForward(%v -> %v) = %v, want %v", c.name, c.src, c.dst, got, c.want)
		}
		if got := g.allowDial(c.src, netip.AddrPortFrom(c.dst, 22)); got != c.want {
			t.Errorf("%s: allowDial(%v -> %v) = %v, want %v", c.name, c.src, c.dst, got, c.want)
		}
	}
	if _, err := New(Config{Network: netip.MustParsePrefix("10.77.0.1/16"), Tokens: [][]byte{[]byte("x")},
		Deny: []netip.Prefix{netip.MustParsePrefix("fd00::/8")}}); err == nil {
		t.Error("accepted an IPv6 deny prefix")
	}
}
