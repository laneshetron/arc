package portal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
)

// resolvectlOutput is abridged real output from `resolvectl dns`. The global
// stanza is what must be ignored: it belongs to the daemon and is reached
// through the stub.
const resolvectlOutput = `Global: 8.8.8.8 2001:4860:4860::8888
Link 2 (enp0s3):
Link 3 (wlan0): 192.168.1.1 2001:db8::1
Link 4 (docker0): 172.17.0.1
`

func TestParseResolvectlDNS(t *testing.T) {
	got := parseResolvectlDNS([]byte(resolvectlOutput), "wlan0")
	want := []netip.Addr{
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("2001:db8::1"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestParseResolvectlIgnoresGlobal is the §4.4 rule in one assertion: the
// global upstream is the one reached through the daemon, which forwards into
// the tunnel once ARC is up.
func TestParseResolvectlIgnoresGlobal(t *testing.T) {
	for _, a := range parseResolvectlDNS([]byte(resolvectlOutput), "wlan0") {
		if a == netip.MustParseAddr("8.8.8.8") {
			t.Fatal("took the global upstream, which routes through the stub")
		}
	}
}

// TestParseResolvectlRejectsStubs covers the case §4.4 exists for: a host
// whose configured upstream is systemd-resolved's own stub.
func TestParseResolvectlRejectsStubs(t *testing.T) {
	const out = `Link 3 (wlan0): 127.0.0.53 127.0.0.1 fe80::1
`
	if got := parseResolvectlDNS([]byte(out), "wlan0"); len(got) != 0 {
		t.Fatalf("kept stubs: %v", got)
	}
}

func TestParseResolvectlUnknownLink(t *testing.T) {
	if got := parseResolvectlDNS([]byte(resolvectlOutput), "eth9"); len(got) != 0 {
		t.Fatalf("got %v for an absent link", got)
	}
}

// scutilOutput is abridged real `scutil --dns` output, including a global
// resolver with no if_index (which must be ignored) and a scoped one.
const scutilOutput = `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Request A records, Request AAAA records

resolver #2
  nameserver[0] : 8.8.8.8
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records
`

func TestParseScutilDNS(t *testing.T) {
	got := parseScutilDNS([]byte(scutilOutput), "en0")
	if len(got) == 0 {
		t.Fatal("no resolvers found for en0")
	}
	for _, a := range got {
		if a != netip.MustParseAddr("192.168.1.1") {
			t.Errorf("got %v, want only the link's own 192.168.1.1", a)
		}
	}
	// The global resolver has no if_index and must not be taken: it is the
	// daemon's, reached through the daemon.
	for _, a := range got {
		if a == netip.MustParseAddr("8.8.8.8") {
			t.Error("took the global resolver, which is reached through the daemon")
		}
	}
}

func TestParseScutilRejectsLoopback(t *testing.T) {
	const out = `resolver #1
  nameserver[0] : 127.0.0.1
  if_index : 6 (en0)
`
	if got := parseScutilDNS([]byte(out), "en0"); len(got) != 0 {
		t.Fatalf("kept a loopback resolver: %v", got)
	}
}

// TestJudgeAnswer covers §4.4's rule from both sides: private shapes are
// anomalous, and a different public address is not.
func TestJudgeAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []string
		want  DNSVerdict
	}{
		{"public", []string{"93.184.216.34"}, DNSClean},
		{"a different public address", []string{"1.2.3.4"}, DNSClean},
		{"two publics", []string{"1.2.3.4", "5.6.7.8"}, DNSClean},
		{"RFC1918", []string{"192.168.1.1"}, DNSAnomalous},
		{"10/8", []string{"10.0.0.1"}, DNSAnomalous},
		{"172.16/12", []string{"172.16.0.1"}, DNSAnomalous},
		{"loopback", []string{"127.0.0.1"}, DNSAnomalous},
		{"link-local", []string{"169.254.1.1"}, DNSAnomalous},
		{"CGNAT", []string{"100.64.0.1"}, DNSAnomalous},
		{"benchmarking", []string{"198.18.0.1"}, DNSAnomalous},
		{"reserved 240/4", []string{"240.0.0.1"}, DNSAnomalous},
		{"this-network", []string{"0.1.2.3"}, DNSAnomalous},
		{"IPv6 loopback", []string{"::1"}, DNSAnomalous},
		{"IPv6 link-local", []string{"fe80::1"}, DNSAnomalous},
		{"IPv6 multicast", []string{"ff02::1"}, DNSAnomalous},
		{"public and private together", []string{"1.2.3.4", "10.0.0.1"}, DNSAnomalous},
		{"no answer", nil, DNSClean},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addrs []netip.Addr
			for _, s := range tc.addrs {
				addrs = append(addrs, netip.MustParseAddr(s))
			}
			if got := judgeAnswer(addrs); got != tc.want {
				t.Errorf("judgeAnswer(%v) = %v, want %v", tc.addrs, got, tc.want)
			}
		})
	}
}

// fakeDiscover returns a fixed upstream list.
func fakeDiscover(addrs []netip.Addr, err error) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) { return addrs, err }
}

// TestUpstreamResolverNoUpstreamIsUnmeasured is the tri-state rule: a
// stub-only or DoH-only host has no upstream, and "could not measure" must not
// read as "honest".
func TestUpstreamResolverNoUpstreamIsUnmeasured(t *testing.T) {
	u := &UpstreamResolver{Interface: "wlan0", Discover: fakeDiscover(nil, nil)}
	got, err := u.Honesty(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != DNSUnmeasured {
		t.Errorf("verdict = %v, want unmeasurable", got)
	}
}

// TestUpstreamResolverDiscoverErrorIsUnmeasured: a platform without the tool
// is unmeasurable too, not a failure of the network.
func TestUpstreamResolverDiscoverErrorIsUnmeasured(t *testing.T) {
	u := &UpstreamResolver{
		Interface: "wlan0",
		Discover:  fakeDiscover(nil, errors.New("resolvectl: not found")),
	}
	if got, err := u.Honesty(context.Background(), "example.com"); err == nil || got != DNSUnmeasured {
		t.Errorf("verdict = %v err = %v, want unmeasurable and the error", got, err)
	}
}

// TestImplausibleLeavesPublicV6Alone guards against over-reach: global IPv6 is
// ordinary and must not be flagged.
func TestImplausibleLeavesPublicV6Alone(t *testing.T) {
	for _, s := range []string{"2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if implausible(netip.MustParseAddr(s)) {
			t.Errorf("%s flagged as implausible", s)
		}
	}
}

// TestDNSVerdictStrings covers the journal vocabulary of §4.4: these strings
// reach a shared diagnostics upload, so they are interface, not detail.
func TestDNSVerdictStrings(t *testing.T) {
	for _, tc := range []struct {
		v    DNSVerdict
		want string
	}{
		{DNSUnmeasured, "unmeasurable"},
		{DNSClean, "clean"},
		{DNSAnomalous, "anomalous"},
	} {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// TestUpstreamResolverUsesDiscoveredServer covers the path from a discovered
// upstream through a query to a verdict, with the query itself stubbed.
func TestUpstreamResolverUsesDiscoveredServer(t *testing.T) {
	// The resolver dials concurrently (UDP and TCP in parallel), so the
	// recorder must be safe under -race.
	var (
		mu   sync.Mutex
		seen []string
	)
	u := &UpstreamResolver{
		Interface: "wlan0",
		Discover:  fakeDiscover([]netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil),
		Timeout:   time.Second,
		Sockopt:   sockopt.Options{Device: "wlan0"},
		Dial: func(_ context.Context, _, addr string, _ sockopt.Options) (net.Conn, error) {
			mu.Lock()
			seen = append(seen, addr)
			mu.Unlock()
			return nil, errors.New("recorded")
		},
	}
	_, err := u.Honesty(context.Background(), "example.com")
	if err == nil {
		t.Fatal("want an error when the query cannot be delivered")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no dial recorded")
	}
	for _, addr := range seen {
		if addr != "203.0.113.9:53" {
			t.Errorf("dialed %q, want the discovered upstream", addr)
		}
	}
}

// TestUpstreamResolverAppliesSocketOptions is the other half of the review's
// probe-B finding: choosing the explicit upstream is not enough if the socket
// still follows the default route. Once full-tunnel routing is installed, an
// unbound query goes through the TUN to the relay's resolver and always looks
// honest — so the interface binding and mark must reach the dial.
func TestUpstreamResolverAppliesSocketOptions(t *testing.T) {
	var (
		mu    sync.Mutex
		opts  []sockopt.Options
		nets  []string
		calls int
	)

	want := sockopt.Options{Device: "wlan0", Mark: 0x5243}
	u := &UpstreamResolver{
		Interface: "wlan0",
		Discover:  fakeDiscover([]netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil),
		Timeout:   200 * time.Millisecond,
		Sockopt:   want,
		Dial: func(_ context.Context, network, _ string, o sockopt.Options) (net.Conn, error) {
			mu.Lock()
			opts = append(opts, o)
			nets = append(nets, network)
			calls++
			mu.Unlock()
			return nil, errors.New("recorded")
		},
	}
	if _, err := u.Honesty(context.Background(), "example.com"); err == nil {
		t.Fatal("want an error when every query is stubbed out")
	}

	mu.Lock()
	defer mu.Unlock()
	if calls == 0 {
		t.Fatal("no dial recorded")
	}
	for i, o := range opts {
		if o != want {
			t.Errorf("dial %d (%s) options = %+v, want %+v", i, nets[i], o, want)
		}
	}
}
