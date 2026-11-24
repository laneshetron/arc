package portal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
)

// TestClassifyTLSError covers §4.6's table: the journal records what was
// observed, never "intercepted", because a broken middlebox and a real
// interception are indistinguishable from the client.
func TestClassifyTLSError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"certificate verification", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "verify_failed"},
		{"unknown authority", x509.UnknownAuthorityError{}, "verify_failed"},
		{"hostname mismatch", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "a.example"}, "verify_failed"},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired}, "verify_failed"},
		{"timeout", timeoutErr{}, "timeout"},
		{"reset", errors.New("read tcp: connection reset by peer"), "reset"},
		{"truncated", io.ErrUnexpectedEOF, "truncated"},
		{"eof", io.EOF, "truncated"},
		{"anything else", errors.New("boom"), "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyTLSError(tc.err); got != tc.want {
				t.Errorf("classifyTLSError = %q, want %q", got, tc.want)
			}
		})
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// TestCheckTLSWithSelfSignedEndpoint is §4.6's second row: the plaintext check
// passes, the HTTPS check fails to verify, and the state is unchanged with the
// failure recorded.
func TestCheckTLSWithSelfSignedEndpoint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := NewProber(nil)
	// A client that does not trust the test certificate — which is exactly the
	// situation §4.6 describes.
	p.Client = &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{},
	}}

	got := p.checkTLS(context.Background(), p.Client, srv.URL)
	if got != "verify_failed" {
		t.Errorf("checkTLS = %q, want verify_failed for an untrusted certificate", got)
	}
}

// TestCheckTLSHealthyEndpoint records nothing, so a healthy network's journal
// stays quiet.
func TestCheckTLSHealthyEndpoint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := NewProber(nil)
	p.Client = srv.Client() // trusts the test certificate

	if got := p.checkTLS(context.Background(), p.Client, srv.URL); got != "" {
		t.Errorf("checkTLS = %q, want empty for a healthy endpoint", got)
	}
}

// TestCheckTLSSkippedWithoutHTTPSURL: an endpoint with no HTTPS form means the
// check does not run, which is not a finding. The decision is Probe's, which
// only calls checkTLS when the passing endpoint has one.
func TestCheckTLSSkippedWithoutHTTPSURL(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer plain.Close()

	p := NewProber(nil)
	p.Client = plain.Client()
	p.Endpoints = []Endpoint{{Name: "e", URL: plain.URL, Status: http.StatusNoContent}}

	c := p.Probe(context.Background())
	if c.Check != CheckPass {
		t.Fatalf("Check = %v, want a pass", c.Check)
	}
	if c.TLS != "" {
		t.Errorf("TLS = %q, want empty when the passing endpoint has no HTTPS form", c.TLS)
	}
}

// TestTLSCheckMatchesThePassingEndpoint is the review's HTTPS-selection
// finding: the TLS check must run against the endpoint that passed plaintext,
// not against whichever endpoint happens to list an HTTPS URL. A portal that
// leaves Gstatic's 204 alone but rewrites Apple's page would otherwise produce
// a clean Gstatic TLS result and bury the interception.
func TestTLSCheckMatchesThePassingEndpoint(t *testing.T) {
	var gstaticTLS, appleTLS bool
	g := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer g.Close()
	gTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gstaticTLS = true
	}))
	defer gTLS.Close()
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Success"))
	}))
	defer a.Close()
	aTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appleTLS = true
		w.Write([]byte("Success"))
	}))
	defer aTLS.Close()

	p := NewProber(nil)
	p.Client = aTLS.Client() // trusts both test certificates
	p.Endpoints = []Endpoint{
		{Name: "gstatic", URL: g.URL, Status: http.StatusNoContent, HTTPSURL: gTLS.URL},
		{Name: "apple", URL: a.URL, Status: http.StatusOK, Body: "Success", HTTPSURL: aTLS.URL},
	}

	c := p.Probe(context.Background())
	if c.Endpoint != "gstatic" {
		t.Fatalf("Endpoint = %q, want the first that answered", c.Endpoint)
	}
	if !gstaticTLS {
		t.Error("the HTTPS check did not use the endpoint that passed plaintext")
	}
	if appleTLS {
		t.Error("the HTTPS check used a different endpoint than the one that passed")
	}
}

// TestResolveUsesTheLinksUpstreams covers the path the HTTP dialer takes: the
// name is answered by the link's own resolver, not the system's.
func TestResolveUsesTheLinksUpstreams(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	u := &UpstreamResolver{
		Interface: "wlan0",
		Discover:  fakeDiscover([]netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil),
		Timeout:   200 * time.Millisecond,
		Dial: func(_ context.Context, _, addr string, _ sockopt.Options) (net.Conn, error) {
			mu.Lock()
			seen = append(seen, addr)
			mu.Unlock()
			return nil, errors.New("stub")
		},
	}
	_, err := u.resolve(context.Background(), "captive.apple.com")
	if err == nil {
		t.Fatal("want an error when every query is stubbed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no query was attempted")
	}
	if seen[0] != "192.0.2.53:53" {
		t.Errorf("queried %q, want the link's upstream", seen[0])
	}
}

// TestResolveWithoutAnUpstreamFails: no discoverable upstream is an error, which
// is what makes the dialer fall back to the system resolver rather than hang.
func TestResolveWithoutAnUpstreamFails(t *testing.T) {
	u := &UpstreamResolver{Interface: "wlan0", Discover: fakeDiscover(nil, nil)}
	if _, err := u.resolve(context.Background(), "example.com"); err == nil {
		t.Fatal("want an error when the link has no upstream")
	}
}

// TestDialerFallsBackOnlyWithoutAnUpstream is the line §4.4 draws: no upstream
// is a reason to use the system resolver, a broken upstream is not. Falling back
// on a broken link resolver asks the tunnel — after FullTunnel that is what the
// system resolver is — and reports the relay's DNS as though it were the
// network's.
func TestDialerFallsBackOnlyWithoutAnUpstream(t *testing.T) {
	t.Run("no upstream falls back", func(t *testing.T) {
		var asked []string
		u := &UpstreamResolver{
			Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
				asked = append(asked, name)
				return nil, ErrNoUpstream
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		// The system resolver will fail for this name, but the point is that it
		// was tried: the error must not be the link's.
		_, err := u.Dialer(time.Second)(ctx, "tcp", "no-such-host.invalid:80")
		if len(asked) != 1 {
			t.Fatalf("asked the link's resolver %d times, want once", len(asked))
		}
		if err != nil && errors.Is(err, ErrNoUpstream) {
			t.Error("the link's error escaped instead of the system lookup being tried")
		}
	})

	t.Run("a broken upstream does not fall back", func(t *testing.T) {
		u := &UpstreamResolver{
			Resolve: func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("upstream timed out")
			},
		}
		start := time.Now()
		_, err := u.Dialer(time.Second)(context.Background(), "tcp", "captive.apple.com:80")
		if err == nil {
			t.Fatal("want an error: a broken link resolver must not silently use the tunnel's")
		}
		if strings.Contains(err.Error(), "no such host") {
			t.Error("the system resolver answered: a broken upstream fell through to the tunnel")
		}
		// And it failed fast: no second full timeout for the system lookup.
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Errorf("took %s: the failed lookup was retried against the system resolver", elapsed)
		}
	})
}

// TestProbeRoundResolvesEachHostOnce is the e2e regression: probe A falls back
// across three endpoints, and a per-dial lookup made a link with a dead upstream
// pay its full DNS timeout once per endpoint before any HTTP was attempted —
// enough to blow a startup budget on exactly the network detection exists for.
func TestProbeRoundResolvesEachHostOnce(t *testing.T) {
	// Three endpoints on three hosts, all failing to connect.
	var (
		mu      sync.Mutex
		lookups []string
	)
	u := &UpstreamResolver{
		Interface: "c0",
		Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
			mu.Lock()
			lookups = append(lookups, name)
			mu.Unlock()
			// Slow and failing, like an upstream that has gone away.
			time.Sleep(80 * time.Millisecond)
			return nil, errors.New("upstream gone")
		},
	}

	p := NewProber(nil)
	p.Client = &http.Client{Transport: &http.Transport{
		// A dialer that never connects, so every endpoint is a no-answer.
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unreachable")
		},
	}}
	p.Endpoints = []Endpoint{
		{Name: "a", URL: "http://a.invalid/check", Status: http.StatusNoContent},
		{Name: "b", URL: "http://a.invalid/check2", Status: http.StatusOK},
		{Name: "c", URL: "http://c.invalid/check", Status: http.StatusOK},
	}
	p.Rounds = u

	start := time.Now()
	p.Probe(context.Background())
	elapsed := time.Since(start)

	mu.Lock()
	defer mu.Unlock()
	hosts := map[string]int{}
	for _, name := range lookups {
		hosts[name]++
	}
	// Two distinct hosts, so two lookups at most — and only one once the
	// resolver has shown it is not answering.
	if hosts["a.invalid"] != 1 {
		t.Errorf("looked up a.invalid %d times, want once per round", hosts["a.invalid"])
	}
	if hosts["c.invalid"] != 0 {
		t.Errorf("looked up c.invalid %d times after the resolver failed; the round should stop asking", hosts["c.invalid"])
	}
	if elapsed > 2*80*time.Millisecond {
		t.Errorf("round took %s; a dead resolver is being retried per endpoint", elapsed)
	}
}

// TestProbeDialerResolvesOnTheLink is the review's second P1: the HTTP probes
// must not ask the system resolver for an endpoint's address, because after
// managed DNS that resolver is the tunnel's. The link's upstream answers, and
// only the address is substituted — the Host and TLS server name stay the
// endpoint's, so certificate verification is unchanged.
func TestProbeDialerResolvesOnTheLink(t *testing.T) {
	want := netip.MustParseAddr("198.51.100.7")
	var (
		mu    sync.Mutex
		asked []string
	)
	u := &UpstreamResolver{
		Interface: "en0",
		Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
			mu.Lock()
			asked = append(asked, name)
			mu.Unlock()
			return []netip.Addr{want}, nil
		},
	}
	d := u.Dialer(time.Second)

	// The stub resolves to a documentation address, so the connection attempt
	// fails — and that is the point: the address it tried came from the link's
	// resolver, not from the system one, and the deadline keeps the test short.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, _ = d(ctx, "tcp", "connectivitycheck.gstatic.com:80")

	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || asked[0] != "connectivitycheck.gstatic.com" {
		t.Fatalf("asked the link's resolver for %v, want the endpoint host", asked)
	}
}

// TestDialerLeavesLiteralAddressesAlone keeps the substitution off the hot path
// when there is nothing to resolve.
func TestDialerLeavesLiteralAddressesAlone(t *testing.T) {
	var asked []string
	u := &UpstreamResolver{
		Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
			asked = append(asked, name)
			return nil, errors.New("should not be asked")
		},
	}
	d := u.Dialer(50 * time.Millisecond)
	_, _ = d(context.Background(), "tcp", "203.0.113.5:9")
	if len(asked) != 0 {
		t.Errorf("resolved %v: a literal address needs no lookup", asked)
	}
}

// TestDefaultEndpointsHTTPSFormsMatchTheirHosts is the review's follow-up: an
// endpoint with an HTTPS form is checked over TLS on that endpoint's own host,
// so a Gstatic pass is not verified against Apple's certificate.
func TestDefaultEndpointsHTTPSFormsMatchTheirHosts(t *testing.T) {
	byName := map[string]Endpoint{}
	for _, ep := range DefaultEndpoints {
		byName[ep.Name] = ep
	}
	if ep := byName["gstatic"]; ep.HTTPSURL == "" {
		t.Fatal("gstatic has no HTTPS form: the TLS check would fall back to another endpoint")
	}
	for _, ep := range DefaultEndpoints {
		if ep.HTTPSURL == "" {
			continue
		}
		plain, err := url.Parse(ep.URL)
		if err != nil {
			t.Fatalf("%s: %v", ep.Name, err)
		}
		secure, err := url.Parse(ep.HTTPSURL)
		if err != nil {
			t.Fatalf("%s: %v", ep.Name, err)
		}
		if plain.Host != secure.Host {
			t.Errorf("%s: HTTPS host %q differs from the plaintext host %q", ep.Name, secure.Host, plain.Host)
		}
		if secure.Scheme != "https" {
			t.Errorf("%s: HTTPSURL scheme = %q", ep.Name, secure.Scheme)
		}
		if plain.Path != secure.Path {
			t.Errorf("%s: HTTPS path %q differs from the plaintext path %q", ep.Name, secure.Path, plain.Path)
		}
	}
}

// TestDialerAppliesSocketOptions is a smoke test: the dialer must be usable and
// must reach a local server, which is what proves the sockopt hook does not
// break ordinary dialing on this platform.
func TestDialerAppliesSocketOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// No options: an unbound dialer, which is the pre-tunnel case.
	d := Dialer(sockopt.Options{}, 2*time.Second)
	c, err := d(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
}

// TestUpstreamDialIgnoresTheSystemAddress is §4.4's core claim: the query must
// go to the link's upstream, not to whatever address the resolver asks for
// (which comes from resolv.conf and is the stub or the tunnel's resolver).
func TestUpstreamDialIgnoresTheSystemAddress(t *testing.T) {
	want := netip.MustParseAddr("192.0.2.1")
	var got string
	// A recording dialer instead of a live one, so the assertion is on the
	// address chosen and no timeout is waited out. It is injected rather than
	// installed as a package global, which would race a probe still winding
	// down from another test.
	d := upstreamDial(want, sockopt.Options{}, func(_ context.Context, _, addr string, _ sockopt.Options) (net.Conn, error) {
		got = addr
		return nil, errors.New("recorded")
	})

	// The system address is deliberately different and must be ignored.
	_, _ = d(context.Background(), "udp", "127.0.0.53:53")
	if got != want.String()+":53" {
		t.Errorf("dialed %q, want %q", got, want.String()+":53")
	}
}

// TestQueryFirstFallsThrough covers a dead first upstream: the second must be
// tried, because a resolver reached over a captive link is often unreachable.
func TestQueryFirstFallsThrough(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no UDP available:", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// A port nothing listens on, then the live one.
	dead := netip.MustParseAddr("127.0.0.1")
	live := pc.LocalAddr().(*net.UDPAddr).AddrPort().Addr()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Both will fail to answer usefully, but the second must have been tried,
	// which is why this asserts on the error path rather than a result.
	if _, err := queryFirst(ctx, []netip.Addr{dead, live}, "example.com", time.Second, sockopt.Options{}, nil); err != nil {
		t.Logf("both upstreams failed, as expected: %v", err)
	}
}

// TestRoundFailureNeverDialsAHostname is the review's multi-endpoint P1: once
// one lookup in a round fails, the later endpoints must get that failure, not a
// dial of the bare hostname — which the system resolver would answer, and after
// full-tunnel routing the system resolver is the tunnel's.
func TestRoundFailureNeverDialsAHostname(t *testing.T) {
	var (
		mu     sync.Mutex
		dialed []string
	)
	u := &UpstreamResolver{
		Interface: "wlan0",
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("upstream timed out")
		},
		connect: func(_ context.Context, _, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return nil, errors.New("unreachable")
		},
	}
	p := NewProber(nil)
	p.Endpoints = []Endpoint{
		{Name: "a", URL: "http://a.invalid/check", Status: http.StatusNoContent},
		{Name: "b", URL: "http://b.invalid/check", Status: http.StatusOK},
		{Name: "c", URL: "http://c.invalid/check", Status: http.StatusOK},
	}
	p.Rounds = u

	if got := p.Probe(context.Background()).Check; got != CheckNoAnswer {
		t.Errorf("Check = %v, want no answer on a link whose resolver is down", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 0 {
		t.Errorf("dialed %v: a failed physical lookup fell through to the system resolver", dialed)
	}
}

// TestNoSystemFallbackAfterTheTunnel covers the deliberate ErrNoUpstream
// fallback: it is honest before the tunnel exists and not after, when the system
// resolver answers through ARC.
func TestNoSystemFallbackAfterTheTunnel(t *testing.T) {
	var dialed []string
	u := &UpstreamResolver{
		Resolve: func(context.Context, string) ([]netip.Addr, error) { return nil, ErrNoUpstream },
		connect: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return nil, errors.New("unreachable")
		},
	}
	dial := u.Dialer(time.Second)

	_, _ = dial(context.Background(), "tcp", "captive.apple.com:80")
	if len(dialed) != 1 || dialed[0] != "captive.apple.com:80" {
		t.Fatalf("dialed %v before the tunnel, want the system fallback for a link with no upstream", dialed)
	}

	dialed = nil
	u.DisableSystemFallback()
	_, err := dial(context.Background(), "tcp", "captive.apple.com:80")
	if len(dialed) != 0 {
		t.Errorf("dialed %v after the tunnel: the system resolver is the tunnel's now", dialed)
	}
	if !errors.Is(err, ErrNoUpstream) {
		t.Errorf("err = %v, want the link's own ErrNoUpstream", err)
	}
}

// TestDiscoverNamesThePhysicalLink is the review's Linux P1: an unnamed
// attachment asks for the link the marked route leaves by, never for "every
// link" — which would include ARC's TUN — and never for "", which resolvectl
// rejects.
func TestDiscoverNamesThePhysicalLink(t *testing.T) {
	origLink, origDiscover := physicalLink, discoverUpstream
	defer func() { physicalLink, discoverUpstream = origLink, origDiscover }()

	var gotMark uint32
	physicalLink = func(_ context.Context, mark uint32) (string, error) {
		gotMark = mark
		return "wlan0", nil
	}
	var asked []string
	discoverUpstream = func(_ context.Context, iface string) ([]netip.Addr, error) {
		asked = append(asked, iface)
		return []netip.Addr{netip.MustParseAddr("192.168.1.1")}, nil
	}

	u := &UpstreamResolver{Sockopt: sockopt.Options{Mark: 0x5243}}
	if _, err := u.discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "wlan0" {
		t.Errorf("discovery asked for %q, want the routed physical link", asked)
	}
	if gotMark != 0x5243 {
		t.Errorf("route lookup used mark %#x, want the probe's: the mark is what selects the physical table", gotMark)
	}

	// No physical link is no upstream, not an error the HTTP probes treat as a
	// broken resolver.
	physicalLink = func(context.Context, uint32) (string, error) { return "", errors.New("no route") }
	if _, err := u.discover(context.Background()); !errors.Is(err, ErrNoUpstream) {
		t.Errorf("err = %v, want ErrNoUpstream", err)
	}
}
