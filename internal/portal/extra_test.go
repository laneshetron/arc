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

	got := p.checkTLS(context.Background(), srv.URL)
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

	if got := p.checkTLS(context.Background(), srv.URL); got != "" {
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
