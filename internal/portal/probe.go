package portal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
)

// Endpoint is one connectivity check with its own declared success response
// (spec/captive-portals.md §4.1).
//
// The criterion is per endpoint, not "204", because it has to be:
// captive.apple.com/hotspot-detect.html returns 200 with a Success page on a
// healthy network, and a client expecting 204 everywhere classifies every
// healthy Mac as unauthenticated and never starts.
type Endpoint struct {
	// Name identifies the endpoint in the journal.
	Name string
	// URL is the plaintext HTTP check. Plaintext first because it is the only
	// check that can see an HTTP-level redirect, which is what produces a
	// login URL (§4.6).
	URL string
	// Status is the healthy status code. Zero means any 2xx.
	Status int
	// Body, when set, must match the body's bytes exactly (§4.1). A portal
	// that injects its own page into a 200 is not passing the check, so this
	// is an equality test rather than a substring one.
	Body string
	// HTTPSURL, when set, is the same endpoint over TLS. It is checked only
	// after the plaintext check passes, to catch a portal that leaves
	// cleartext alone but intercepts TLS (§4.6).
	HTTPSURL string
}

// DefaultEndpoints are the connectivity checks of §4.1, in the order they are
// tried. The first that answers decides; the rest are fallbacks for networks
// that block one of them.
var DefaultEndpoints = []Endpoint{
	{
		Name:   "gstatic",
		URL:    "http://connectivitycheck.gstatic.com/generate_204",
		Status: http.StatusNoContent,
	},
	{
		Name:   "apple",
		URL:    "http://captive.apple.com/hotspot-detect.html",
		Status: http.StatusOK,
		Body:   "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
		// Verified over HTTPS too: the same page, valid certificate. Used for
		// the TLS check of §4.6.
		HTTPSURL: "https://captive.apple.com/hotspot-detect.html",
	},
	{
		Name:   "msft",
		URL:    "http://www.msftconnecttest.com/connecttest.txt",
		Status: http.StatusOK,
		Body:   "Microsoft Connect Test",
	},
}

// maxBody bounds what a probe reads. A portal page can be large and a
// hostile one unbounded; the classifier only needs enough to look for login
// form markers and to compare against a declared body.
const maxBody = 64 << 10

// Prober runs the probes of §4.1. Its zero value is unusable; call NewProber.
type Prober struct {
	// Endpoints is the connectivity-check list. Defaults to DefaultEndpoints.
	Endpoints []Endpoint
	// Client performs the HTTP checks. Its transport should be bound to the
	// physical interface (§4.1), which the caller does because only it knows
	// the interface.
	Client *http.Client
	// Resolver, when set, answers probe B (§4.4). Nil leaves DNS unmeasured,
	// which is a legitimate outcome on a stub-only or DoH-only host.
	Resolver DNSProber
	// DNSName is the canary resolved for probe B. Defaults to canaryName.
	DNSName string
	// Now is the clock, for tests. Defaults to time.Now.
	Now func() time.Time
}

// canaryName is the public name probe B resolves. It only has to be a name
// with a public answer, so that a private or reserved answer is categorically
// implausible (§4.4).
const canaryName = "example.com"

// DNSProber answers probe B: resolve a public name through the physical
// link's own upstream, not the system resolver (§4.4), and report whether the
// answer is categorically implausible.
//
// It is an interface because the upstream discovery is platform-specific —
// resolvectl on Linux, scutil on macOS — and because tests must not need a
// resolver.
type DNSProber interface {
	// Honesty resolves name and returns the verdict. An error means the probe
	// could not run, which the caller reports as DNSUnmeasured.
	Honesty(ctx context.Context, name string) (DNSVerdict, error)
}

// NewProber returns a Prober with the default endpoints and a client with the
// given dialer. The dialer is how the caller binds probes to the physical
// interface and keeps them out of the TUN (§4.1).
func NewProber(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Prober {
	transport := &http.Transport{
		DialContext: dial,
		// A portal's redirect must be visible, so redirects are never
		// followed: the Location is the evidence (§4.5).
		DisableKeepAlives: true,
		// Probes carry nothing secret and go to fixed endpoints; keep the
		// timeout short so detection does not delay startup.
		ResponseHeaderTimeout: 5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
	}
	return &Prober{
		Endpoints: DefaultEndpoints,
		Client: &http.Client{
			Transport: transport,
			// Never follow: a redirect is what identifies a portal.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Now: time.Now,
	}
}

// Check is one round of detection: the classification evidence plus the
// details the journal records (§4.7: evidence, never the URL).
type Check struct {
	Evidence

	// Endpoint is the endpoint that answered, for the journal.
	Endpoint string
	// Status is the status it answered with, 0 when none.
	Status int
	// BodyBytes is how much body came back — enough to tell a rewritten page
	// from an empty one without recording the page.
	BodyBytes int
	// TLS is the outcome of the HTTPS check of §4.6, or "" when it did not
	// run. It records what was observed, not a verdict (§4.6): a broken
	// middlebox and a real interception are indistinguishable from here.
	TLS string
	// DNSErr is why probe B could not run, when it could not.
	DNSErr error
}

// Probe runs one round of detection and returns the evidence, without
// classifying it: the Classifier owns the history and the transition rules.
//
// A probe never returns an error. Every failure mode is evidence — a timeout,
// a refused connection and a rewritten body are different findings, and §4's
// P3 rule is that they must not collapse into "unreachable".
func (p *Prober) Probe(ctx context.Context) Check {
	c := p.checkEndpoint(ctx)
	c.DNS, c.DNSErr = p.checkDNS(ctx)

	// §4.6: an HTTPS check runs only when plaintext passed, and its failure
	// lowers confidence without changing the state.
	if c.Check == CheckPass {
		c.TLS = p.checkTLS(ctx)
	}
	return c
}

// checkEndpoint is probe A. It tries the endpoints in order and returns the
// first that answers usefully, because the first that answers is also the one
// whose declared criterion applies.
func (p *Prober) checkEndpoint(ctx context.Context) Check {
	var last Check
	for _, ep := range p.Endpoints {
		c := p.oneEndpoint(ctx, ep)
		if c.Check != CheckNoAnswer {
			return c
		}
		last = c
	}
	return last
}

// oneEndpoint runs probe A against a single endpoint, plus probe C when it
// redirected (§4.5).
func (p *Prober) oneEndpoint(ctx context.Context, ep Endpoint) Check {
	c := Check{Endpoint: ep.Name}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
	if err != nil {
		return c
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return c // CheckNoAnswer: a transport failure is not an HTTP finding
	}
	defer resp.Body.Close()
	c.Status = resp.StatusCode

	// Read a bounded body. A 204 has none by RFC 9110 and net/http will not
	// deliver one anyway (§4.2), so this is only ever interesting for the
	// endpoints that declare a body.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil && len(body) == 0 {
		return c
	}
	c.BodyBytes = len(body)

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// A redirect is positive portal evidence whether or not its target
		// is alive (§4.5). Probe C asks whether there is a usable URL.
		c.Check = CheckRedirect
		if loc := resp.Header.Get("Location"); loc != "" {
			if target := resolveRef(ep.URL, loc); target != "" && p.servesPage(ctx, target) {
				c.Redirect = target
			}
		}

	case meetsCriterion(ep, resp.StatusCode, body):
		c.Check = CheckPass

	default:
		c.Check = CheckMismatch
		// A login page served by the connectivity host itself has no
		// redirect to follow, so the body is the only evidence (§4.5).
		c.LoginForm = looksLikeLogin(body)
	}
	return c
}

// meetsCriterion reports whether a response is the one the endpoint declares.
func meetsCriterion(ep Endpoint, status int, body []byte) bool {
	if ep.Status == 0 {
		if status < 200 || status > 299 {
			return false
		}
	} else if status != ep.Status {
		return false
	}
	if ep.Body != "" {
		return string(body) == ep.Body
	}
	return true
}

// servesPage is probe C: fetch the redirect target once, without following
// further redirects, and report whether it serves a page. A portal that
// redirects to a dead host is still a portal, but there is no URL to show.
func (p *Prober) servesPage(ctx context.Context, target string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false
	}
	// Any body at all means something is served there. A 200 with no body is
	// a captive host answering, not a login page.
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
	return n > 0
}

// resolveRef resolves a Location against the request URL. Bare Locations
// ("/login") are common from portal gear.
func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	u := b.ResolveReference(r)
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.String()
}

// looksLikeLogin applies §4.3.2's marker test: a login page asks for
// something only a portal asks for.
func looksLikeLogin(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	s := strings.ToLower(string(body))
	for _, m := range LoginFormMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// checkDNS is probe B.
func (p *Prober) checkDNS(ctx context.Context) (DNSVerdict, error) {
	if p.Resolver == nil {
		return DNSUnmeasured, nil
	}
	name := p.DNSName
	if name == "" {
		name = canaryName
	}
	return p.Resolver.Honesty(ctx, name)
}

// checkTLS is the HTTPS half of §4.6: the same endpoint over TLS, to catch a
// portal that leaves cleartext alone but intercepts HTTPS.
//
// Its result never changes the state. It records what was observed, because a
// broken middlebox, an expired certificate on the endpoint and a genuine
// interception are indistinguishable from here — so the journal says
// "tls=verify_failed", not "tls_intercepted".
func (p *Prober) checkTLS(ctx context.Context) string {
	ep := p.tlsEndpoint()
	if ep == nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.HTTPSURL, nil)
	if err != nil {
		return "request_failed"
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return classifyTLSError(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
	return ""
}

// tlsEndpoint returns the first endpoint that has an HTTPS check.
func (p *Prober) tlsEndpoint() *Endpoint {
	for i := range p.Endpoints {
		if p.Endpoints[i].HTTPSURL != "" {
			return &p.Endpoints[i]
		}
	}
	return nil
}

// classifyTLSError names the observed failure, per §4.6's table. The result
// never changes the state; it only decides what the journal records.
func classifyTLSError(err error) string {
	var (
		cve    *tls.CertificateVerificationError
		hoster x509.HostnameError
		uaErr  x509.UnknownAuthorityError
		certer x509.CertificateInvalidError
		neterr net.Error
	)
	switch {
	case errors.As(err, &cve), errors.As(err, &hoster), errors.As(err, &uaErr), errors.As(err, &certer):
		return "verify_failed"
	case errors.As(err, &neterr) && neterr.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "reset by peer"):
		return "reset"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "truncated"
	}
	return "failed"
}

// Dialer returns a dial function that keeps probes on the physical link: it
// applies the same socket options the carriers use (§4.1's requirement that
// probe traffic bypasses the TUN, which would otherwise measure the relay's
// egress instead of the network's).
//
// The mark and device follow `sockopt.Options`, so a caller that already
// binds carriers to an interface binds probes the same way. An empty Options
// leaves them unset, which is correct before the tunnel exists.
func Dialer(opts sockopt.Options, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, Control: sockopt.Control(opts)}
	return d.DialContext
}
