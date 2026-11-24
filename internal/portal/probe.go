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
	// Substr, when set, must appear in the body. It exists only for a
	// -portal-probe the operator wrote an expectation for: an operator-written
	// expectation is the one place a fuzzy match is what was asked for, and
	// the built-in endpoints never use it.
	//
	// It is not interchangeable with dropping the check: an expectation of
	// "200:Success" that ignored the substring would accept a login page that
	// also answered 200, which is the failure this field prevents.
	Substr string
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
	c, ep := p.checkEndpoint(ctx)
	c.DNS, c.DNSErr = p.checkDNS(ctx)

	// §4.6: the HTTPS check runs only when plaintext passed, and it runs
	// against the endpoint that passed. Checking a different endpoint's TLS
	// answers a question nobody asked: a portal that rewrites Apple's page
	// while leaving Gstatic's alone would show a clean Gstatic TLS result and
	// bury the interception.
	if c.Check == CheckPass && ep != nil && ep.HTTPSURL != "" {
		c.TLS = p.checkTLS(ctx, ep.HTTPSURL)
	}
	return c
}

// checkEndpoint is probe A. It tries the endpoints in order and returns the
// first that answers usefully, because the first that answers is also the one
// whose declared criterion applies. It returns that endpoint too, so the TLS
// check can be matched to it (§4.6).
func (p *Prober) checkEndpoint(ctx context.Context) (Check, *Endpoint) {
	var last Check
	for i := range p.Endpoints {
		ep := &p.Endpoints[i]
		c := p.oneEndpoint(ctx, *ep)
		if c.Check != CheckNoAnswer {
			return c, ep
		}
		last = c
	}
	return last, nil
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

	// The body is needed for two things: an exact-body criterion, and the login
	// markers of §4.3.2. Read it before classifying, but only as far as the
	// criterion could need it.
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// §4.3.2: a redirect is portal evidence only when its Location
		// qualifies — a different host, or a same-host login path. A 304 has
		// no Location at all, and a same-host redirect to somewhere that is
		// not a login is ordinary web behaviour, so neither is evidence.
		loc := resp.Header.Get("Location")
		if c.Redirect, c.LoginForm = p.classifyRedirect(ctx, ep.URL, loc); c.Redirect != "" || c.LoginForm {
			c.Check = CheckRedirect
			return c
		}
		// A redirect that does not qualify is an unexplained mismatch, not a
		// portal.
		c.Check = CheckMismatch

	case meetsCriterion(ep, resp.StatusCode, body):
		c.Check = CheckPass

	default:
		c.Check = CheckMismatch
		// §4.3.2 asks for an HTML page with actual login-form elements, not
		// any body containing a marker word: a 503 whose text happens to
		// include "accept_terms" is an error page, not a portal.
		c.LoginForm = resp.StatusCode == http.StatusOK &&
			isHTML(resp.Header.Get("Content-Type"), body) &&
			looksLikeLogin(body)
	}
	return c
}

// classifyRedirect decides whether a 3xx is portal evidence, per §4.3.2, and
// returns the usable login URL and whether the target served a login page.
//
// A redirect qualifies when it goes to a different host, or within the same
// host to a path that looks like a login. Anything else — a 304 with no
// Location, a same-host redirect to "/" — is ordinary web behaviour and must
// not suppress the user's carriers.
func (p *Prober) classifyRedirect(ctx context.Context, base, loc string) (portalURL string, loginForm bool) {
	if loc == "" {
		return "", false
	}
	target := resolveRef(base, loc)
	if target == "" {
		return "", false
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	t, err := url.Parse(target)
	if err != nil {
		return "", false
	}
	differentHost := !strings.EqualFold(b.Host, t.Host)

	// Probe C: does the target serve a page, and is it a login page?
	served, page, contentType := p.fetchPage(ctx, target)

	switch {
	case differentHost && served:
		// A different host that serves anything is a portal: no ordinary
		// endpoint redirects a connectivity check to a third party.
		return target, false
	case differentHost:
		// Proven interception, no usable URL (§4.5).
		return "", true
	case served && isHTML(contentType, page) && looksLikeLogin(page):
		// Same host, but the target is a login page for the portal.
		return target, true
	case looksLikeLoginPath(t.Path):
		// Same host and the path names a login, whether or not the page
		// loaded: "redirect to /login" is the classic portal shape.
		return target, true
	}
	return "", false
}

// loginPathMarkers are the path fragments that name a login page. Coarse on
// purpose: the alternative is requiring a page fetch that a portal may not
// serve.
var loginPathMarkers = []string{"login", "log-in", "signin", "sign-in", "auth", "captive", "portal", "welcome", "connect", "hotspot"}

// looksLikeLoginPath reports whether a URL path names a login page.
func looksLikeLoginPath(path string) bool {
	p := strings.ToLower(path)
	for _, m := range loginPathMarkers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
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
		// Exact: an injected page is not the declared one (§4.1).
		return string(body) == ep.Body
	}
	if ep.Substr != "" {
		return strings.Contains(string(body), ep.Substr)
	}
	return true
}

// fetchPage is probe C: fetch a redirect target once, without following
// further redirects, and report whether it serves a page, the body (bounded)
// and its content type.
//
// A portal that redirects to a dead host is still a portal, but there is no URL
// to show — which is why this reports both facts rather than one.
func (p *Prober) fetchPage(ctx context.Context, target string) (served bool, body []byte, contentType string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, nil, ""
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return false, nil, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false, nil, ""
	}
	body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	// Any body at all means something is served there. A 200 with no body is a
	// captive host answering, not a login page.
	return len(body) > 0, body, resp.Header.Get("Content-Type")
}

// isHTML reports whether a body is HTML, by content type when the server
// states one and by a sniff when it does not. §4.3.2 asks for a login *page*,
// so a plain-text body cannot qualify whatever words it contains.
func isHTML(contentType string, body []byte) bool {
	ct := strings.ToLower(contentType)
	if ct != "" {
		return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
	}
	// No content type: sniff the start of the body.
	head := strings.ToLower(strings.TrimSpace(string(body[:min(len(body), 200)])))
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") ||
		strings.Contains(head, "<form") || strings.Contains(head, "<body")
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
func (p *Prober) checkTLS(ctx context.Context, httpsURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpsURL, nil)
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
