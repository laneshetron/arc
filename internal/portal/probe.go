package portal

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"

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
		// The same path over TLS: generate_204 answers 204 with a valid
		// certificate, which is what §4.6's check needs. Without it a Gstatic
		// pass had no HTTPS form of its own, so checkTLS fell back to another
		// endpoint's certificate and reported on a host the probe never used.
		HTTPSURL: "https://connectivitycheck.gstatic.com/generate_204",
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
	// LoginPage reports that probe C fetched a redirect's target and found a
	// login form there. It is journal detail; the redirect itself is the
	// evidence, and a dead target is still evidence without it.
	LoginPage bool
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
		if v := p.classifyRedirect(ctx, ep.URL, loc); v.evidence {
			c.Check = CheckRedirect
			c.Redirect, c.LoginPage = v.url, v.loginForm
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
		if c.LoginForm {
			// §4.5's second row: the connectivity host served the login page
			// itself, so the URL to show is the URL that served it. Without
			// this the URL is empty and the client tells the user it "cannot
			// locate" a portal whose address it just fetched.
			c.Redirect = ep.URL
		}
	}
	return c
}

// redirectVerdict separates the two questions §4.5 insists on separating: does
// this prove a portal, and is there a URL worth showing? A target that does not
// load still proves interception; it just leaves nothing to click.
type redirectVerdict struct {
	// evidence reports that the redirect proves a portal exists.
	evidence bool
	// url is the usable login URL, or "" when the target did not serve a page.
	url string
	// loginForm reports that the target served an actual login form, for the
	// journal. It is not the same as evidence: a dead target is evidence with
	// no form.
	loginForm bool
}

// classifyRedirect decides whether a 3xx is portal evidence, per §4.3.2.
//
// A redirect qualifies when it goes to a different host, or within the same
// host to a path that names a login or to a page that really is one. Anything
// else — a 304 with no Location, a same-host redirect to "/" — is ordinary web
// behaviour and must not suppress the user's carriers.
func (p *Prober) classifyRedirect(ctx context.Context, base, loc string) redirectVerdict {
	if loc == "" {
		return redirectVerdict{}
	}
	target := resolveRef(base, loc)
	if target == "" {
		return redirectVerdict{}
	}
	b, err := url.Parse(base)
	if err != nil {
		return redirectVerdict{}
	}
	t, err := url.Parse(target)
	if err != nil {
		return redirectVerdict{}
	}
	differentHost := !strings.EqualFold(b.Host, t.Host)

	// Probe C: does the target serve a page, and is it a login page?
	served, page, contentType := p.fetchPage(ctx, target)
	pageIsLogin := served && isHTML(contentType, page) && looksLikeLogin(page)
	// A page that loaded can be shown. Whether it is a *login* page decides the
	// journal and, for a same-host redirect, whether this is evidence at all.
	url := ""
	if served {
		url = target
	}

	switch {
	case differentHost:
		// No ordinary endpoint redirects a connectivity check to a third
		// party, so the host change alone is proof (§4.3.2). The URL is
		// whatever the target managed to serve.
		return redirectVerdict{evidence: true, url: url, loginForm: pageIsLogin}
	case pageIsLogin:
		return redirectVerdict{evidence: true, url: target, loginForm: true}
	case looksLikeLoginPath(t.Path):
		// Same host and the path names a login: "redirect to /login" is the
		// classic portal shape, and it holds whether or not the page loads
		// (§4.5's third row).
		return redirectVerdict{evidence: true, url: url}
	}
	return redirectVerdict{}
}

// loginPathSegments are path segments that name a login page. Matched against
// whole segments, not substrings: "connect" as a substring matches
// "/account-connect" and "/author-bio" matches "auth", and a false positive
// here tells the user to log in to something that is not a portal.
var loginPathSegments = map[string]bool{
	"login": true, "log-in": true, "log_in": true, "logon": true,
	"signin": true, "sign-in": true, "sign_in": true,
	"captive": true, "captiveportal": true,
	"hotspot": true, "welcome": true, "authenticate": true,
	"portal-login": true,
}

// looksLikeLoginPath reports whether a URL path names a login page, per
// §4.3.2's "same-host login path".
func looksLikeLoginPath(path string) bool {
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		seg = strings.TrimSuffix(seg, ".html")
		seg = strings.TrimSuffix(seg, ".htm")
		seg = strings.TrimSuffix(seg, ".php")
		seg = strings.TrimSuffix(seg, ".asp")
		if loginPathSegments[seg] {
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

// looksLikeLogin reports whether a body is a login *page*, per §4.3.2: an HTML
// document containing a form that asks for something a portal asks for.
//
// It parses the markup rather than searching the bytes. A substring test over
// the raw body matches a comment, a script string, an attribute in some
// unrelated widget, or documentation mentioning "type=\"password\"" — none of
// which is a form a user can be asked to fill in, and all of which would
// suppress the user's carriers on an ordinary network.
func looksLikeLogin(body []byte) bool {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var (
		form   bool
		secret bool
	)
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if form && secret {
			return
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "form":
				form = true
			case "input":
				if looksLikePortalField(attr(n, "type"), attr(n, "name"), attr(n, "id")) {
					secret = true
				}
			case "select", "textarea":
				if looksLikePortalField("", attr(n, "name"), attr(n, "id")) {
					secret = true
				}
			}
			// A script or style body is not markup a user interacts with.
			if n.Data == "script" || n.Data == "style" {
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	// §4.3.2 asks for a form with login fields, and both halves matter: a bare
	// password input outside any form is a widget, and an empty form is a
	// search box.
	return form && secret
}

// looksLikePortalField reports whether one form control asks for a credential
// or a portal-specific token.
//
// The name list is short because the test has to stay specific: "user",
// "email" and "password" appear in ordinary sign-in pages, which is exactly why
// the password *type* is what carries the weight rather than a name.
func looksLikePortalField(typ, name, id string) bool {
	if strings.EqualFold(typ, "password") {
		return true
	}
	for _, v := range []string{name, id} {
		v = strings.ToLower(v)
		if v == "" {
			continue
		}
		switch v {
		case "voucher", "room", "roomnumber", "seat", "seatnumber",
			"terms", "accept_terms", "access_code", "accesscode", "pin":
			return true
		}
	}
	return false
}

// attr returns the value of an element's attribute, or "".
func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
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
// It does **not** control which resolver answers the hostname in addr, so a
// Prober built with it still asks the system resolver for every endpoint's
// address. That is fine before a tunnel exists and wrong after: managed DNS
// points the system resolver at the tunnel, so the lookup would travel through
// the very path being diagnosed. Use UpstreamResolver.Dialer instead, which
// resolves the name on the link first.
func Dialer(opts sockopt.Options, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, Control: sockopt.Control(opts)}
	return d.DialContext
}

// Dialer returns a dial function for the HTTP probes that resolves each
// endpoint's hostname through this link's own upstream before connecting, with
// the link's socket options on the connection.
//
// Without it, probe A depends on the system resolver. After `FullTunnel`
// installs managed DNS that resolver is the tunnel's, so an A/AAAA lookup for
// the connectivity endpoint either travels through the path it is supposed to
// test, fails when that path fails (misreporting a portal as unreachable), or
// answers with an address that does not belong to the bound attachment.
//
// The name is what TLS and HTTP still use: only the address is substituted
// here, so the Host header and the TLS server name stay the endpoint's, and
// certificate verification is unchanged.
//
// When the link cannot resolve the name — no discoverable upstream, a stub-only
// or DoH-only host — the lookup falls back to the system resolver. That is not
// better than before, but it is the only resolution available, and failing the
// probe outright would invent a network fault.
func (u *UpstreamResolver) Dialer(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, Control: sockopt.Control(u.Sockopt)}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return d.DialContext(ctx, network, addr)
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return d.DialContext(ctx, network, addr) // already an address
		}
		addrs, err := u.lookup(ctx, host)
		if err != nil || len(addrs) == 0 {
			return d.DialContext(ctx, network, addr)
		}
		var lastErr error
		for _, a := range addrs {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// lookup is resolve, with a hook the tests use to answer without a resolver.
func (u *UpstreamResolver) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	if u.Resolve != nil {
		return u.Resolve(ctx, name)
	}
	return u.resolve(ctx, name)
}
