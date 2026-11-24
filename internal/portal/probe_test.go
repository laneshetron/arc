package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// testProber returns a Prober whose endpoint is the given server. The client
// follows no redirects, as the real one does not, so a 3xx is observable.
func testProber(t *testing.T, h http.Handler, ep Endpoint) *Prober {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	ep.URL = srv.URL + "/check"
	if ep.HTTPSURL != "" {
		ep.HTTPSURL = "" // the test server is plaintext
	}
	p := NewProber(nil)
	p.Endpoints = []Endpoint{ep}
	p.Client = srv.Client()
	p.Client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return p
}

// TestProbePassMatchesTheDeclaredCriterion is §4.1's central rule: the
// criterion is per endpoint, so the same handler passes one profile and fails
// another.
func TestProbePassMatchesTheDeclaredCriterion(t *testing.T) {
	gstatic := Endpoint{Name: "gstatic", Status: http.StatusNoContent}
	apple := Endpoint{Name: "apple", Status: http.StatusOK, Body: "<HTML>Success</HTML>"}

	t.Run("204 satisfies a 204 profile", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), gstatic)
		if got := p.Probe(context.Background()).Check; got != CheckPass {
			t.Errorf("Check = %v, want pass", got)
		}
	})

	t.Run("200 with a body satisfies the apple profile", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<HTML>Success</HTML>"))
		}), apple)
		if got := p.Probe(context.Background()).Check; got != CheckPass {
			t.Errorf("Check = %v, want pass", got)
		}
	})

	// The regression that would break every Mac: an endpoint declaring 204
	// answering 200 is a mismatch, and the same answer against a profile that
	// declares 200 is a pass.
	t.Run("200 does not satisfy a 204 profile", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<HTML><BODY>Success</BODY></HTML>"))
		}), gstatic)
		c := p.Probe(context.Background())
		if c.Check != CheckMismatch {
			t.Errorf("Check = %v, want mismatch", c.Check)
		}
	})

	// A portal injecting its own page into a 200 must not pass a profile with
	// a declared body: the comparison is exact (§4.1).
	t.Run("an injected body fails an exact-body profile", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<HTML>Success</HTML><!-- portal -->"))
		}), apple)
		if got := p.Probe(context.Background()).Check; got != CheckMismatch {
			t.Errorf("Check = %v, want mismatch", got)
		}
	})
}

// TestProbeSubstringCriterion is the review's P1 end to end: a custom
// -portal-probe-expect 200:Success must accept a body containing Success and
// reject one that does not — including a login page that also answers 200,
// which is the failure a status-only check would let through.
func TestProbeSubstringCriterion(t *testing.T) {
	custom := Endpoint{Name: "custom", Status: http.StatusOK, Substr: "Microsoft Connect Test"}

	t.Run("a matching body passes", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Microsoft Connect Test"))
		}), custom)
		if got := p.Probe(context.Background()).Check; got != CheckPass {
			t.Errorf("Check = %v, want pass", got)
		}
	})

	t.Run("a 200 login page does not pass", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html><body><form action="/login">` +
				`<input type="password" name="pass"></form></body></html>`))
		}), custom)
		c := p.Probe(context.Background())
		if c.Check == CheckPass {
			t.Fatal("Check = pass: a 200 login page satisfied a substring criterion it does not contain")
		}
		// The page is still a portal — it is a login form — so it must count as
		// positive evidence rather than merely "not a pass": Evidence.portals()
		// takes LoginForm whichever CheckKind accompanies it.
		if !c.LoginForm {
			t.Errorf("LoginForm = false: a 200 login page must still be portal evidence")
		}
		if !c.Evidence.portals() {
			t.Error("Evidence.portals() = false for a login page")
		}
	})

	t.Run("a 200 without the substring is a mismatch", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("something else entirely"))
		}), custom)
		if got := p.Probe(context.Background()).Check; got != CheckMismatch {
			t.Errorf("Check = %v, want mismatch", got)
		}
	})
}

// TestProbeRedirectFollowsNothingAndProbesTarget covers §4.5: a redirect is
// proof, and probe C decides whether there is a URL to show.
func TestProbeRedirectFollowsNothingAndProbesTarget(t *testing.T) {
	t.Run("live target yields a URL", func(t *testing.T) {
		var portalURL string
		portalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<html><form><input type=password name=pass></form></html>"))
		}))
		defer portalSrv.Close()
		portalURL = portalSrv.URL + "/login"

		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, portalURL, http.StatusFound)
		}), Endpoint{Name: "e", Status: http.StatusNoContent})

		c := p.Probe(context.Background())
		if c.Check != CheckRedirect {
			t.Fatalf("Check = %v, want redirect", c.Check)
		}
		if c.Redirect != portalURL {
			t.Errorf("Redirect = %q, want %q", c.Redirect, portalURL)
		}
		if !c.LoginPage {
			t.Error("LoginPage = false: the target served a password form")
		}
	})

	t.Run("dead target yields no URL but still a redirect", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
		}), Endpoint{Name: "e", Status: http.StatusNoContent})

		c := p.Probe(context.Background())
		if c.Check != CheckRedirect {
			t.Fatalf("Check = %v, want redirect", c.Check)
		}
		if c.Redirect != "" {
			t.Errorf("Redirect = %q, want empty for an unreachable target", c.Redirect)
		}
	})
}

// TestProbeDetectsALoginPageServedDirectly is §4.5's second row: the
// connectivity host answers 200 with a login page and no redirect at all.
func TestProbeDetectsALoginPageServedDirectly(t *testing.T) {
	p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><form><input type="password" name="pw">` +
			`<input name="room"></form></body></html>`))
	}), Endpoint{Name: "e", Status: http.StatusNoContent})

	c := p.Probe(context.Background())
	if c.Check != CheckMismatch {
		t.Fatalf("Check = %v, want mismatch", c.Check)
	}
	if !c.LoginForm {
		t.Error("LoginForm = false, want true: the body asks for a password and a room")
	}

	// And the classifier turns that into unauthenticated, which is the part
	// that matters.
	if got := observe(false, c.Evidence); got != StateUnauthenticated {
		t.Errorf("state = %v, want unauthenticated", got)
	}
}

// TestProbeAnUnmarkedErrorPageIsNotAPortal is §4.3.2: a gateway error page
// with no login form is a mismatch and nothing more.
func TestProbeAnUnmarkedErrorPageIsNotAPortal(t *testing.T) {
	p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("<html><body>503 Service Unavailable</body></html>"))
	}), Endpoint{Name: "e", Status: http.StatusNoContent})

	c := p.Probe(context.Background())
	if c.Check != CheckMismatch {
		t.Fatalf("Check = %v, want mismatch", c.Check)
	}
	if c.LoginForm {
		t.Error("LoginForm = true for a plain error page")
	}
	st := observe(true, c.Evidence)
	if st != StateUnknown {
		t.Errorf("state = %v, want unknown: a 503 is not portal evidence", st)
	}
	if st.BlocksCarriers() {
		t.Error("a 503 must not suppress carriers")
	}
}

// TestProbeUnqualifiedRedirectsAreNotEvidence is the other half of the review's
// P2: counting every 3xx as positive evidence would let an ordinary web
// behaviour — a 304, or a same-host redirect to "/" — suppress the user's
// carriers indefinitely. §4.3.2's qualifying test is the one that counts.
func TestProbeUnqualifiedRedirectsAreNotEvidence(t *testing.T) {
	t.Run("304 with no Location is a mismatch", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotModified)
		}), Endpoint{Name: "e", Status: http.StatusNoContent})

		c := p.Probe(context.Background())
		if c.Check != CheckMismatch {
			t.Errorf("Check = %v, want mismatch: a 304 has no Location to qualify", c.Check)
		}
		if c.Evidence.portals() {
			t.Error("a 304 counted as portal evidence")
		}
	})

	t.Run("same-host redirect to root is a mismatch", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
		}), Endpoint{Name: "e", Status: http.StatusNoContent})

		c := p.Probe(context.Background())
		if c.Check != CheckMismatch {
			t.Errorf("Check = %v, want mismatch: a same-host redirect to / is ordinary web behaviour", c.Check)
		}
		if c.Evidence.portals() {
			t.Error("a same-host redirect to / counted as portal evidence")
		}
		if got := observe(true, c.Evidence); got != StateUnknown {
			t.Errorf("state = %v, want unknown", got)
		}
	})

	t.Run("same-host redirect to a live login path yields a URL", func(t *testing.T) {
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/check" {
				http.Redirect(w, r, "/login?next=/", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><form><input type="password" name="pw"></form></html>`))
		}))
		defer srv.Close()
		srvURL = srv.URL

		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, srvURL+"/login?next=/", http.StatusFound)
		}), Endpoint{Name: "e", Status: http.StatusNoContent})

		c := p.Probe(context.Background())
		if c.Check != CheckRedirect {
			t.Fatalf("Check = %v, want redirect", c.Check)
		}
		if c.Redirect == "" {
			t.Error("Redirect empty: the same-host login path served a page")
		}
		if !c.LoginPage {
			t.Error("LoginPage = false: the target served a password form")
		}
	})

	// §4.5's third row: a login path that does not load still proves
	// interception, and still leaves nothing to show. The two answers are
	// independent, which is why the probe returns them separately.
	t.Run("same-host redirect to a dead login path is evidence with no URL", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Every path redirects, so the target never serves a page.
			http.Redirect(w, r, "/login", http.StatusFound)
		}), Endpoint{Name: "e", Status: http.StatusNoContent})

		c := p.Probe(context.Background())
		if c.Check != CheckRedirect {
			t.Fatalf("Check = %v, want redirect: interception is proven", c.Check)
		}
		if c.Redirect != "" {
			t.Errorf("Redirect = %q, want empty: the target never served a page", c.Redirect)
		}
		if got := observe(false, c.Evidence); got != StateUnauthenticated {
			t.Errorf("state = %v, want unauthenticated", got)
		}
	})

	t.Run("a 503 containing a marker word is not a login form", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("<html><body>Please accept_terms to continue</body></html>"))
		}), Endpoint{Name: "e", Status: http.StatusNoContent})

		c := p.Probe(context.Background())
		if c.LoginForm {
			t.Error("LoginForm = true: a 503 whose text mentions a marker is an error page")
		}
		if st := observe(true, c.Evidence); st != StateUnknown {
			t.Errorf("state = %v, want unknown", st)
		}
	})

	t.Run("a plain-text body with a marker word is not a login form", func(t *testing.T) {
		p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("accept_terms"))
		}), Endpoint{Name: "e", Status: http.StatusOK})

		c := p.Probe(context.Background())
		if c.LoginForm {
			t.Error("LoginForm = true: a text/plain body is not an HTML login form")
		}
	})
}

// TestProbeNoAnswer covers the transport failures: they are CheckNoAnswer,
// not a mismatch, so three of them make the network unreachable rather than
// pretending to have classified it.
func TestProbeNoAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close() // nothing is listening now

	ep := Endpoint{Name: "e", Status: http.StatusNoContent, URL: dead + "/check"}
	p := NewProber(nil)
	p.Endpoints = []Endpoint{ep}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if got := p.Probe(ctx).Check; got != CheckNoAnswer {
		t.Errorf("Check = %v, want no-answer for a refused connection", got)
	}
}

// fakeDNS implements DNSProber.
type fakeDNS struct {
	v   DNSVerdict
	err error
}

func (f fakeDNS) Honesty(context.Context, string) (DNSVerdict, error) { return f.v, f.err }

// TestProbeDNSIsReportedNotDecided checks that probe B's verdict reaches the
// classifier intact, including the unmeasurable case.
func TestProbeDNSIsReportedNotDecided(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  DNSProber
		want DNSVerdict
	}{
		{"no resolver", nil, DNSUnmeasured},
		{"clean", fakeDNS{v: DNSClean}, DNSClean},
		{"anomalous", fakeDNS{v: DNSAnomalous}, DNSAnomalous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}), Endpoint{Name: "e", Status: http.StatusNoContent})
			p.Resolver = tc.res
			if got := p.Probe(context.Background()).DNS; got != tc.want {
				t.Errorf("DNS = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestProbeFallsBackAcrossEndpoints covers the list: a blocked first endpoint
// must not end detection.
func TestProbeFallsBackAcrossEndpoints(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	p := NewProber(nil)
	p.Endpoints = []Endpoint{
		{Name: "dead", URL: deadURL + "/check", Status: http.StatusNoContent},
		{Name: "good", URL: good.URL + "/check", Status: http.StatusNoContent},
	}
	p.Client = good.Client()
	c := p.Probe(context.Background())
	if c.Check != CheckPass || c.Endpoint != "good" {
		t.Errorf("Check = %v from %q, want pass from the second endpoint", c.Check, c.Endpoint)
	}
}

// TestResolveRef covers the Location forms portal gear actually emits.
func TestResolveRef(t *testing.T) {
	for _, tc := range []struct {
		base, ref, want string
	}{
		{"http://a.example/check", "http://b.example/login", "http://b.example/login"},
		{"http://a.example/check", "/login", "http://a.example/login"},
		{"http://a.example/check?x=1", "login?y=2", "http://a.example/login?y=2"},
		{"http://a.example/check", "//b.example/x", "http://b.example/x"},
	} {
		got := resolveRef(tc.base, tc.ref)
		if got != tc.want {
			t.Errorf("resolveRef(%q, %q) = %q, want %q", tc.base, tc.ref, got, tc.want)
		}
	}
}

// TestResolveRefRejectsOtherSchemes keeps a hostile Location from making the
// probe dereference something that is not a web page.
func TestResolveRefRejectsOtherSchemes(t *testing.T) {
	for _, ref := range []string{"ftp://a.example/x", "file:///etc/passwd", "javascript:alert(1)"} {
		if got := resolveRef("http://a.example/check", ref); got != "" {
			t.Errorf("resolveRef accepted %q as %q", ref, got)
		}
	}
}

// TestLooksLikeLogin covers form detection both ways: it must fire on portals
// and stay quiet on ordinary pages, because a false positive suppresses every
// carrier.
func TestLooksLikeLogin(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"password field", `<form><input type="password"></form>`, true},
		{"single-quoted attr", `<form><input type='PASSWORD'></form>`, true},
		{"uppercase attr name", `<FORM><INPUT TYPE="password"></FORM>`, true},
		{"room number", `<form><input name="room" value=""></form>`, true},
		{"voucher", `<form><input name="voucher"></form>`, true},
		{"terms acceptance", `<form><input type="checkbox" name="terms"></form>`, true},
		{"select of rooms", `<form><select name="room"><option>1</option></select></form>`, true},
		{"plain success page", `<HTML><BODY>Success</BODY></HTML>`, false},
		{"error page", `<html>503 Service Unavailable</html>`, false},
		{"empty", ``, false},

		// The cases a substring test got wrong, and the reason this parses.
		{"password mentioned in a comment",
			`<html><!-- the hotel used to render <input type="password"> here --><body>Welcome</body></html>`, false},
		{"password in a script string",
			`<html><script>var tpl = '<input type="password" name="pw">';</script><body>OK</body></html>`, false},
		{"password in documentation",
			`<html><body><p>Configure it as &lt;input type="password"&gt; in your router.</p></body></html>`, false},
		{"password input outside any form",
			`<html><body><input type="password" name="pw"></body></html>`, false},
		{"empty form",
			`<html><body><form action="/search"><input name="q"></form></body></html>`, false},
		{"ordinary sign-in page with only an email field",
			`<html><body><form><input name="email"></form></body></html>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeLogin([]byte(tc.body)); got != tc.want {
				t.Errorf("looksLikeLogin = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDefaultEndpointsHaveCriteria guards the table: an endpoint with no
// declared status would accept any 2xx, which for a connectivity check means
// a portal's 200 page passes.
func TestDefaultEndpointsHaveCriteria(t *testing.T) {
	for _, ep := range DefaultEndpoints {
		if ep.Status == 0 {
			t.Errorf("%s: no declared status", ep.Name)
		}
		if _, err := url.Parse(ep.URL); err != nil {
			t.Errorf("%s: %v", ep.Name, err)
		}
		if !strings.HasPrefix(ep.URL, "http://") {
			t.Errorf("%s: probe A must be plaintext so a redirect is visible (§4.6)", ep.Name)
		}
	}
}

// TestDefaultClientDoesNotFollowRedirects exercises the client NewProber
// builds, rather than a test overriding it: the redirect policy is the whole
// mechanism by which a portal is detected, so it must not depend on the test
// harness setting it up.
func TestDefaultClientDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Write([]byte("login page"))
	}))
	defer srv.Close()

	p := NewProber(nil)
	p.Endpoints = []Endpoint{{Name: "e", URL: srv.URL + "/check", Status: http.StatusNoContent}}

	c := p.Probe(context.Background())
	if c.Check != CheckRedirect {
		t.Fatalf("Check = %v: the default client followed the redirect instead of reporting it", c.Check)
	}
	if c.Status != http.StatusFound {
		t.Errorf("Status = %d, want 302", c.Status)
	}
	if c.Redirect == "" {
		t.Error("probe C did not find the live redirect target")
	}
}
