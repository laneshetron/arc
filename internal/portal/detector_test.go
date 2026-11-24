package portal

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"

	"strings"
	"sync"
	"testing"
	"time"
)

func newDetector(t *testing.T, h http.Handler, state State, seen bool) *Detector {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	p := NewProber(nil)
	p.Endpoints = []Endpoint{{Name: "e", URL: srv.URL + "/check", Status: http.StatusNoContent}}
	p.Client = srv.Client()
	p.Client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	var c Classifier
	c.Resume(state, seen)
	return &Detector{Prober: p, Classifier: &c}
}

// TestDetectorReportsTransitions checks that Check applies the classifier and
// fires OnChange, which is what the client uses to open or close carriers.
func TestDetectorReportsTransitions(t *testing.T) {
	var (
		mu      sync.Mutex
		changes []State
	)
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), StateUnauthenticated, true)
	d.OnChange = func(s State, _ Check) {
		mu.Lock()
		changes = append(changes, s)
		mu.Unlock()
	}

	if got := d.Check(context.Background()); got != StateAuthenticated {
		t.Fatalf("state = %v, want authenticated after a passing check with history", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(changes) != 1 || changes[0] != StateAuthenticated {
		t.Errorf("OnChange calls = %v, want one authenticated", changes)
	}
}

// TestDetectorBlockedCarriesTheURL is §6.1's contract for the client: when
// carriers are blocked, the URL to show comes with it.
func TestDetectorBlockedCarriesTheURL(t *testing.T) {
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://portal.example.net/login", http.StatusFound)
	}), StateUnknown, false)
	// The redirect target is not served, so probe C finds nothing: the state is
	// still unauthenticated, and the host comes from nowhere.
	if got := d.Check(context.Background()); got != StateUnauthenticated {
		t.Fatalf("state = %v, want unauthenticated", got)
	}
	if !d.BlocksCarriers() {
		t.Error("carriers should be blocked in unauthenticated")
	}
}

// TestDetectorInterval covers §5's two cadences: fast while waiting for a
// login, steady otherwise.
func TestDetectorInterval(t *testing.T) {
	var c Classifier
	c.Resume(StateUnauthenticated, true)
	d := &Detector{Classifier: &c}
	if got := d.Interval(time.Minute, 10*time.Second); got != 10*time.Second {
		t.Errorf("unauthenticated interval = %v, want the login cadence", got)
	}
	c.Resume(StateAuthenticated, true)
	if got := d.Interval(time.Minute, 10*time.Second); got != time.Minute {
		t.Errorf("authenticated interval = %v, want the steady cadence", got)
	}
}

// TestDetectorRunNoticesLogin is the §5 loop's whole purpose: a client sitting
// unauthenticated must notice a login it did not perform and unblock.
func TestDetectorRunNoticesLogin(t *testing.T) {
	var pass sync.Mutex
	loggedIn := false

	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pass.Lock()
		ok := loggedIn
		pass.Unlock()
		if ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}), StateUnknown, false)
	// Shorten the login cadence for the test; Run clamps to its minimum, so
	// the test waits that minimum rather than inventing a special case.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		d.Run(ctx, time.Minute, loginPollMin)
		close(done)
	}()

	// First check happens immediately and finds a portal.
	deadline := time.After(2 * time.Second)
	for d.State() != StateUnauthenticated {
		select {
		case <-deadline:
			t.Fatal("never reached unauthenticated")
		case <-time.After(10 * time.Millisecond):
		}
	}

	pass.Lock()
	loggedIn = true
	pass.Unlock()

	<-done // the run exits on ctx, which has expired by now
	// One more explicit check proves the transition the loop would have made.
	if got := d.Check(context.Background()); got != StateAuthenticated {
		t.Errorf("state = %v after login, want authenticated", got)
	}
}

// TestDetectorWaitNeedsAConfirmedPass is the startup gate's contract: unknown is
// fail-open for carriers (§6.3) but is not a login, so Wait keeps polling
// rather than letting a portal that went quiet open carriers into itself.
// TestDetectorRoundHasADeadline is the review's timing finding: a server that
// sends headers and then stalls the body must not hold the login wait forever.
// The HTTP client's own timeouts cover headers and the TLS handshake; the body
// is bounded by size, not time.
func TestDetectorRoundHasADeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // headers are through; the body never finishes
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	p := NewProber(nil)
	p.Client = srv.Client()
	p.Endpoints = []Endpoint{{Name: "e", URL: srv.URL, Status: http.StatusNoContent}}

	d := &Detector{Prober: p, Classifier: new(Classifier), RoundTimeout: 80 * time.Millisecond}
	start := time.Now()
	obs := d.Observe(context.Background())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Observe took %s: the round has no deadline", elapsed)
	}
	if !obs.Completed || !obs.TimedOut {
		t.Errorf("Completed = %v, TimedOut = %v: a round that exhausts its own budget is a completed observation", obs.Completed, obs.TimedOut)
	}
	if obs.Cancelled {
		t.Error("a round's own timeout reported as caller cancellation: one slow probe must not end the watch")
	}
}

// TestDetectorRepeatedRoundDeadlinesFailOpen is the review's stale-verdict
// finding: a link that silently drops everything never finishes a round inside
// its budget, and discarding those rounds left a captive attachment blocked
// forever after the user logged in. A round that exhausts its own budget is a
// no-answer, and three of them are §5.1's fail-open.
func TestDetectorRepeatedRoundDeadlinesFailOpen(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	p := NewProber(nil)
	p.Client = srv.Client()
	p.Endpoints = []Endpoint{{Name: "e", URL: srv.URL, Status: http.StatusNoContent}}

	c := new(Classifier)
	c.Resume(StateUnauthenticated, true)
	d := &Detector{Prober: p, Classifier: c, RoundTimeout: 60 * time.Millisecond}

	for i := 0; i < 2; i++ {
		d.Observe(context.Background())
	}
	if got := d.State(); got != StateUnauthenticated {
		t.Fatalf("state = %v after two stalled rounds, want unchanged: one or two lost rounds are not evidence", got)
	}
	d.Observe(context.Background())
	if got := d.State(); got != StateUnknown {
		t.Errorf("state = %v after three stalled rounds, want unknown (§5.1's three timeouts)", got)
	}
}

// stallingDNS is a probe B that never answers before the round ends.
type stallingDNS struct{}

func (stallingDNS) Honesty(ctx context.Context, _ string) (DNSVerdict, error) {
	<-ctx.Done()
	return DNSUnmeasured, ctx.Err()
}

// TestDetectorKeepsEvidenceFromATimedOutRound is the other half: conclusive
// evidence probe A already has is not thrown away because an auxiliary probe
// ran the round out.
func TestDetectorKeepsEvidenceFromATimedOutRound(t *testing.T) {
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}), StateNone, false)
	d.Prober.Resolver = stallingDNS{}
	d.RoundTimeout = 60 * time.Millisecond

	obs := d.Observe(context.Background())
	if !obs.TimedOut {
		t.Fatal("the round did not run out its budget; the test is not exercising the case")
	}
	if got := d.State(); got != StateUnauthenticated {
		t.Errorf("state = %v, want unauthenticated: probe A's redirect was conclusive before DNS stalled", got)
	}
}

// TestDetectorRunSurvivesASlowRound is the distinction between the round's own
// timeout and the caller ending: one stalled probe must not end the mid-session
// watch, which would leave the tunnel unwatched for the rest of its life.
func TestDetectorRunSurvivesASlowRound(t *testing.T) {
	var (
		mu      sync.Mutex
		stalled bool
		probes  int
	)
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		slow := stalled
		probes++
		mu.Unlock()
		if slow {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done() // stall the body past the round timeout
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), StateUnknown, false)
	d.RoundTimeout = 40 * time.Millisecond
	d.Logger = slog.New(slog.DiscardHandler)

	mu.Lock()
	stalled = true
	mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	d.Run(ctx, 20*time.Millisecond, 20*time.Millisecond)

	mu.Lock()
	n := probes
	mu.Unlock()
	// Run returns when ctx ends; the point is that it kept polling through the
	// stalled rounds rather than returning after the first one.
	if n < 3 {
		t.Errorf("probes = %d: Run stopped after a round timed out instead of retrying", n)
	}
}

// TestDetectorWaitReturnsInconclusive is §6.3, which the earlier revision's
// test contradicted: an inconclusive verdict ends a wait — a client that cannot
// tell proceeds with a warning — but it must come back marked as inconclusive,
// not as a login.
func TestDetectorWaitReturnsInconclusive(t *testing.T) {
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // mismatch -> unknown
	}), StateUnauthenticated, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := d.Wait(ctx, 10*time.Millisecond)
	if !got.Completed {
		t.Fatal("Wait returned an incomplete observation: it should have finished on a verdict")
	}
	if got.State != StateUnknown {
		t.Errorf("State = %v, want unknown", got.State)
	}
	if got.State.Usable() {
		t.Error("unknown reported as a confirmed pass")
	}
}

// TestDetectorWaitNeverAppliesACancelledRound is the cancellation half, and the
// one the review found: a round cut off by the deadline produces evidence that
// looks exactly like a timeout, so it must not become the verdict.
func TestDetectorWaitNeverAppliesACancelledRound(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blocked:
		case <-r.Context().Done():
		}
	}), StateUnauthenticated, false)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	got := d.Wait(ctx, 10*time.Millisecond)
	if got.Completed {
		t.Fatal("Wait reported a completed observation after cancellation")
	}
	if got.State != StateUnauthenticated {
		t.Errorf("State = %v, want the state it had: a cancelled round applies nothing", got.State)
	}
}

// TestDetectorCheckDoesNotApplyACancelledRound is the same guarantee one level
// down, where it is actually enforced.
func TestDetectorCheckDoesNotApplyACancelledRound(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blocked:
		case <-r.Context().Done():
		}
	}), StateAuthenticated, true)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	obs := d.Observe(ctx)
	if obs.Completed {
		t.Fatal("Observe applied a cancelled round")
	}
	if !obs.Cancelled {
		t.Error("Cancelled = false for a round cut off by the caller")
	}
	if got := d.State(); got != StateAuthenticated {
		t.Errorf("state = %v after a cancelled round, want it unchanged", got)
	}
}

// TestDetectorWaitReturnsOnAPass covers the other end: once the check passes,
// Wait stops rather than polling to the deadline.
func TestDetectorWaitReturnsOnAPass(t *testing.T) {
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), StateUnknown, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if got := d.Wait(ctx, 10*time.Millisecond); !got.State.Usable() {
		t.Fatalf("Wait = %v, want a usable state", got.State)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Wait took %s: it polled past a pass", elapsed)
	}
}

// TestDetectorRunWithNoSteadyCadenceWatchesOnlyForALogin is the -portal-keepalive
// 0 case: the expiry check is off, but Run still notices a login, because a
// client that cannot notice a login is broken (§5, §8).
func TestDetectorRunWithNoSteadyCadenceWatchesOnlyForALogin(t *testing.T) {
	var (
		mu   sync.Mutex
		open bool
	)
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ok := open
		mu.Unlock()
		if ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}), StateUnknown, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan Observation, 1)
	go func() { done <- d.Run(ctx, 0, 10*time.Millisecond) }()

	// The first check finds the portal and Run must keep going: a zero steady
	// cadence disables the expiry check, never the login poll.
	deadline := time.After(2 * time.Second)
	for d.State() != StateUnauthenticated {
		select {
		case <-deadline:
			t.Fatal("never reached unauthenticated")
		case <-time.After(5 * time.Millisecond):
		}
	}
	mu.Lock()
	open = true
	mu.Unlock()

	select {
	case got := <-done:
		if !got.State.Usable() {
			t.Errorf("Run returned %v, want a usable state once the login completed", got.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run never returned a passing state with a zero steady cadence")
	}
}

// TestDetectorAccessors covers the small readers the client uses for display.
func TestDetectorAccessors(t *testing.T) {
	portalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><form><input type="password" name="pw"></form></html>`))
	}))
	defer portalSrv.Close()
	want := portalSrv.URL + "/login?ref=T"

	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, want, http.StatusFound)
	}), StateUnknown, false)

	d.Check(context.Background())
	if got := d.PortalURL(); got != want {
		t.Errorf("PortalURL = %q, want the full login URL %q for display", got, want)
	}
	wantHost := strings.TrimPrefix(portalSrv.URL, "http://")
	if got := d.Host(); got != wantHost {
		t.Errorf("Host = %q, want just the host %q for the journal", got, wantHost)
	}
	state, url := d.Blocked()
	if state != StateUnauthenticated || url != want {
		t.Errorf("Blocked = (%v, %q), want unauthenticated with the URL", state, url)
	}
	if !d.BlocksCarriers() {
		t.Error("BlocksCarriers = false behind a portal")
	}
	if got := d.Interval(time.Minute, 10*time.Second); got != 10*time.Second {
		t.Errorf("Interval = %v, want the login cadence while unauthenticated", got)
	}
}

// TestDetectorLogsEvidenceNotURL is §4.7: the journal records the evidence and
// the portal host, never the URL, because a portal URL's query carries a
// per-device token and the journal is what -share-diagnostics uploads.
func TestDetectorLogsEvidenceNotURL(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/login?ref=SECRET-TOKEN", http.StatusFound)
	}), StateUnknown, false)
	d.Logger = logger

	d.Check(context.Background())

	out := buf.String()
	if out == "" {
		t.Fatal("nothing was logged")
	}
	if strings.Contains(out, "SECRET-TOKEN") {
		t.Errorf("journal contains the portal URL's query, which can carry a token:\n%s", out)
	}
	if !strings.Contains(out, "state=unauthenticated") {
		t.Errorf("journal does not record the state:\n%s", out)
	}
}

// TestDetectorQuietWhenNothingChanges keeps a healthy network's journal free of
// repeated lines.
func TestDetectorQuietWhenNothingChanges(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), StateNone, false)
	d.Logger = logger

	d.Check(context.Background()) // none -> none
	if got := buf.String(); got != "" {
		t.Errorf("logged on an unchanged healthy check:\n%s", got)
	}
}

// TestDetectorReportsInconclusiveOnce is §6.3 plus the review's observation:
// an inconclusive verdict must be reported — a client that cannot tell whether a
// portal exists must say so, or it blames the relay for the portal's behaviour —
// but reporting it on every cadence would bury the journal, so it is reported
// once per episode.
func TestDetectorReportsInconclusiveOnce(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// A mismatch: answered, but not as declared and not a redirect (§4.3.2).
	d := newDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}), StateUnknown, false)
	d.Logger = logger

	for i := 0; i < 3; i++ {
		if got := d.Check(context.Background()); got != StateUnknown {
			t.Fatalf("check %d: state = %v, want unknown", i, got)
		}
	}

	out := buf.String()
	if n := strings.Count(out, "portal state inconclusive"); n != 1 {
		t.Errorf("reported an inconclusive state %d times, want once per episode:\n%s", n, out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("the inconclusive verdict was not a warning:\n%s", out)
	}
	if !strings.Contains(out, "status=503") {
		t.Errorf("the warning does not carry the evidence that produced it:\n%s", out)
	}
}

// TestDetectorUnmeasurableDNSIsReported is the other half of that observation:
// "nobody measured the resolver" must be distinguishable from "the resolver is
// honest", which is what DNSErr carries.
func TestDetectorUnmeasurableDNSIsReported(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}))
	defer srv.Close()

	p := NewProber(nil)
	p.Client = srv.Client()
	p.Client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p.Endpoints = []Endpoint{{Name: "e", URL: srv.URL, Status: http.StatusNoContent}}
	p.Resolver = &UpstreamResolver{Discover: func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("no resolvectl here")
	}}

	d := &Detector{Prober: p, Classifier: new(Classifier), Logger: logger}
	d.Check(context.Background())

	out := buf.String()
	if !strings.Contains(out, "dns_error=") {
		t.Errorf("journal does not say why DNS was unmeasured:\n%s", out)
	}
	if !strings.Contains(out, "no resolvectl here") {
		t.Errorf("journal does not carry the discovery error:\n%s", out)
	}
}
