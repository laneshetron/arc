package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/portal"
)

// portalDetector returns a detector whose endpoint is the given handler, with
// the classifier in the given state.
func portalDetector(t *testing.T, h http.Handler, state portal.State) *portal.Detector {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	p := portal.NewProber(nil)
	p.Endpoints = []portal.Endpoint{{Name: "e", URL: srv.URL + "/check", Status: http.StatusNoContent}}
	p.Client = srv.Client()
	p.Client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	var c portal.Classifier
	c.Resume(state, state != portal.StateNone)
	return &portal.Detector{Prober: p, Classifier: &c}
}

// oneAttachment wraps a single detector as the map and list the wait function
// takes.
func oneAttachment(d *portal.Detector) (map[string]*portal.Detector, []string) {
	return map[string]*portal.Detector{"wlan0": d}, []string{"wlan0"}
}

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestRunPortalWatchReportsExpiry is §5's keepalive: a grant that lapses
// mid-session must be visible as a portal, not as a dead relay. It also pins
// §7.1 — the watch only reports; nothing about the tunnel changes.
func TestRunPortalWatchReportsExpiry(t *testing.T) {
	var (
		mu      sync.Mutex
		expired bool
		logs    strings.Builder
	)
	isExpired := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return expired
	}
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isExpired() {
			http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), portal.StateUnknown)
	// Detection itself passed, so the watch starts from a healthy state. A
	// clean answer with a portal in this attachment's history classifies as
	// authenticated (§4.3.1), which is exactly the state §5's expiry check
	// exists for.
	if got := d.Check(context.Background()); got.BlocksCarriers() {
		t.Fatalf("initial state = %s, want a passing state", got)
	}

	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	detectors, eligible := oneAttachment(d)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPortalWatch(ctx, log, detectors, eligible, portal.Config{Steady: 20 * time.Millisecond})
	}()

	mu.Lock()
	expired = true
	mu.Unlock()

	// Three unanswered redirects is what makes the state unauthenticated
	// (§4.3.2), so give the loop a few cadences.
	deadline := time.Now().Add(2 * time.Second)
	for !d.BlocksCarriers() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !d.BlocksCarriers() {
		t.Fatal("state never became unauthenticated: the watch did not notice the expiry")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runPortalWatch did not return when the context ended")
	}

	mu.Lock()
	out := logs.String()
	mu.Unlock()
	if !strings.Contains(out, "requires a login") {
		t.Errorf("log = %q, want a warning that the network now requires a login", out)
	}
}

// writerFunc adapts a function to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TestPortalWaitPassesOnOneAttachment is the per-attachment rule again, now at
// the wait: a cellular link that recovered must not be held out by captive
// Wi-Fi, in either bind order, and the wait returns as soon as one passes.
func TestPortalWaitPassesOnOneAttachment(t *testing.T) {
	for _, order := range [][]string{{"wlan0", "wwan0"}, {"wwan0", "wlan0"}} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			captive := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
			}), portal.StateUnknown)
			healthy := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}), portal.StateUnknown)

			byIface := map[string]*portal.Detector{
				"wlan0": captive,
				"wwan0": healthy,
			}
			detectors := map[string]*portal.Detector{}
			for _, iface := range order {
				detectors[iface] = byIface[iface]
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			passed, err := portalWaitMessage(ctx, detectors, order, portal.Config{Login: 30 * time.Millisecond}, testLogger())
			if err != nil {
				t.Fatalf("portalWaitMessage = %v, want the healthy attachment to pass", err)
			}
			if len(passed) != 1 || passed[0] != "wwan0" {
				t.Errorf("passed = %v, want only wwan0", passed)
			}
		})
	}
}

// TestPortalWaitDeadlineDuringAProbeIsNotAPass is the review's cancellation
// case: -portal-wait expiring in the middle of a probe must not read the
// resulting unknown as a completed login.
func TestPortalWaitDeadlineDuringAProbeIsNotAPass(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang past the wait, then let the server shut down cleanly.
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), portal.StateUnauthenticated)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	detectors, blocked := oneAttachment(d)
	passed, err := portalWaitMessage(ctx, detectors, blocked, portal.Config{Login: 40 * time.Millisecond, Wait: 60 * time.Millisecond}, testLogger())
	if err == nil {
		t.Fatalf("passed = %v with no error: a probe cut off by the deadline is not a login", passed)
	}
	if !isPortalBlocked(err) {
		t.Errorf("err = %v, want a portal-blocked error", err)
	}
}

// TestPortalGateBlocksAndWaitsForLogin is §6.1 and §5 together: behind a
// portal the client does not proceed, and it proceeds by itself once the user
// logs in — which is what stops "reconnect by hand" from being the instruction.
func TestPortalGateBlocksAndWaitsForLogin(t *testing.T) {
	var (
		mu       sync.Mutex
		loggedIn bool
	)
	isLoggedIn := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return loggedIn
	}
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLoggedIn() {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}), portal.StateUnknown)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		time.Sleep(120 * time.Millisecond)
		mu.Lock()
		loggedIn = true
		mu.Unlock()
	}()

	detectors, blocked := oneAttachment(d)
	cfg := portal.Config{Login: 50 * time.Millisecond} // shortened for the test
	passed, err := portalWaitMessage(ctx, detectors, blocked, cfg, testLogger())
	if err != nil {
		t.Fatalf("portalWaitMessage = %v, want nil once the portal passes", err)
	}
	if len(passed) != 1 || passed[0] != "wlan0" {
		t.Errorf("passed = %v, want the attachment that recovered", passed)
	}
}

// TestPortalGateGivesUpAfterWait is the -portal-wait bound: a script must not
// hang behind a portal forever.
func TestPortalGateGivesUpAfterWait(t *testing.T) {
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}), portal.StateUnknown)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	detectors, blocked := oneAttachment(d)
	cfg := portal.Config{Login: 50 * time.Millisecond, Wait: 150 * time.Millisecond}
	err := func() error {
		_, e := portalWaitMessage(ctx, detectors, blocked, cfg, testLogger())
		return e
	}()
	if err == nil {
		t.Fatal("want an error when the wait expires")
	}
	if !isPortalBlocked(err) {
		t.Errorf("err = %v, want a portal-blocked error", err)
	}
	if !strings.Contains(err.Error(), "captive portal") {
		t.Errorf("err = %q, want it to say why", err)
	}
}

// TestPortalGateHonoursCancellation means Ctrl-C during the wait exits cleanly
// rather than sitting until the timeout.
func TestPortalGateHonoursCancellation(t *testing.T) {
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}), portal.StateUnknown)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	detectors, blocked := oneAttachment(d)
	cfg := portal.Config{Login: 50 * time.Millisecond}
	_, err := portalWaitMessage(ctx, detectors, blocked, cfg, testLogger())
	if !isPortalBlocked(err) {
		t.Fatalf("err = %v, want a portal-blocked error on cancellation", err)
	}
}

// TestPortalGateDoesNotTreatUnknownAsPassed is the bug the review caught: a
// poll that is cut off by the wait expiring leaves the state unknown, and
// unknown is fail-open — so reading "not blocking" as "passed" would open
// carriers into a portal.
func TestPortalGateDoesNotTreatUnknownAsPassed(t *testing.T) {
	// An endpoint that never answers: three polls make the state unknown.
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // a mismatch -> unknown
	}), portal.StateUnknown)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	detectors, blocked := oneAttachment(d)
	cfg := portal.Config{Login: 30 * time.Millisecond, Wait: 120 * time.Millisecond}
	passed, err := portalWaitMessage(ctx, detectors, blocked, cfg, testLogger())
	if err == nil {
		t.Fatalf("passed = %v with no error: an unresolved portal must not be treated as a login", passed)
	}
	if len(passed) != 0 {
		t.Errorf("passed = %v, want none", passed)
	}
}

// TestCheckPortalRespectsMode covers §8: off sends no probes, auto only with a
// tunnel, force always.
func TestCheckPortalRespectsMode(t *testing.T) {
	for _, tc := range []struct {
		mode       portal.CheckMode
		fullTunnel bool
		wantNil    bool
	}{
		{portal.CheckOff, true, true},
		{portal.CheckOff, false, true},
		{portal.CheckAuto, false, true},
	} {
		d, eligible, err := checkPortal(context.Background(), testLogger(), portal.Config{Mode: tc.mode}, tc.fullTunnel, nil, 0)
		if err != nil {
			t.Fatalf("%v: %v", tc.mode, err)
		}
		if (d == nil) != tc.wantNil {
			t.Errorf("mode %v, tunnel %v: detectors nil = %v, want %v", tc.mode, tc.fullTunnel, d == nil, tc.wantNil)
		}
		// With detection off the caller's binds pass through untouched.
		if tc.wantNil && len(eligible) != 0 {
			t.Errorf("mode %v: eligible = %v, want the caller's list unchanged", tc.mode, eligible)
		}
	}
}

// TestCheckPortalUsesTheCustomEndpoint is §4.1's rule that a custom probe needs
// its own criterion: the endpoint list must be replaced, not extended, and the
// substring must survive — without it, `200:Success` would accept a login page
// that also answered 200.
func TestCheckPortalUsesTheCustomEndpoint(t *testing.T) {
	detectors, _, err := checkPortal(context.Background(), testLogger(), portal.Config{
		Mode:     portal.CheckForce,
		ProbeURL: "http://portal.example/check",
		Expect:   portal.Expectation{Status: 200, Substr: "Success"},
	}, false, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(detectors) != 1 {
		t.Fatalf("detectors = %d, want one per attachment", len(detectors))
	}
	for _, d := range detectors {
		if got := len(d.Prober.Endpoints); got != 1 {
			t.Fatalf("endpoints = %d, want only the custom one", got)
		}
		ep := d.Prober.Endpoints[0]
		if ep.URL != "http://portal.example/check" || ep.Status != 200 {
			t.Errorf("endpoint = %+v, want the custom URL and its criterion", ep)
		}
		if ep.Substr != "Success" {
			t.Errorf("Substr = %q, want it carried from the expectation", ep.Substr)
		}
	}
}

// TestProbeSocketOptionsMatchCarriers is the macOS P1: a nonzero mark is
// rejected by sockopt.Apply on Darwin, so setting it unconditionally made every
// probe fail on the platform where detection matters most.
func TestProbeSocketOptionsMatchCarriers(t *testing.T) {
	const mark = 0x5243

	// Without policy routing (macOS, and Linux before the tunnel) there must be
	// no mark at all.
	got := probeSocketOptions(false, []string{"en0"}, mark, "en0")
	if got.Mark != 0 {
		t.Errorf("Mark = %#x without policy routing, want 0: Darwin rejects it", got.Mark)
	}
	if got.Device != "en0" {
		t.Errorf("Device = %q, want the link bound", got.Device)
	}

	// With policy routing (Linux full tunnel) the mark is what keeps the probe
	// out of the tunnel.
	got = probeSocketOptions(true, []string{"wlan0"}, mark, "wlan0")
	if got.Device == "" {
		t.Error("Device empty: an unbound probe would follow the default route into the tunnel")
	}
}

// TestProbeSocketOptionsFallBackToTheFirstBind covers a caller that names no
// interface for the attachment.
func TestProbeSocketOptionsFallBackToTheFirstBind(t *testing.T) {
	got := probeSocketOptions(false, []string{"en7", "en0"}, 0, "")
	if got.Device != "en7" {
		t.Errorf("Device = %q, want the first bind", got.Device)
	}
}
