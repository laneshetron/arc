package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/portal"
	"github.com/laneshetron/arc/internal/tun"
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
		runPortalWatch(ctx, log, detectors, eligible, nil, portal.Config{Steady: 20 * time.Millisecond})
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

// TestAttachmentsResolveTheUnderlay is the macOS P1: with no -bind and no
// socket marks, an unbound probe follows the default route — which, once
// full-tunnel routing is installed, is the TUN. Detection would then measure
// ARC itself, and probe B would have no link to discover an upstream for.
func TestAttachmentsResolveTheUnderlay(t *testing.T) {
	orig := underlayInterface
	defer func() { underlayInterface = orig }()

	var asked int
	underlayInterface = func() (string, error) {
		asked++
		return "en0", nil
	}

	got, err := attachments(false, nil, testLogger())
	if err != nil {
		t.Fatalf("attachments = %v", err)
	}
	if len(got) != 1 || got[0] != (attachment{bind: "", iface: "en0"}) {
		t.Errorf("attachments = %v, want the resolved underlay", got)
	}
	if asked != 1 {
		t.Errorf("asked for the underlay %d times, want once", asked)
	}

	// An explicit bind is left alone: the user named the link.
	got, err = attachments(false, []string{"wlan0"}, testLogger())
	if err != nil {
		t.Fatalf("attachments = %v", err)
	}
	if len(got) != 1 || got[0] != (attachment{bind: "wlan0", iface: "wlan0"}) {
		t.Errorf("attachments = %v, want the explicit bind untouched", got)
	}
}

// TestAttachmentsResolveAnEmptyEntry covers a mixes case: -bind with an empty
// entry, which OpenCarriers resolves the same way.
func TestAttachmentsResolveAnEmptyEntry(t *testing.T) {
	orig := underlayInterface
	defer func() { underlayInterface = orig }()
	underlayInterface = func() (string, error) { return "en0", nil }

	got, err := attachments(false, []string{"", "wwan0"}, testLogger())
	if err != nil {
		t.Fatalf("attachments = %v", err)
	}
	want := []attachment{{bind: "", iface: "en0"}, {bind: "wwan0", iface: "wwan0"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("attachments = %v, want %v", got, want)
	}

	// The default route's interface named again is one attachment, not two
	// detectors racing each other's verdicts.
	got, err = attachments(false, []string{"", "en0"}, testLogger())
	if err != nil {
		t.Fatalf("attachments = %v", err)
	}
	if len(got) != 1 || got[0].iface != "en0" {
		t.Errorf("attachments = %v, want one en0 attachment", got)
	}
}

// TestAttachmentsToleratesAMissingUnderlay is the Linux-with-police-routing
// case: tun.Underlay returns "" and nothing fails, because the mark is what
// keeps traffic on the link.
func TestAttachmentsToleratesAMissingUnderlay(t *testing.T) {
	orig := underlayInterface
	defer func() { underlayInterface = orig }()
	underlayInterface = func() (string, error) { return "", nil }

	got, err := attachments(false, nil, testLogger())
	if err != nil {
		t.Fatalf("attachments = %v", err)
	}
	if len(got) != 1 || got[0] != (attachment{}) {
		t.Errorf("attachments = %v, want the unnamed default attachment", got)
	}
}

// TestPortalDetectorsNameTheirInterface is the journal follow-up: with two
// attachments, a line that does not say which one it is about cannot answer the
// question per-attachment detection exists for.
func TestPortalDetectorsNameTheirInterface(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		return buf.Write(p)
	}), nil))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}))
	defer srv.Close()

	detectors, _, _, err := checkPortal(context.Background(), log, portal.Config{
		Mode:     portal.CheckForce,
		ProbeURL: srv.URL,
		Expect:   portal.Expectation{Status: http.StatusNoContent},
	}, false, []string{"wlan0"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(detectors) != 1 {
		t.Fatalf("detectors = %d, want one", len(detectors))
	}
	for _, d := range detectors {
		d.Check(context.Background())
	}

	out := buf.String()
	if !strings.Contains(out, "wlan0") {
		t.Errorf("no journal line names the attachment:\n%s", out)
	}
}

// TestRunPortalWatchReportsAnExcludedAttachment is the review's admission
// finding, handled as a stated limitation: carriers are opened once, so a link
// that was captive at startup cannot join this session — but the user must hear
// about it, both while it blocks and when it recovers.
func TestRunPortalWatchReportsAnExcludedAttachment(t *testing.T) {
	var (
		mu      sync.Mutex
		logs    strings.Builder
		recover bool
	)
	isRecovered := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return recover
	}
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isRecovered() {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}), portal.StateUnauthenticated)

	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), nil))

	ctx, cancel := context.WithCancel(context.Background())
	detectors, excluded := oneAttachment(d)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPortalWatch(ctx, log, detectors, nil, excluded,
			portal.Config{Steady: 20 * time.Millisecond, Login: 20 * time.Millisecond})
	}()

	mu.Lock()
	recover = true
	mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for d.State() != portal.StateAuthenticated && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
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
	if !strings.Contains(out, "not carrying traffic") {
		t.Errorf("journal does not say the recovered attachment is excluded:\n%s", out)
	}
	if strings.Contains(out, "portal check passed") {
		t.Errorf("an excluded attachment's recovery was logged as a normal pass:\n%s", out)
	}
}

// TestRunPortalWatchPassesTheConfiguredLoginCadence guards the review's
// cadence finding: Run must be given -portal-poll, not a placeholder, or a
// client configured for a slower poll behaves differently mid-session than at
// the gate. The count of requests is what makes that observable.
func TestRunPortalWatchPassesTheConfiguredLoginCadence(t *testing.T) {
	var (
		mu     sync.Mutex
		probes int
	)
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		probes++
		mu.Unlock()
		http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
	}), portal.StateUnauthenticated)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	detectors, eligible := oneAttachment(d)
	// The watch waits one steady interval before starting, so that has to be
	// short. The assertion is about the *login* cadence: an unauthenticated
	// attachment polls at cfg.Login, and with the placeholder (0, normalized to
	// ten seconds) there would be one probe rather than several.
	go runPortalWatch(ctx, testLogger(), detectors, eligible, nil,
		portal.Config{Steady: 20 * time.Millisecond, Login: 30 * time.Millisecond})

	time.Sleep(250 * time.Millisecond)
	mu.Lock()
	n := probes
	mu.Unlock()
	if n < 3 {
		t.Errorf("probes = %d in 250ms at a 30ms login cadence; the watch is not using it", n)
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

// TestPortalGateHonoursCancellation means Ctrl-C during the wait exits promptly
// rather than sitting until the timeout, and says it was interrupted: "log in,
// then rerun" describes a deadline, not a user who chose to stop.
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
	if !errors.Is(err, context.Canceled) || isPortalBlocked(err) {
		t.Fatalf("err = %v, want the cancellation, not a portal-blocked error", err)
	}
}

// TestPortalGateProceedsOnUnknownWithAWarning is §6.3, which the earlier
// revision contradicted: an inconclusive verdict proceeds with a warning,
// because refusing to start on "probably a portal" strands users on ordinary
// networks with broken middleboxes. The distinction that must survive is
// cancellation — that is TestPortalWaitDeadlineDuringAProbeIsNotAPass.
func TestPortalGateProceedsOnUnknownWithAWarning(t *testing.T) {
	// An answered-but-wrong response: a mismatch, which classifies as unknown.
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}), portal.StateUnauthenticated)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	detectors, blocked := oneAttachment(d)
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := portal.Config{Login: 30 * time.Millisecond}
	passed, err := portalWaitMessage(ctx, detectors, blocked, cfg, log)
	if err != nil {
		t.Fatalf("portalWaitMessage = %v, want it to proceed: an inconclusive verdict is fail-open", err)
	}
	if len(passed) != 1 || passed[0] != "wlan0" {
		t.Errorf("passed = %v, want the attachment included", passed)
	}
	// Proceeding must not be sold as a login, which is the other half of the
	// review's point.
	if strings.Contains(logs.String(), "portal passed") {
		t.Errorf("logged a completed login for an inconclusive verdict:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "inconclusive") {
		t.Errorf("the journal does not say the verdict was inconclusive:\n%s", logs.String())
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
		d, eligible, _, err := checkPortal(context.Background(), testLogger(), portal.Config{Mode: tc.mode}, tc.fullTunnel, nil, 0)
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
	detectors, _, _, err := checkPortal(context.Background(), testLogger(), portal.Config{
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
	got := probeSocketOptions(false, mark, "en0")
	if got.Mark != 0 {
		t.Errorf("Mark = %#x without policy routing, want 0: Darwin rejects it", got.Mark)
	}
	if got.Device != "en0" {
		t.Errorf("Device = %q, want the link bound", got.Device)
	}

	// With policy routing (Linux full tunnel) the mark is what keeps the probe
	// out of the tunnel.
	got = probeSocketOptions(true, mark, "wlan0")
	if got.Device == "" {
		t.Error("Device empty: an unbound probe would follow the default route into the tunnel")
	}
}

// TestProbeSocketOptionsNeverBorrowABind is the review's binds[0] finding: the
// unnamed default attachment must not be probed out of another attachment's
// interface, which would give the default link that interface's verdict. ""
// survives only where the mark keeps the probe physical.
func TestProbeSocketOptionsNeverBorrowABind(t *testing.T) {
	if got := probeSocketOptions(true, 0x5243, ""); got.Device != "" {
		t.Errorf("Device = %q, want unbound: the default attachment has no interface of its own", got.Device)
	}
}

// TestCarrierBinds covers the two binding regressions: carriers open in the
// user's -bind order whatever order detection finished in, and a default
// attachment stays unnamed for the carriers unless they need its name — so
// split-tunnel carriers keep following the default route.
func TestCarrierBinds(t *testing.T) {
	atts := []attachment{{bind: "eth0", iface: "eth0"}, {bind: "", iface: "en0"}, {bind: "wlan0", iface: "wlan0"}}

	// Detection finished wlan0 first; the carriers must still lead with eth0.
	got := carrierBinds(atts, []string{"wlan0", "en0", "eth0"}, false)
	if want := []string{"eth0", "", "wlan0"}; !slices.Equal(got, want) {
		t.Errorf("carrierBinds = %q, want %q", got, want)
	}

	// Captive attachments are left out.
	got = carrierBinds(atts, []string{"wlan0"}, false)
	if want := []string{"wlan0"}; !slices.Equal(got, want) {
		t.Errorf("carrierBinds = %q, want %q", got, want)
	}

	// Where the carriers resolve the name themselves (full tunnel without
	// policy routing), the resolved name is what they would have used anyway.
	if !tun.PolicyRouting {
		got = carrierBinds(atts, []string{"en0"}, true)
		if want := []string{"en0"}; !slices.Equal(got, want) {
			t.Errorf("full tunnel: carrierBinds = %q, want %q", got, want)
		}
	}
}

// TestPortalWaitCtrlCIsNotAPass is the review's parent-cancellation finding: a
// round that completes as the user presses Ctrl-C must not start the client, and
// the exit must say it was interrupted rather than "log in, then rerun".
func TestPortalWaitCtrlCIsNotAPass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel() // Ctrl-C lands while this round is answering
		w.WriteHeader(http.StatusNoContent)
	}), portal.StateUnauthenticated)
	detectors, blocked := oneAttachment(d)

	passed, err := portalWaitMessage(ctx, detectors, blocked, portal.Config{Login: 10 * time.Millisecond}, testLogger())
	if len(passed) != 0 {
		t.Fatalf("passed = %v: a cancelled process started anyway", passed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the cancellation itself", err)
	}
	if isPortalBlocked(err) {
		t.Error("Ctrl-C reported as a portal block")
	}
}

// countingDetector is a portal detector that counts its probes.
func countingDetector(t *testing.T, state portal.State, status int) (*portal.Detector, func() int) {
	var (
		mu sync.Mutex
		n  int
	)
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		if status == http.StatusFound {
			http.Redirect(w, r, "http://127.0.0.1:1/login", http.StatusFound)
			return
		}
		w.WriteHeader(status)
	}), state)
	return d, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// TestRunPortalWatchCadencePerAttachment covers both P3s on the watch: with
// -portal-keepalive 0 an admitted attachment gets no watcher at all, and an
// excluded one starts on the login cadence rather than inheriting the steady
// one.
func TestRunPortalWatchCadencePerAttachment(t *testing.T) {
	admitted, admittedProbes := countingDetector(t, portal.StateNone, http.StatusNoContent)
	excluded, excludedProbes := countingDetector(t, portal.StateUnauthenticated, http.StatusFound)
	detectors := map[string]*portal.Detector{"eth0": admitted, "wlan0": excluded}

	for _, steady := range []time.Duration{0, time.Hour} {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		runPortalWatch(ctx, testLogger(), detectors, []string{"eth0"}, []string{"wlan0"},
			portal.Config{Steady: steady, Login: 20 * time.Millisecond})
		cancel()
	}
	if n := admittedProbes(); n != 0 {
		t.Errorf("admitted attachment probed %d times; keepalive 0 and an hour's cadence both mean none here", n)
	}
	if n := excludedProbes(); n < 2 {
		t.Errorf("excluded attachment probed %d times, want it on the 20ms login cadence", n)
	}
}

// TestRunPortalWatchReportsANewLoginURL is the review's URL finding: a portal
// that moves its login page without the state changing must still get its new
// address in front of the user.
func TestRunPortalWatchReportsANewLoginURL(t *testing.T) {
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><form><input type="password"></form></html>`)
	}))
	defer login.Close()

	var (
		mu   sync.Mutex
		sid  int
		logs strings.Builder
	)
	d := portalDetector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sid++
		n := sid
		mu.Unlock()
		http.Redirect(w, r, fmt.Sprintf("%s/login?sid=%d", login.URL, n), http.StatusFound)
	}), portal.StateUnauthenticated)
	d.Check(context.Background()) // the URL startup would have printed

	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), nil))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	detectors, excluded := oneAttachment(d)
	runPortalWatch(ctx, log, detectors, nil, excluded, portal.Config{Login: 20 * time.Millisecond})

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(logs.String(), "portal login page changed") {
		t.Errorf("a new login URL was not reported:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "sid=") {
		t.Error("the journal carries the URL's query; it must keep the host only (§4.7)")
	}
}
