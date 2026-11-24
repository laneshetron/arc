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
	c.Resume(state, state != portal.StateNone, "")
	return &portal.Detector{Prober: p, Classifier: &c}
}

// TestPortalGateBlocksAndWaitsForLogin is §6.1 and §5 together: behind a
// portal the client does not proceed, and it proceeds by itself once the user
// logs in — which is the behaviour that stops "reconnect by hand" from being
// the instruction.
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

	// Log in shortly after the wait begins.
	go func() {
		time.Sleep(120 * time.Millisecond)
		mu.Lock()
		loggedIn = true
		mu.Unlock()
	}()

	cfg := portal.Config{Login: 50 * time.Millisecond} // shortened for the test
	if err := portalWaitMessage(ctx, d, cfg, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("portalWaitMessage = %v, want nil once the portal passes", err)
	}
	if d.BlocksCarriers() {
		t.Error("still blocking after the portal passed")
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

	cfg := portal.Config{Login: 50 * time.Millisecond, Wait: 150 * time.Millisecond}
	err := portalWaitMessage(ctx, d, cfg, slog.New(slog.DiscardHandler))
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

	cfg := portal.Config{Login: 50 * time.Millisecond}
	if err := portalWaitMessage(ctx, d, cfg, slog.New(slog.DiscardHandler)); !isPortalBlocked(err) {
		t.Fatalf("err = %v, want a portal-blocked error on cancellation", err)
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
		{portal.CheckAuto, true, false},
		{portal.CheckForce, false, false},
	} {
		d, err := checkPortal(slog.New(slog.DiscardHandler), portal.Config{Mode: tc.mode}, tc.fullTunnel, nil, 0, true)
		if err != nil {
			t.Fatalf("%v: %v", tc.mode, err)
		}
		if (d == nil) != tc.wantNil {
			t.Errorf("mode %v, tunnel %v: detector nil = %v, want %v", tc.mode, tc.fullTunnel, d == nil, tc.wantNil)
		}
	}
}

// TestCheckPortalUsesTheCustomEndpoint is §4.1's rule that a custom probe needs
// its own criterion: the endpoint list must be replaced, not extended.
func TestCheckPortalUsesTheCustomEndpoint(t *testing.T) {
	d, err := checkPortal(slog.New(slog.DiscardHandler), portal.Config{
		Mode:     portal.CheckForce,
		ProbeURL: "http://portal.example/check",
		Expect:   portal.Expectation{Status: 204},
	}, false, nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(d.Prober.Endpoints); got != 1 {
		t.Fatalf("endpoints = %d, want only the custom one", got)
	}
	ep := d.Prober.Endpoints[0]
	if ep.URL != "http://portal.example/check" || ep.Status != 204 {
		t.Errorf("endpoint = %+v, want the custom URL and its criterion", ep)
	}
}
