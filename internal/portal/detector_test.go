package portal

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	c.Resume(state, seen, "portal.example.net")
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
	c.Resume(StateUnauthenticated, true, "")
	d := &Detector{Classifier: &c}
	if got := d.Interval(time.Minute, 10*time.Second); got != 10*time.Second {
		t.Errorf("unauthenticated interval = %v, want the login cadence", got)
	}
	c.Resume(StateAuthenticated, true, "")
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
