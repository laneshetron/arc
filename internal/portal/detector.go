package portal

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Detector is the client's portal state: a Prober feeding a Classifier, plus
// the keepalive loop of §5 that notices both a completed login and a lapsed
// grant.
//
// One Detector lives per network attachment. It is safe for concurrent use:
// the client calls State from whichever goroutine needs it, and the loop runs
// in its own.
type Detector struct {
	Prober     *Prober
	Classifier *Classifier
	Logger     *slog.Logger

	// OnChange is called after each probe that changes the state, with the
	// new state and the evidence. It must not block.
	OnChange func(State, Check)

	mu sync.Mutex
}

// State returns the current state.
func (d *Detector) State() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Classifier.State()
}

// BlocksCarriers reports whether carriers must stay closed (§6.1).
func (d *Detector) BlocksCarriers() bool { return d.State().BlocksCarriers() }

// PortalURL is the login URL to show, or "" when none was found (§4.5).
func (d *Detector) PortalURL() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Classifier.PortalHost
}

// Blocked is the state that §6.1 describes, for callers that want the
// explanation rather than the boolean.
func (d *Detector) Blocked() (state State, url string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Classifier.State(), d.Classifier.PortalHost
}

// Check runs one round now and applies it.
func (d *Detector) Check(ctx context.Context) State {
	ev := d.Prober.Probe(ctx)

	d.mu.Lock()
	before := d.Classifier.State()
	after := d.Classifier.Observe(ev.Evidence)
	d.mu.Unlock()

	// §4.7: the journal records evidence, never the URL. The endpoint, status,
	// body size and TLS outcome are what a maintainer needs to tell a portal
	// from a broken middlebox; the login URL may carry a session token.
	//
	// Logged when the state changes, or when something is worth knowing even
	// though it did not change it: an anomalous resolver verdict, or a TLS
	// failure under a passing check (§4.6). A healthy network that keeps
	// answering as expected logs nothing, so a journal stays readable.
	notable := before != after || ev.DNS == DNSAnomalous || ev.TLS != ""
	if d.Logger != nil && notable {
		args := []any{
			"state", after.String(),
			"was", before.String(),
			"endpoint", ev.Endpoint,
			"status", ev.Status,
			"body_bytes", ev.BodyBytes,
			"dns", ev.DNS.String(),
		}
		if ev.TLS != "" {
			args = append(args, "tls", ev.TLS)
		}
		if h := d.PortalURL(); h != "" {
			// The host only: a portal URL's path and query can carry a
			// per-device token (§4.7).
			args = append(args, "portal_host", h)
		}
		d.Logger.Info("portal state", args...)
	}

	if before != after && d.OnChange != nil {
		d.OnChange(after, ev)
	}
	return after
}

// Interval returns how long to wait before the next check, per §5's table:
// fast while waiting for a login, slow while watching for expiry.
func (d *Detector) Interval(steady time.Duration, login time.Duration) time.Duration {
	switch d.State() {
	case StateUnauthenticated:
		return login
	default:
		return steady
	}
}

// loginBackoff is how the unauthenticated poll stretches: ten seconds is how
// long a user expects their login to take effect, a minute is how long they
// will tolerate being told to wait (§5).
const (
	loginPollMin = 10 * time.Second
	loginPollMax = time.Minute
)

// Run keeps checking until ctx ends, calling Check on the cadence §5 sets.
//
// The cadences are the caller's policy — the flags are registered by the
// command — but the login backoff is not: it is the same rule everywhere, so
// it lives here.
func (d *Detector) Run(ctx context.Context, steady, login time.Duration) {
	if steady <= 0 {
		steady = time.Minute
	}
	if login <= 0 {
		login = loginPollMin
	}
	if login < loginPollMin {
		login = loginPollMin
	}
	if login > loginPollMax {
		login = loginPollMax
	}

	next := d.Interval(steady, login)
	backoff := login
	started := time.Now()

	t := time.NewTimer(0) // check immediately: §5 runs at startup
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		state := d.Check(ctx)

		// While unauthenticated the poll backs off from the login cadence to
		// the maximum, but resets whenever the state changes — so a user who
		// logs in and back out is noticed quickly again.
		if state == StateUnauthenticated {
			if time.Since(started) > time.Minute {
				backoff = min(backoff*2, loginPollMax)
			}
			next = backoff
		} else {
			backoff, started = login, time.Now()
			next = steady
		}
		t.Reset(next)
	}
}
