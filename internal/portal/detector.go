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

	mu          sync.Mutex
	toldUnknown bool
}

// State returns the current state.
func (d *Detector) State() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Classifier.State()
}

// BlocksCarriers reports whether carriers must stay closed (§6.1).
func (d *Detector) BlocksCarriers() bool { return d.State().BlocksCarriers() }

// PortalURL is the login URL to show, in full, or "" when none was found
// (§4.5). The user needs its exact path and query; §4.7's redaction applies to
// what is persisted, not to what is displayed.
func (d *Detector) PortalURL() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Classifier.PortalURL
}

// Blocked is the state that §6.1 describes, for callers that want the
// explanation rather than the boolean.
func (d *Detector) Blocked() (state State, url string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Classifier.State(), d.Classifier.PortalURL
}

// Check runs one round now and applies it.
func (d *Detector) Check(ctx context.Context) State {
	ev := d.Prober.Probe(ctx)

	d.mu.Lock()
	before := d.Classifier.State()
	after := d.Classifier.Observe(ev.Evidence)
	host := d.Classifier.Host()

	// The exception to "log only changes" is an inconclusive verdict, which
	// §6.3 requires be reported even though it is also the startup state: a
	// client that cannot tell whether a portal exists must say so, because the
	// alternative is blaming the relay for the portal's behaviour. Reported
	// once per episode rather than on every cadence, and the flag clears when
	// the state does — so a network that goes inconclusive again is news again.
	reportInconclusive := after == StateUnknown && (before != StateUnknown || !d.toldUnknown)
	if after == StateUnknown {
		d.toldUnknown = true
	} else {
		d.toldUnknown = false
	}
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
	if d.Logger != nil && (notable || reportInconclusive) {
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
		if ev.DNSErr != nil {
			// Why probe B could not run, which is the difference between "the
			// resolver is honest" and "nobody measured it" (§4.4).
			args = append(args, "dns_error", ev.DNSErr.Error())
		}
		if host != "" {
			// The host only: a portal URL's path and query can carry a
			// per-device token, and this journal is what -share-diagnostics
			// uploads (§4.7).
			args = append(args, "portal_host", host)
		}
		if reportInconclusive {
			args = append(args, "advice", "carriers open; a failed handshake will confirm or refute a portal")
			d.Logger.Warn("portal state inconclusive", args...)
		} else {
			d.Logger.Info("portal state", args...)
		}
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

// Run keeps checking on the cadence §5 sets: the login poll while carriers are
// blocked, the steady cadence otherwise. It returns the last state it observed.
//
// It is the only scheduler in the package, so the startup gate and the
// mid-session watch cannot drift apart. Run watches: it keeps going until the
// context ends. A steady cadence of zero means "watch only for a login", which
// is what -portal-keepalive 0 asks for — it disables the expiry check and never
// the login poll — so Run returns once nothing is blocking.
//
// The cadences are the caller's policy — the flags are registered by the
// command — but the login backoff is not: it is the same rule everywhere, so it
// lives here.
func (d *Detector) Run(ctx context.Context, steady, login time.Duration) State {
	return d.run(ctx, steady, login, func(state State) bool {
		return steady == 0 && !state.BlocksCarriers()
	})
}

// Wait polls until the attachment is confirmed usable or the context ends, and
// returns the state that ended it. It is the startup gate's loop.
//
// Its finish condition is stricter than Run's: only a confirmed pass ends it.
// StateUnknown is fail-open for carriers (§6.3), but it is not proof a login
// happened — a portal that stopped answering looks the same — so treating it as
// a pass would open carriers into a portal behind a page that merely went
// quiet. The wait keeps polling through it, and -portal-wait is what bounds
// that.
//
// It polls on the login cadence whatever the state, because its only job is to
// notice a login: -portal-keepalive paces watching a live tunnel, and at the
// gate there is no tunnel yet.
func (d *Detector) Wait(ctx context.Context, login time.Duration) State {
	return d.run(ctx, login, login, func(state State) bool {
		return state == StateAuthenticated || state == StateNone
	})
}

// Usable reports whether the state is a confirmed pass: no portal, or one that
// was passed. It is the predicate Wait finishes on.
func (s State) Usable() bool { return s == StateNone || s == StateAuthenticated }

// run is the scheduler behind both entry points. done is consulted after each
// check to decide whether to stop early.
func (d *Detector) run(ctx context.Context, steady, login time.Duration, done func(State) bool) State {
	if steady < 0 {
		steady = 0
	}
	// The login cadence is the caller's -portal-poll, honoured as given: a
	// clamp here would silently ignore the flag. The documented floor and
	// ceiling apply to the *backoff* (see loginPollMax), not to a value the
	// operator chose.
	if login <= 0 {
		login = loginPollMin
	}

	next := d.Interval(steady, login)
	backoff := login
	started := time.Now()

	t := time.NewTimer(0) // check immediately: §5 runs at startup
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return d.State()
		case <-t.C:
		}

		state := d.Check(ctx)

		// A cancelled check is not an observation (§5.1): its state is
		// whatever it was, and acting on it would let a deadline decide the
		// verdict.
		if ctx.Err() != nil {
			return state
		}
		if done(state) {
			return state
		}

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
		if next <= 0 {
			// A zero cadence in the watch means "login only", which Run's done
			// has already handled; anything left to do would otherwise spin.
			return state
		}
		t.Reset(next)
	}
}

// Host returns the portal's host for logs and status lines, never the URL: a
// portal URL can carry a per-device token and the journal is uploaded under
// -share-diagnostics (§4.7). The user sees the full URL; the operator sees this.
func (d *Detector) Host() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Classifier.Host()
}
