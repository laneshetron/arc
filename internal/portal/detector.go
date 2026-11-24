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

	// OnURL is called after a probe that changes the login URL, with the new
	// URL ("" when it was cleared), after OnChange. It is separate from
	// OnChange because a portal can move its login page — a new session token,
	// a different host — without the state changing, and the user still needs
	// the address that works now. It must not block.
	OnURL func(string)

	// RoundTimeout bounds one detection round; 0 uses DefaultRoundTimeout.
	RoundTimeout time.Duration

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

// RoundTimeout bounds one detection round. It is a field so tests can shorten
// it, and so a caller with an unusually slow link can raise it.
func (d *Detector) roundTimeout() time.Duration {
	if d.RoundTimeout > 0 {
		return d.RoundTimeout
	}
	return DefaultRoundTimeout
}

// DefaultRoundTimeout bounds a detection round: probe A (with one redirect
// follow), probe B's queries and the HTTPS check, each of which has a 5 s HTTP
// or 3 s DNS bound of its own. Fifteen seconds is comfortably more than the sum
// of a healthy round and still short enough that a stalled portal cannot hold
// the login wait indefinitely.
const DefaultRoundTimeout = 15 * time.Second

// Observation is the result of one detection round.
//
// Completed says the round's evidence was applied. A round ends one of three
// ways, and only the caller's cancellation leaves the state alone:
//
//   - it finishes: the evidence is applied.
//   - it exhausts its own budget (TimedOut): the evidence it gathered is applied
//     as it stands. Whatever probe A concluded before the budget ran out still
//     counts, and an endpoint that never answered within it is a no-answer —
//     which is what a link that silently drops everything looks like, and what
//     §5.1's three-timeouts rule needs to see. Discarding these rounds instead
//     left such a link in whatever state it was last in, indefinitely.
//   - the caller cancels it (Cancelled): nothing is applied. A request cut off
//     by Ctrl-C or the -portal-wait deadline looks exactly like one that timed
//     out on its own, and applying it would let the caller's deadline decide the
//     verdict (§5.1).
type Observation struct {
	State     State
	Check     Check
	Completed bool
	TimedOut  bool
	Cancelled bool
}

// Check runs one round and applies its evidence, returning the state afterwards.
//
// A round the caller cancels applies nothing: the state is whatever it was, and
// Observe's Cancelled reports why. Callers that care — the scheduler and the
// startup wait do — use Observe.
func (d *Detector) Check(ctx context.Context) State {
	return d.Observe(ctx).State
}

// Observe runs one round and applies its evidence unless the caller cancelled
// it.
//
// The round is bounded here rather than left to the HTTP client: its timeouts
// cover the response headers and the TLS handshake, but not a body that stalls
// after the headers arrive, and `io.LimitReader` bounds size rather than time.
// A portal — or a broken middlebox — that sends a header and then stops would
// otherwise hang the login wait or the steady watcher indefinitely.
func (d *Detector) Observe(ctx context.Context) Observation {
	outer := ctx
	ctx, cancel := context.WithTimeout(ctx, d.roundTimeout())
	defer cancel()

	ev := d.Prober.Probe(ctx)

	// The caller ending the round is not an observation. Its evidence is
	// indistinguishable from a real timeout, so applying it would let a
	// deadline or a Ctrl-C move the state — including toward `unknown`, which
	// opens carriers (§6.3).
	if outer.Err() != nil {
		return Observation{State: d.State(), Check: ev, Cancelled: true}
	}
	// The round's own budget running out is: the measurement had its full
	// allowance and this is what it found. See Observation.
	timedOut := ctx.Err() != nil

	d.mu.Lock()
	before := d.Classifier.State()
	urlBefore := d.Classifier.PortalURL
	after := d.Classifier.Observe(ev.Evidence)
	urlAfter := d.Classifier.PortalURL
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
		if timedOut {
			args = append(args, "round", "exhausted its budget")
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
	if urlBefore != urlAfter && d.OnURL != nil {
		d.OnURL(urlAfter)
	}
	return Observation{State: after, Check: ev, Completed: true, TimedOut: timedOut}
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
// blocked, the steady cadence otherwise. It returns the observation that
// stopped it — a completed one when `done` was satisfied, a cancelled one when
// the context ended mid-round.
//
// It is the only scheduler in the package, so the startup gate and the
// mid-session watch cannot drift apart. Run watches: it keeps going until the
// context ends. A steady cadence of zero means "watch only for a login", which
// is what -portal-keepalive 0 asks for — it disables the expiry check and never
// the login poll — so Run returns once nothing is blocking.
//
// Both cadences come from the caller's flags, including the login one: the
// watch passes -portal-poll, not a placeholder, so a client configured for a
// slower poll behaves the same mid-session as at the gate.
//
// The backoff ceiling and the minute-before-backoff are not the caller's: they
// are the same rule everywhere (§5), so they live here.
func (d *Detector) Run(ctx context.Context, steady, login time.Duration) Observation {
	return d.run(ctx, cadence{steady: steady, login: login}, func(state State) bool {
		return steady == 0 && !state.BlocksCarriers()
	})
}

// Wait polls until the attachment is not blocked, or the context ends, and
// returns the observation that ended it. It is the startup gate's loop.
//
// It finishes on any *completed* observation that does not block carriers, and
// that includes `unknown`. §6.3 is explicit about this: a client that cannot
// tell whether a portal exists proceeds with a warning, because refusing to
// start on "probably a portal" strands users on ordinary networks with broken
// middleboxes, and the first carrier failure then explains itself. Holding the
// gate on `unknown` instead — which an earlier revision did — means a portal
// that has been passed but whose canary now answers 503 waits forever, which is
// the failure §6.3 exists to prevent.
//
// The observation is returned rather than the bare state so the caller can tell
// a completed verdict from a cancelled one. That distinction is the whole
// reason this returns a struct: a round cut off by -portal-wait produces
// evidence indistinguishable from a real timeout, and Completed is what keeps a
// deadline from deciding the verdict.
//
// It polls on the login cadence whatever the state, because its only job is to
// notice a login: -portal-keepalive paces watching a live tunnel, and at the
// gate there is no tunnel yet.
func (d *Detector) Wait(ctx context.Context, login time.Duration) Observation {
	return d.run(ctx, cadence{steady: login, login: login}, func(state State) bool {
		return !state.BlocksCarriers()
	})
}

// Usable reports whether the state is a confirmed pass: no portal, or one that
// was passed. It is the predicate Wait finishes on.
func (s State) Usable() bool { return s == StateNone || s == StateAuthenticated }

// cadence is the two §5 intervals, normalized once.
type cadence struct {
	steady time.Duration
	login  time.Duration
}

// normalize fills in a login cadence the caller left unset and makes a negative
// steady cadence mean "no steady checks" rather than a timer that fires
// immediately and spins.
func (c cadence) normalize() cadence {
	if c.login <= 0 {
		c.login = loginPollMin
	}
	if c.steady < 0 {
		c.steady = 0
	}
	return c
}

// run is the scheduler behind both entry points. done is consulted after each
// completed observation to decide whether to stop early, and the observation
// that ended the loop is returned — including the cancelled one that stopped it
// without being applied.
func (d *Detector) run(ctx context.Context, c cadence, done func(State) bool) Observation {
	c = c.normalize()

	next := d.Interval(c.steady, c.login)
	// The backoff stretches from the login cadence toward loginPollMax, one
	// doubling per full minute *of the current episode* — the first a minute in,
	// the next a minute after that. It therefore has to be
	// measured from when this unauthenticated episode began, not from the last
	// non-captive observation — an episode that starts after a long authenticated
	// stretch must still begin at the fast cadence.
	backoff := c.login
	var episodeStart, lastStep time.Time

	t := time.NewTimer(0) // check immediately: §5 runs at startup
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return Observation{State: d.State()}
		case <-t.C:
		}

		obs := d.Observe(ctx)

		// The caller ending the round stops the loop: its evidence is
		// indistinguishable from a real timeout, so it must not move the state
		// or be read as a pass. A round that exhausted its own budget is a
		// completed observation and is treated like any other.
		if !obs.Completed || done(obs.State) {
			return obs
		}

		switch obs.State {
		case StateUnauthenticated:
			now := time.Now()
			switch {
			case episodeStart.IsZero():
				episodeStart, lastStep, backoff = now, now, c.login
			case now.Sub(lastStep) >= time.Minute:
				// One doubling per full minute, measured from the previous
				// doubling. Measuring each step from the episode's start would
				// double on every round once the first minute had passed.
				lastStep, backoff = now, min(backoff*2, loginPollMax)
			}
			next = backoff
		default:
			episodeStart, backoff = time.Time{}, c.login
			next = c.steady
		}
		if next <= 0 {
			// A zero cadence in the watch means "login only", which Run's done
			// has already handled; anything left to do would otherwise spin.
			return obs
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
