// Package beacon applies §3.3's policy to what the exchange returns: which
// relays a device should try, in what order, and which to skip because the
// last attempt at them failed.
//
// The distinction this package exists to keep is §3.3's: a record that
// verifies gives a *candidate list*, not a relay to use. A valid, unexpired,
// correctly signed record can name a relay that is simply dead, and no
// amount of re-reading it will say so. Only a failed connection does that,
// so failure state lives here rather than in the record.
package beacon

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Candidate is one relay a device may try, with the reason it is offered.
type Candidate struct {
	Relay Relay
	// Enrolled is true when this relay came from the device's invite rather
	// than a beacon. §3.3 gives those precedence and §3.4 makes them
	// permanent: a beacon cannot displace a working enrolled endpoint, and
	// no beacon expiry retires one.
	Enrolled bool
	// Beacon is the beacon name this relay was published under, for a relay
	// learned from a beacon. It identifies which watermark and which
	// not_after govern the entry, and it is empty for an enrolled relay.
	Beacon string
	// NotAfter is when the operator stopped vouching for the record this
	// relay came from. Zero for an enrolled relay, which never expires.
	NotAfter time.Time
}

// Cooldown is the backoff schedule for a candidate that failed (§3.3): the
// first failure skips it for Base, and each repeated failure doubles that up
// to Max. A candidate that connects resets to nothing.
type Cooldown struct {
	Base time.Duration // default 5 minutes
	Max  time.Duration // default 1 hour
}

func (c Cooldown) base() time.Duration {
	if c.Base > 0 {
		return c.Base
	}
	return 5 * time.Minute
}

func (c Cooldown) max() time.Duration {
	if c.Max > 0 {
		return c.Max
	}
	return time.Hour
}

// delay is how long the nth consecutive failure skips a candidate.
func (c Cooldown) delay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	d := c.base()
	for range failures - 1 {
		d *= 2
		if d >= c.max() {
			return c.max()
		}
	}
	return min(d, c.max())
}

// failure is one candidate's retry state.
type failure struct {
	count int
	until time.Time
}

// List is the ordered set of relays a device will try, and the per-candidate
// retry state §3.3 requires. It is safe for concurrent use: a session
// goroutine reports outcomes while another asks what to try next.
type List struct {
	mu    sync.Mutex
	cands []Candidate
	state map[netip.AddrPort]failure
	cool  Cooldown
	now   func() time.Time
}

// NewList returns a List over cands, in the order given. Callers build that
// order per §3.3: the enrolled endpoint first, then each beacon name's
// relays in configured order.
func NewList(cands []Candidate, cool Cooldown, now func() time.Time) *List {
	if now == nil {
		now = time.Now
	}
	return &List{
		cands: append([]Candidate(nil), cands...),
		state: make(map[netip.AddrPort]failure),
		cool:  cool,
		now:   now,
	}
}

// Set replaces the candidate list, keeping the retry state of relays that
// appear in both. A re-query returns a new list every time and the client
// re-reads beacons hourly (§3.3); forgetting the failures at each re-read
// would retry a dead relay first on every rotation, which is exactly what
// the cooldown exists to prevent.
func (l *List) Set(cands []Candidate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cands = append([]Candidate(nil), cands...)
}

// Candidates returns the current list in order, including any that are
// cooling down.
func (l *List) Candidates() []Candidate {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Candidate(nil), l.cands...)
}

var (
	// ErrNoCandidate reports that every candidate is either absent or
	// cooling down.
	ErrNoCandidate = errors.New("beacon: no candidate available")
	// ErrExpired reports a beacon-only relay whose record has passed
	// not_after, which §3.4 retires for new connections.
	ErrExpired = errors.New("beacon: beacon-only relay expired")
)

// Next returns the first candidate worth trying now, skipping any that are
// cooling down or whose beacon has expired. It reports ErrNoCandidate when
// there is none, and the caller decides how to wait.
//
// Only expired *beacon-only* relays are skipped. §3.4 keeps an enrolled
// relay dialable forever, because that pin came from the invite and no
// beacon schedule may retire it — the property that stops a beacon outage
// from locking a device out.
func (l *List) Next() (Candidate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	expired := false
	for _, c := range l.cands {
		if !c.Enrolled && !c.NotAfter.IsZero() && !c.NotAfter.After(now) {
			expired = true
			continue
		}
		if f, ok := l.state[key(c.Relay)]; ok && now.Before(f.until) {
			continue
		}
		return c, nil
	}
	if expired {
		return Candidate{}, ErrExpired
	}
	return Candidate{}, ErrNoCandidate
}

// Failed records that a candidate could not be used — refused, handshake
// failure, or a session that died before it was stable (§3.3) — and starts
// or extends its cooldown.
func (l *List) Failed(c Candidate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := key(c.Relay)
	f := l.state[k]
	f.count++
	f.until = l.now().Add(l.cool.delay(f.count))
	l.state[k] = f
}

// Succeeded clears a candidate's cooldown, since a relay that connects is
// evidently alive.
func (l *List) Succeeded(c Candidate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.state, key(c.Relay))
}

// Failures reports how many consecutive failures a candidate has, which a
// journal records alongside the cooldown it implies.
func (l *List) Failures(c Candidate) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state[key(c.Relay)].count
}

// CooldownUntil reports when a candidate becomes eligible again, or the zero
// time if it is eligible now.
func (l *List) CooldownUntil(c Candidate) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state[key(c.Relay)].until
}

// key identifies a relay by its address. The port is not part of a Relay —
// §3.1 carries ports per endpoint — so the address alone is the identity a
// cooldown hangs on.
func key(r Relay) netip.AddrPort {
	return netip.AddrPortFrom(r.Addr.Unmap(), 0)
}

// FromBeacons builds the candidate list §3.3 describes from an enrolled
// relay and a set of verified beacons, in the order the caller supplies.
// Each beacon contributes its relays in publication order, after the
// enrolled endpoint.
//
// A relay that appears both enrolled and in a beacon is kept as the enrolled
// entry, because that is the stronger claim: it does not expire (§3.4) and a
// beacon must not be able to downgrade a pin.
func FromBeacons(enrolled *Candidate, beacons map[string]*Beacon, order []string) []Candidate {
	var out []Candidate
	seen := make(map[netip.AddrPort]bool)
	if enrolled != nil {
		out = append(out, *enrolled)
		seen[key(enrolled.Relay)] = true
	}
	for _, name := range order {
		b, ok := beacons[name]
		if !ok {
			continue
		}
		for _, r := range b.Relays {
			k := key(r)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, Candidate{
				Relay:    r,
				Beacon:   name,
				NotAfter: b.NotAfter,
			})
		}
	}
	return out
}

// Watermarks is the per-beacon-name rollback guard of §3.4: the newest
// `published` accepted for each name.
//
// It is per name, not per deployment, and that is load-bearing. `b1` can
// carry a newer publication naming a dead relay while `b2` carries an older
// but unexpired one naming the live standby; a shared watermark advanced by
// `b1` would discard `b2` as a rollback and never reach the relay that
// works. The records are signed independently and published at different
// times, so their clocks are not comparable.
type Watermarks struct {
	mu sync.Mutex
	at map[string]time.Time
}

// NewWatermarks returns a Watermarks seeded with previously persisted
// values, which may be nil.
func NewWatermarks(seed map[string]time.Time) *Watermarks {
	w := &Watermarks{at: make(map[string]time.Time, len(seed))}
	for k, v := range seed {
		w.at[k] = v
	}
	return w
}

// Accept reports whether a beacon published at published is at least as new
// as the newest already accepted for its name, and records it if so. §3.4
// makes this a refusal even for a record that verifies and has not expired,
// because otherwise a restart or a second device on the same profile would
// reopen the window in which the operator's previous rotation of that name
// is still valid.
func (w *Watermarks) Accept(name string, published time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if prev, ok := w.at[name]; ok && published.Before(prev) {
		return false
	}
	w.at[name] = published
	return true
}

// Snapshot returns the watermarks to persist. It is a copy, so the caller
// may write it to disk without holding the lock.
func (w *Watermarks) Snapshot() map[string]time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]time.Time, len(w.at))
	for k, v := range w.at {
		out[k] = v
	}
	return out
}

// Verify runs §3.3's acceptance checks on one content string and, on
// success, applies the rollback watermark for that beacon name. The order is
// signature, then not_after, then watermark, matching §3.3, and the
// watermark is written only after the first two pass — so an unsigned or
// expired record cannot advance it.
func Verify(content, name, suffix string, key []byte, now time.Time, w *Watermarks) (*Beacon, error) {
	b, err := Decode(content, suffix, key, now)
	if err != nil {
		return nil, err
	}
	if w != nil && !w.Accept(name, b.Published) {
		return nil, fmt.Errorf("%w: %s published %s", errRollback, name, b.Published.UTC().Format(time.RFC3339))
	}
	return b, nil
}

var errRollback = errors.New("beacon: older than the newest accepted for this name")

// SortedNames returns the beacon names in a stable order, so a candidate
// list built from a map is reproducible.
func SortedNames(m map[string]*Beacon) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
