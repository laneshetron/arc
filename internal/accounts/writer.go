package accounts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Writer lease defaults (§3.2).
const (
	DefaultLease   = 15 * time.Minute
	DefaultRenew   = time.Minute
	DefaultMargin  = time.Minute
	acquireBackoff = 5 * time.Second
)

var (
	// ErrNotWriter: this writer does not hold a live lease, so it may
	// neither commit nor authenticate.
	ErrNotWriter = errors.New("accounts: not the lease holder")
	// ErrUnavailable: the store could not be written; nothing changed.
	ErrUnavailable = errors.New("accounts: store unavailable")
)

// HeldError reports a lease that another holder has.
type HeldError struct{ Lease Lease }

func (e *HeldError) Error() string {
	return fmt.Sprintf("accounts: lease held by %s until %s", e.Lease.Holder, stamp(e.Lease.Expires))
}

// A Writer holds the writer lease on a Store and commits transactions
// to it (§3.2). Each commit, renewal, acquisition and release is one
// conditional write of the whole object, the lease in its header, so a
// writer whose lease was taken cannot commit. A Writer is safe for
// concurrent use.
type Writer struct {
	Store  Store
	Holder string        // this writer's identity in the lease
	Lease  time.Duration // default DefaultLease
	Renew  time.Duration // default DefaultRenew
	Margin time.Duration // subtracted from the lease for clock rate differences; default DefaultMargin
	Log    *slog.Logger
	// Cache, if set, is a local file rewritten with every committed
	// state, for inspection. It is never read back: the store is the
	// only source of truth.
	Cache string
	// OnState is called with each newly committed state whose records
	// changed (not for lease renewals alone), in commit order. OnLost is
	// called when the writer stops being the holder. Neither may call
	// back into the Writer.
	OnState func(*State)
	OnLost  func(error)
	// Seed, if set, gives the first state when the store is empty, such
	// as today's tokens file, migrated. Without it, an empty store starts
	// with no accounts.
	Seed func() (*State, error)
	// Now is the clock, for tests; nil uses time.Now.
	Now func() time.Time

	mu       sync.Mutex
	st       *State
	version  string
	token    string
	holding  bool
	deadline time.Time // by Now, past which this writer must not act as holder
}

func (w *Writer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Writer) lease() time.Duration  { return orDefault(w.Lease, DefaultLease) }
func (w *Writer) renew() time.Duration  { return orDefault(w.Renew, DefaultRenew) }
func (w *Writer) margin() time.Duration { return orDefault(w.Margin, DefaultMargin) }

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func (w *Writer) log() *slog.Logger {
	if w.Log == nil {
		return slog.Default()
	}
	return w.Log
}

// Serving reports whether this writer holds a live lease: only then may
// its relay authenticate new sessions (§3.2).
func (w *Writer) Serving() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.servingLocked()
}

func (w *Writer) servingLocked() bool { return w.holding && w.now().Before(w.deadline) }

// State returns the last committed state, or nil before the first
// acquisition. It must not be modified.
func (w *Writer) State() *State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st
}

// Acquire tries once to take the lease. It fails with a *HeldError if
// another holder's lease is live, ErrConflict if the store changed while
// it tried, or the store's error.
func (w *Writer) Acquire(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.acquireLocked(ctx, false)
}

// Takeover breaks the lease whoever holds it, for a holder known to be
// dead, and takes it.
func (w *Writer) Takeover(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.acquireLocked(ctx, true)
}

func (w *Writer) acquireLocked(ctx context.Context, force bool) error {
	data, version, err := w.Store.Get(ctx)
	var st *State
	switch {
	case errors.Is(err, ErrNotFound):
		st, version = &State{}, ""
		if w.Seed != nil {
			if st, err = w.Seed(); err != nil {
				return fmt.Errorf("accounts: seeding an empty store: %w", err)
			}
		}
	case err != nil:
		return err
	default:
		if st, err = Parse(data, w.now()); err != nil {
			return err
		}
	}
	// The same holder (this instance, restarted) may retake its own lease:
	// the lock its relay takes at start excludes a second process here.
	if l := st.Lease; !force && l.Held(w.now()) && l.Holder != w.Holder {
		return &HeldError{Lease: l}
	}
	var tok [16]byte
	rand.Read(tok[:])
	w.token = hex.EncodeToString(tok[:])
	w.st, w.version = st, version
	w.holding = true
	w.deadline = w.now().Add(w.lease() - w.margin()) // provisional; set by the write below
	if err := w.putLocked(ctx, st.Clone(), true); err != nil {
		w.holding = false
		return err
	}
	w.log().Info("accounts lease acquired", "holder", w.Holder, "generation", w.st.Generation)
	return nil
}

// Commit applies change to a copy of the current state and commits it.
// It returns ErrNotWriter without a live lease, ErrUnavailable if the
// store could not be written (nothing changed), and change's own error,
// or a validation error, without writing.
func (w *Writer) Commit(ctx context.Context, change func(*State) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.servingLocked() {
		return ErrNotWriter
	}
	next := w.st.Clone()
	if err := change(next); err != nil {
		return err
	}
	return w.putLocked(ctx, next, true)
}

// renewLocked extends the lease, committing the state unchanged.
func (w *Writer) renewLocked(ctx context.Context) error {
	if !w.servingLocked() {
		return ErrNotWriter
	}
	return w.putLocked(ctx, w.st.Clone(), false)
}

// putLocked writes next as the next generation, holding the lease, and
// on success makes it current. changed says whether to call OnState.
func (w *Writer) putLocked(ctx context.Context, next *State, changed bool) error {
	sent := w.now()
	next.Generation = w.st.Generation + 1
	next.Lease = Lease{Holder: w.Holder, Token: w.token, Expires: sent.Add(w.lease()).UTC().Truncate(time.Second)}
	next.Prune(sent)
	if err := next.Validate(); err != nil {
		return err
	}
	data := next.Marshal()
	version, err := w.Store.Put(ctx, data, w.version)
	if errors.Is(err, ErrConflict) {
		w.loseLocked(err)
		return ErrNotWriter
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	w.st, w.version = next, version
	// The lease in the store runs from no earlier than sent; Truncate
	// can only shorten it, and the margin covers clock rate differences.
	w.deadline = sent.Add(w.lease() - w.margin() - time.Second)
	if w.Cache != "" {
		if err := WriteFileAtomic(w.Cache, data); err != nil {
			w.log().Error("accounts cache not written; the store has the change", "file", w.Cache, "err", err)
		}
	}
	if changed && w.OnState != nil {
		w.OnState(next)
	}
	return nil
}

func (w *Writer) loseLocked(err error) {
	if !w.holding {
		return
	}
	w.holding = false
	w.log().Error("accounts lease lost", "holder", w.Holder, "err", err)
	if w.OnLost != nil {
		w.OnLost(err)
	}
}

// Release gives the lease up, for a clean shutdown, so a successor need
// not wait for it to expire.
func (w *Writer) Release(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.servingLocked() {
		return nil
	}
	next := w.st.Clone()
	next.Generation = w.st.Generation + 1
	next.Lease = Lease{}
	next.Prune(w.now())
	if _, err := w.Store.Put(ctx, next.Marshal(), w.version); err != nil {
		return err
	}
	w.holding = false
	return nil
}

// Run keeps the lease: it acquires it (retrying while another holds it
// or the store is unreachable), renews it, and, when it is lost, starts
// over. On return, when ctx is done, it releases the lease.
func (w *Writer) Run(ctx context.Context) {
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := w.Release(ctx); err != nil {
			w.log().Warn("accounts lease not released; a successor waits for it to expire", "err", err)
		}
	}()
	for ctx.Err() == nil {
		if err := w.Acquire(ctx); err != nil {
			wait := acquireBackoff
			var held *HeldError
			if errors.As(err, &held) {
				w.log().Warn("waiting for the accounts lease", "holder", held.Lease.Holder, "expires", held.Lease.Expires)
				wait = max(min(time.Until(held.Lease.Expires), w.renew()), acquireBackoff)
			} else {
				w.log().Warn("accounts lease not acquired", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		}
		w.hold(ctx)
	}
}

// hold renews the lease until it is lost or ctx is done.
func (w *Writer) hold(ctx context.Context) {
	tick := time.NewTicker(w.renew())
	defer tick.Stop()
	for {
		w.mu.Lock()
		holding, left := w.holding, w.deadline.Sub(w.now())
		w.mu.Unlock()
		if !holding {
			return
		}
		expire := time.NewTimer(max(left, 0))
		select {
		case <-ctx.Done():
			expire.Stop()
			return
		case <-expire.C:
			w.mu.Lock()
			if w.holding && !w.servingLocked() {
				w.loseLocked(errors.New("lease expired before it could be renewed"))
			}
			w.mu.Unlock()
		case <-tick.C:
			expire.Stop()
			w.mu.Lock()
			err := w.renewLocked(ctx)
			w.mu.Unlock()
			if err != nil && !errors.Is(err, ErrNotWriter) {
				w.log().Warn("accounts lease not renewed; serving until it expires", "err", err)
			}
		}
	}
}
