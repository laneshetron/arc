package accounts

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxStateSize bounds the serialized accounts (§3.2): the caps keep
// them well under it, and a commit that would pass it is refused, so a
// store never holds accounts too large to read back.
const MaxStateSize = 1 << 20

var maxStateSize = MaxStateSize // for tests

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
	// ErrIndeterminate: the store did not confirm a write and could not
	// be read back to tell whether it has it. The writer resolves it,
	// by reading the store, before its next write.
	ErrIndeterminate = errors.New("accounts: the store did not confirm the write, which may or may not have been made")
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
// concurrent use; Serving and State never wait for the store.
type Writer struct {
	Store  Store
	Holder string        // this writer's name in the lease, for operators
	Lease  time.Duration // default DefaultLease
	Renew  time.Duration // default DefaultRenew
	Margin time.Duration // subtracted from the lease for clock rate differences; default DefaultMargin
	Log    *slog.Logger
	// TokenFile, if set, keeps the token of this writer's lease, so that
	// a writer restarted on the same host can retake its own live lease
	// instead of waiting for it to expire. It must be private to one
	// writer at a time, as a file in the directory Control locks is. A
	// holder's name alone never proves a lease is its own.
	TokenFile string
	// Cache, if set, is a local file rewritten with every committed
	// state, for inspection. It is never read back: the store is the
	// only source of truth.
	Cache string
	// OnState is called with each newly committed state whose records
	// changed (not for lease renewals alone), in commit order. OnLost is
	// called when the writer stops being the holder. Neither may call
	// back into the Writer, except Serving and State.
	OnState func(*State)
	OnLost  func(error)
	// Seed, if set, gives the first state when the store is empty, such
	// as today's tokens file, migrated. Without it, an empty store starts
	// with no accounts.
	Seed func() (*State, error)
	// Now is the clock, for tests; nil uses time.Now.
	Now func() time.Time

	// mu serializes the store's writes, and with them every field below
	// but the atomics, which publish what Serving and State read.
	mu        sync.Mutex
	st        *State
	version   string
	token     string
	pending   *pendingWrite // a write whose outcome is unknown
	acquiring bool

	cur atomic.Pointer[State]
	// serveUntil is the end of serving by the monotonic clock (mono), or
	// 0 when not the holder. Local validity never follows the wall clock:
	// a clock stepped back must not extend it. Only the lease in the
	// store, read by other relays, is a wall-clock time.
	serveUntil atomic.Int64
	unresolved atomic.Bool          // a changed write's outcome is unknown: see Serving
	mono       func() time.Duration // for tests; nil uses monotonic time since start
}

// A pendingWrite is a write the store neither confirmed nor refused.
type pendingWrite struct {
	data    []byte
	next    *State
	sent    time.Time     // by the wall clock, for the lease in the store
	sentAt  time.Duration // by the monotonic clock, for serving
	changed bool
	acquire bool // an acquisition: once made, it starts serving
	cause   error
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
// its relay authenticate new sessions (§3.2). It does not wait for a
// write in progress.
//
// It is false, though the lease is live, while an accounts change is
// unresolved (ErrIndeterminate): the relay's credentials may be stale,
// a revoked device's among them, so it admits no one until the store's
// state is known again. Sessions already open stay up.
func (w *Writer) Serving() bool { return w.live() && !w.unresolved.Load() }

// live reports whether this writer's lease is unexpired by its clock.
func (w *Writer) live() bool {
	d := w.serveUntil.Load()
	return d != 0 && int64(w.monoNow()) < d
}

// setPending records the write whose outcome is unknown, or none.
func (w *Writer) setPending(p *pendingWrite) {
	w.pending = p
	w.unresolved.Store(p != nil && p.changed && p.cause != nil)
}

// holding reports whether this writer considers itself the holder,
// whether or not its deadline has passed.
func (w *Writer) holding() bool { return w.serveUntil.Load() != 0 }

var started = time.Now()

// monoNow reads the monotonic clock.
func (w *Writer) monoNow() time.Duration {
	if w.mono != nil {
		return w.mono()
	}
	return time.Since(started)
}

// remaining returns how long until this writer stops serving.
func (w *Writer) remaining() time.Duration {
	return time.Duration(w.serveUntil.Load()) - w.monoNow()
}

// State returns the last committed state, or nil before the first
// acquisition. It must not be modified. It does not wait for a write in
// progress.
func (w *Writer) State() *State { return w.cur.Load() }

func (w *Writer) setState(st *State, version string) {
	w.st, w.version = st, version
	w.cur.Store(st)
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
	if err == nil && w.pending != nil && bytes.Equal(data, w.pending.data) {
		// An acquisition the store did not confirm, made after all.
		w.pending.acquire = true
		w.adoptLocked(version)
		w.log().Info("accounts lease acquired", "holder", w.Holder, "generation", w.st.Generation)
		return nil
	}
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
	w.setPending(nil)
	if l := st.Lease; !force && l.Held(w.now()) && !w.ownLease(l) {
		return &HeldError{Lease: l}
	}
	var tok [16]byte
	rand.Read(tok[:])
	w.token = hex.EncodeToString(tok[:])
	// Serving stays off until the write below is in the store and its
	// state applied: until then the relay's credentials may be stale.
	w.serveUntil.Store(0)
	w.setState(st, version)
	w.acquiring = true
	err = w.putLocked(ctx, st.Clone(), true)
	w.acquiring = false
	if err != nil {
		return err
	}
	w.log().Info("accounts lease acquired", "holder", w.Holder, "generation", w.st.Generation)
	return nil
}

// ownLease reports whether l is this writer's own: its token is this
// writer's, or, from before a restart, the one TokenFile kept.
func (w *Writer) ownLease(l Lease) bool {
	if l.Token == "" {
		return false
	}
	if l.Token == w.token {
		return true
	}
	if w.TokenFile == "" {
		return false
	}
	data, err := os.ReadFile(w.TokenFile)
	return err == nil && strings.TrimSpace(string(data)) == l.Token
}

func (w *Writer) saveToken() {
	if w.TokenFile == "" {
		return
	}
	if err := WriteFileAtomic(w.TokenFile, []byte(w.token+"\n")); err != nil {
		w.log().Warn("accounts lease token not saved; after a restart the relay waits for its lease to expire", "file", w.TokenFile, "err", err)
	}
}

// Commit applies change to a copy of the current state and commits it.
// It returns ErrNotWriter without a live lease, ErrUnavailable if the
// store refused the write or could not be reached (nothing changed),
// ErrIndeterminate if it is unknown whether the store has the change,
// and change's own error, or a validation error, without writing.
func (w *Writer) Commit(ctx context.Context, change func(*State) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.resolveLocked(ctx); err != nil {
		return err
	}
	if !w.live() {
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
	if err := w.resolveLocked(ctx); err != nil {
		return err
	}
	if !w.live() {
		return ErrNotWriter
	}
	return w.putLocked(ctx, w.st.Clone(), false)
}

// putLocked writes next as the next generation, holding the lease, and
// on success makes it current. changed says whether to call OnState.
func (w *Writer) putLocked(ctx context.Context, next *State, changed bool) error {
	sent, sentAt := w.now(), w.monoNow()
	next.Generation = w.st.Generation + 1
	next.Lease = Lease{Holder: w.Holder, Token: w.token, Expires: sent.Add(w.lease()).UTC().Truncate(time.Second)}
	next.Prune(sent)
	if err := next.Validate(); err != nil {
		return err
	}
	data := next.Marshal()
	if len(data) > maxStateSize {
		return fmt.Errorf("accounts: the change would make the accounts %d bytes, over the %d-byte limit", len(data), maxStateSize)
	}
	version, err := w.Store.Put(ctx, data, w.version)
	switch {
	case errors.Is(err, ErrConflict):
		// A store's client may retry a write it already made, which then
		// fails its own condition: the store having exactly these bytes
		// means it was this write.
		w.setPending(&pendingWrite{data: data, next: next, sent: sent, sentAt: sentAt, changed: changed, acquire: w.acquiring, cause: err})
		cur, version, gerr := w.Store.Get(ctx)
		switch {
		case gerr != nil && !errors.Is(gerr, ErrNotFound):
			return fmt.Errorf("%w: %v; reading the store back: %v", ErrIndeterminate, err, gerr)
		case gerr == nil && bytes.Equal(cur, data):
			w.log().Warn("accounts write confirmed by reading the store back", "generation", next.Generation, "err", err)
			w.adoptLocked(version)
			return nil
		}
		w.setPending(nil)
		w.lose(err)
		return ErrNotWriter
	case err != nil:
		// A store can keep a write whose response is lost: read it back.
		w.setPending(&pendingWrite{data: data, next: next, sent: sent, sentAt: sentAt, changed: changed, acquire: w.acquiring, cause: err})
		return w.resolveLocked(ctx)
	}
	w.setPending(&pendingWrite{data: data, next: next, sent: sent, sentAt: sentAt, changed: changed, acquire: w.acquiring})
	w.adoptLocked(version)
	return nil
}

// resolveLocked settles a pending write by reading the store: the write
// was made if the store has exactly its bytes, and was not if the store
// is unchanged. Without a pending write, it does nothing.
func (w *Writer) resolveLocked(ctx context.Context) error {
	p := w.pending
	if p == nil {
		return nil
	}
	data, version, err := w.Store.Get(ctx)
	switch {
	case err != nil && !errors.Is(err, ErrNotFound):
		return fmt.Errorf("%w: %v; reading the store back: %v", ErrIndeterminate, p.cause, err)
	case err == nil && bytes.Equal(data, p.data):
		w.log().Warn("accounts write confirmed by reading the store back", "generation", p.next.Generation, "err", p.cause)
		w.adoptLocked(version)
		return nil
	case version == w.version && (err == nil || w.version == ""):
		w.setPending(nil)
		return fmt.Errorf("%w: %v", ErrUnavailable, p.cause)
	}
	// Neither: another writer changed the store, so this one lost the
	// lease, perhaps after its write was made.
	w.setPending(nil)
	w.lose(errors.New("the store changed while a write was unconfirmed"))
	return fmt.Errorf("%w: %v; the store has since changed, and this relay lost the accounts lease", ErrIndeterminate, p.cause)
}

// adoptLocked makes the pending write, now known to be in the store at
// version, current.
func (w *Writer) adoptLocked(version string) {
	p := w.pending
	w.setPending(nil)
	w.setState(p.next, version)
	w.saveToken()
	if w.Cache != "" {
		if err := WriteFileAtomic(w.Cache, p.data); err != nil {
			w.log().Error("accounts cache not written; the store has the change", "file", w.Cache, "err", err)
		}
	}
	// The relay has the state before it serves by it.
	if p.changed && w.OnState != nil {
		w.OnState(p.next)
	}
	// The lease in the store runs from no earlier than sent; Truncate
	// can only shorten it, and the margin covers clock rate differences.
	until := max(int64(p.sentAt+w.lease()-w.margin()-time.Second), 1)
	if p.acquire {
		w.serveUntil.Store(until)
		return
	}
	// A writer that already gave up the lease (it expired while the
	// write was in flight) stays given up: its sessions are closed.
	if old := w.serveUntil.Load(); old != 0 {
		w.serveUntil.CompareAndSwap(old, until)
	}
}

// lose makes this writer stop being the holder, once: it may run
// without the lock, from expire.
func (w *Writer) lose(err error) {
	for {
		d := w.serveUntil.Load()
		if d == 0 {
			return
		}
		if w.serveUntil.CompareAndSwap(d, 0) {
			break
		}
	}
	w.log().Error("accounts lease lost", "holder", w.Holder, "err", err)
	if w.OnLost != nil {
		w.OnLost(err)
	}
}

// Release gives the lease up, for a clean shutdown, so a successor need
// not wait for it to expire. It stops serving, closing the relay's
// sessions, before it writes: if the write is lost after the store took
// it, a successor may already serve.
func (w *Writer) Release(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.resolveLocked(ctx); err != nil {
		return err
	}
	if !w.live() {
		return nil
	}
	w.lose(errors.New("lease released"))
	next := w.st.Clone()
	next.Generation = w.st.Generation + 1
	next.Lease = Lease{}
	next.Prune(w.now())
	version, err := w.Store.Put(ctx, next.Marshal(), w.version)
	if err != nil {
		// Whether or not the store took it, this writer no longer serves;
		// the next acquisition reads the store afresh.
		return fmt.Errorf("accounts: releasing the lease: %w", err)
	}
	w.setState(next, version)
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
		if w.live() {
			// Taken meanwhile, by an operator's takeover (Do).
			w.hold(ctx)
			continue
		}
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

// hold renews the lease until it is lost or ctx is done. Expiry is
// watched apart from renewal, which waits for the lock, so a write stuck
// in the store cannot keep the relay's sessions open past the lease.
func (w *Writer) hold(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go w.watch(ctx)
	tick := time.NewTicker(w.renew())
	defer tick.Stop()
	for w.holding() {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.mu.Lock()
			err := w.renewLocked(ctx)
			w.mu.Unlock()
			if err != nil && !errors.Is(err, ErrNotWriter) {
				w.log().Warn("accounts lease not renewed; serving until it expires", "err", err)
			}
		}
	}
}

// watch ends the lease at its deadline, which renewals move, until it
// is lost or ctx is done. It never takes the lock.
func (w *Writer) watch(ctx context.Context) {
	for w.holding() {
		t := time.NewTimer(max(w.remaining(), 0))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			w.expire()
		}
	}
}

// expire ends serving once the deadline passes. It does not wait for a
// write in progress, so the relay's sessions close on time even while
// the store hangs.
func (w *Writer) expire() {
	if w.holding() && !w.live() {
		w.lose(errors.New("lease expired before it could be renewed"))
	}
}
