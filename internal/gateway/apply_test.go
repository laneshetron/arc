package gateway

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
)

func storeGateway(t *testing.T, st *accounts.State, gate func() bool) *Gateway {
	t.Helper()
	g, err := New(Config{Network: netip.MustParsePrefix("10.77.0.1/16"), TunMTU: 1280, Gate: gate})
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(st)
	return g
}

func twoAccounts(t *testing.T) (*accounts.State, []byte, []byte) {
	t.Helper()
	st := &accounts.State{}
	accounts.AddAccount(st, "a", true, 0)
	accounts.AddAccount(st, "b", false, 0)
	_, ta, err := accounts.AddToken(st, "a", "laptop", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, tb, _ := accounts.AddToken(st, "b", "phone", time.Now())
	return st, ta, tb
}

// TestApplyKeepsAccountIdentity: a lease granted before an update keeps
// its account through it, so refreshes and isolation still hold, and the
// account's new name and policy apply to it.
func TestApplyKeepsAccountIdentity(t *testing.T) {
	st, ta, tb := twoAccounts(t)
	g := storeGateway(t, st, nil)
	r, err := g.Authorize(ta, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := netip.AddrFrom4(r.IPv4)
	b := authorize(t, g, string(tb))
	if g.DeviceName(a) != "laptop" {
		t.Errorf("device %q", g.DeviceName(a))
	}

	next := st.Clone()
	acct := next.AccountByName("a")
	acct.Name, acct.RelayAccess = "renamed", false
	accounts.AddToken(next, "renamed", "desktop", time.Now())
	g.Apply(next)
	if _, err := g.Authorize(ta, nil, &r); err != nil {
		t.Errorf("refresh after an update: %v", err)
	}
	if g.AccountName(a) != "renamed" || g.allowTunnel(a, netip.MustParseAddr("10.77.0.1")) {
		t.Errorf("lease kept the old account's name or policy: %q", g.AccountName(a))
	}
	if g.allowForward(a, packet(a, b)) {
		t.Error("accounts not isolated after an update")
	}
	if len(g.Tokens()) != 0 {
		t.Error("store accounts exposed plaintext tokens")
	}
}

// TestApplyRevokes: a device removed by an update loses its lease: no
// refresh, no traffic either way, and a session not yet bound is refused.
func TestApplyRevokes(t *testing.T) {
	st, ta, tb := twoAccounts(t)
	g := storeGateway(t, st, nil)
	r, _ := g.Authorize(ta, nil, nil)
	a := netip.AddrFrom4(r.IPv4)
	b := authorize(t, g, string(tb))

	next := st.Clone()
	if _, err := accounts.Revoke(next, "a/laptop", time.Now()); err != nil {
		t.Fatal(err)
	}
	g.Apply(next)
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrBadCredential) {
		t.Errorf("revoked token authorized: %v", err)
	}
	if _, err := g.Authorize(ta, nil, &r); err == nil {
		t.Error("revoked token refreshed")
	}
	if g.Lookup(packet(b, a)) != nil || g.allowForward(b, packet(b, a)) {
		t.Error("traffic still reaches the revoked lease")
	}
	if !g.isRevoked(a) || g.isRevoked(b) {
		t.Error("wrong leases revoked")
	}
}

func TestKeyBinding(t *testing.T) {
	st, ta, _ := twoAccounts(t)
	key := make([]byte, 32)
	key[0] = 7
	st.Devices[0].Key = key
	g := storeGateway(t, st, nil)
	if _, err := g.Authorize(ta, make([]byte, 32), nil); !errors.Is(err, ErrWrongKey) {
		t.Errorf("token from another key: %v", err)
	}
	if _, err := g.Authorize(ta, key, nil); err != nil {
		t.Errorf("token from its key: %v", err)
	}
}

func TestGate(t *testing.T) {
	st, ta, _ := twoAccounts(t)
	serving := false
	g := storeGateway(t, st, func() bool { return serving })
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrNotServing) {
		t.Errorf("authorized while not serving: %v", err)
	}
	serving = true
	if _, err := g.Authorize(ta, nil, nil); err != nil {
		t.Error(err)
	}
}

// TestRevokeDuringAuthorize: an Apply that removes a device while its
// credential is being authorized either refuses the authorization or
// revokes the lease it grants; it never leaves a live lease behind.
func TestRevokeDuringAuthorize(t *testing.T) {
	st, ta, _ := twoAccounts(t)
	g := storeGateway(t, st, nil)
	next := st.Clone()
	if _, err := accounts.Revoke(next, "a/laptop", time.Now()); err != nil {
		t.Fatal(err)
	}
	applied := make(chan struct{})
	testHookAuthorize = func() {
		testHookAuthorize = nil
		go func() { g.Apply(next); close(applied) }()
		// Give the revocation every chance to land between finding the
		// credential and leasing the address.
		select {
		case <-applied:
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer func() { testHookAuthorize = nil }()
	r, err := g.Authorize(ta, nil, nil)
	<-applied
	if err == nil && !g.isRevoked(netip.AddrFrom4(r.IPv4)) {
		t.Fatal("a device revoked during its authorization holds a live lease")
	}
}

// stuckStore's writes hang until released.
type stuckStore struct {
	accounts.Store
	stuck   chan struct{}
	release chan struct{}
}

func (s *stuckStore) Put(ctx context.Context, data []byte, ifMatch string) (string, error) {
	if s.stuck != nil {
		close(s.stuck)
		s.stuck = nil
		<-s.release
	}
	return s.Store.Put(ctx, data, ifMatch)
}

// TestAuthorizeDuringStuckWrite: a store write that hangs does not hold
// up authorization, which asks the writer whether it serves.
func TestAuthorizeDuringStuckWrite(t *testing.T) {
	ctx := context.Background()
	store := &stuckStore{Store: accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	st, ta, _ := twoAccounts(t)
	w := &accounts.Writer{Store: store, Holder: "a", Seed: func() (*accounts.State, error) { return st, nil }}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	g := storeGateway(t, w.State(), w.Serving)
	store.stuck, store.release = make(chan struct{}), make(chan struct{})
	stuck := store.stuck
	done := make(chan error)
	go func() {
		done <- w.Commit(ctx, func(s *accounts.State) error { _, err := accounts.AddAccount(s, "c", false, 0); return err })
	}()
	<-stuck
	authorized := make(chan error)
	go func() { _, err := g.Authorize(ta, nil, nil); authorized <- err }()
	select {
	case err := <-authorized:
		if err != nil {
			t.Errorf("authorize during a stuck write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("authorize waited for the store")
	}
	if w.State() == nil {
		t.Error("no state during a stuck write")
	}
	close(store.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestStaleCredentialDuringAcquisition: a relay reacquiring the lease
// admits nobody until the store's state is applied, so a device revoked
// elsewhere while it held stale credentials is refused even while the
// acquisition hangs.
func TestStaleCredentialDuringAcquisition(t *testing.T) {
	ctx := context.Background()
	store := &stuckStore{Store: accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	st, ta, _ := twoAccounts(t)
	w := &accounts.Writer{Store: store, Holder: "a", Seed: func() (*accounts.State, error) { return st, nil }}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	g := storeGateway(t, w.State(), w.Serving)
	// Another writer takes over and revokes the device; this relay's
	// gateway still has its credential.
	other := &accounts.Writer{Store: store, Holder: "b"}
	if err := other.Takeover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := other.Commit(ctx, func(s *accounts.State) error { _, err := accounts.Revoke(s, "a/laptop", time.Now()); return err }); err != nil {
		t.Fatal(err)
	}
	if err := other.Release(ctx); err != nil {
		t.Fatal(err)
	}
	w.OnState = g.Apply
	store.stuck, store.release = make(chan struct{}), make(chan struct{})
	stuck := store.stuck
	done := make(chan error)
	go func() { done <- w.Acquire(ctx) }()
	<-stuck
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrNotServing) {
		t.Errorf("stale credential during a hung acquisition: %v", err)
	}
	close(store.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrBadCredential) {
		t.Errorf("revoked credential after acquiring: %v", err)
	}
}

// lossyStore's writes land but, while lossy, report failure; while
// blind, reads fail.
type lossyStore struct {
	accounts.Store
	lossy, blind bool
}

func (s *lossyStore) Put(ctx context.Context, data []byte, ifMatch string) (string, error) {
	v, err := s.Store.Put(ctx, data, ifMatch)
	if err == nil && s.lossy {
		return "", errors.New("connection reset")
	}
	return v, err
}

func (s *lossyStore) Get(ctx context.Context) ([]byte, string, error) {
	if s.blind {
		return nil, "", errors.New("store unreachable")
	}
	return s.Store.Get(ctx)
}

// TestUnresolvedRevocation: a revocation the store took without
// confirming, and that cannot be read back, leaves the relay admitting
// no one, the revoked device included, until it is resolved.
func TestUnresolvedRevocation(t *testing.T) {
	ctx := context.Background()
	store := &lossyStore{Store: accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	st, ta, tb := twoAccounts(t)
	w := &accounts.Writer{Store: store, Holder: "a", Seed: func() (*accounts.State, error) { return st, nil }}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	g := storeGateway(t, w.State(), w.Serving)
	w.OnState = g.Apply
	store.lossy, store.blind = true, true
	err := w.Commit(ctx, func(s *accounts.State) error { _, err := accounts.Revoke(s, "a/laptop", time.Now()); return err })
	if !errors.Is(err, accounts.ErrIndeterminate) {
		t.Fatalf("revocation: %v", err)
	}
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrNotServing) {
		t.Errorf("revoked device during an unresolved revocation: %v", err)
	}
	if _, err := g.Authorize(tb, nil, nil); !errors.Is(err, ErrNotServing) {
		t.Errorf("another device during an unresolved revocation: %v", err)
	}
	// Resolved by the next write, the revocation is found made.
	store.lossy, store.blind = false, false
	if err := w.Commit(ctx, func(*accounts.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrBadCredential) {
		t.Errorf("revoked device after resolution: %v", err)
	}
	if _, err := g.Authorize(tb, nil, nil); err != nil {
		t.Errorf("other device after resolution: %v", err)
	}
}

// TestResolutionAppliesBeforeAdmitting: once an unresolved revocation is
// found made, the relay keeps admitting no one until the gateway has the
// new credentials.
func TestResolutionAppliesBeforeAdmitting(t *testing.T) {
	ctx := context.Background()
	store := &lossyStore{Store: accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	st, ta, _ := twoAccounts(t)
	w := &accounts.Writer{Store: store, Holder: "a", Seed: func() (*accounts.State, error) { return st, nil }}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	g := storeGateway(t, w.State(), w.Serving)
	w.OnState = g.Apply
	store.lossy, store.blind = true, true
	if err := w.Commit(ctx, func(s *accounts.State) error { _, err := accounts.Revoke(s, "a/laptop", time.Now()); return err }); !errors.Is(err, accounts.ErrIndeterminate) {
		t.Fatalf("revocation: %v", err)
	}
	store.lossy, store.blind = false, false
	applying, apply := make(chan struct{}), make(chan struct{})
	var once sync.Once
	w.OnState = func(s *accounts.State) {
		once.Do(func() { close(applying); <-apply })
		g.Apply(s)
	}
	done := make(chan error)
	go func() { done <- w.Commit(ctx, func(*accounts.State) error { return nil }) }()
	<-applying
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrNotServing) {
		t.Errorf("revoked device while its revocation is being applied: %v", err)
	}
	close(apply)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrBadCredential) {
		t.Errorf("revoked device once applied: %v", err)
	}
}
