package accounts

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// clock is a settable time for writers under test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestMigrateTokensFile(t *testing.T) {
	st, err := Parse([]byte("lane tokA relay\nfriend tokB\n# comment\nbare\nlane tokC relay\n"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 0 || len(st.Accounts) != 3 || len(st.Devices) != 4 {
		t.Fatalf("migrated %d accounts, %d devices: %s", len(st.Accounts), len(st.Devices), st.Marshal())
	}
	lane := st.AccountByName("lane")
	if lane == nil || !lane.RelayAccess || st.AccountByName("line4") == nil || st.AccountByName("friend").RelayAccess {
		t.Fatalf("accounts %s", st.Marshal())
	}
	devs := st.DevicesOf(lane.ID)
	if len(devs) != 2 || devs[0].Name != "legacy-1" || devs[1].Name != "legacy-2" || devs[0].Bound() ||
		devs[0].TokenHash != TokenHash([]byte("tokA")) || devs[0].Front != FrontVerifier([]byte("tokA")) || !devs[0].Created.Equal(t0) {
		t.Errorf("lane's devices %+v", devs)
	}
	for _, bad := range []string{"lane tokA\nlane tokA\n", "lane tokA relay\nlane tokB\n", "a b c d\n", "bad/name tok\n", "x tok opt\n"} {
		if _, err := Parse([]byte(bad), t0); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRecordsRoundTrip(t *testing.T) {
	a := &Account{ID: NewID(), Name: "alexei", MaxDevices: 5, Invites: true, Manage: false}
	root := &Device{ID: NewID(), Account: a.ID, Name: "laptop", TokenHash: TokenHash([]byte("t1")), Front: FrontVerifier([]byte("t1")),
		Key: make([]byte, 32), Created: t0}
	inv := &Invite{ID: NewID(), Account: a.ID, SecretHash: [32]byte{1}, Front: [16]byte{2}, Expires: t0.Add(time.Hour),
		By: root.ID, Request: NewID(), Gen: 9, Redeemed: NewID()}
	child := &Device{ID: inv.Redeemed, Account: a.ID, Name: "desktop", TokenHash: TokenHash([]byte("t2")), Lineage: []ID{root.ID}, Via: inv.ID, Created: t0}
	st := &State{Generation: 42, Lease: Lease{Holder: "relay-1", Token: "abcd", Expires: t0.Add(15 * time.Minute)},
		Accounts: []*Account{a, {ID: NewID(), Name: "lane", RelayAccess: true, MaxDevices: 16, Invites: false, Manage: true}},
		Devices:  []*Device{root, child},
		Invites:  []*Invite{inv, {ID: NewID(), Account: a.ID, Expires: t0}},
		Revoked:  []*Tombstone{{ID: NewID(), Until: t0.Add(TombstoneLife), By: root.ID, Rest: "device x y z token=00 extra=1"}, {ID: NewID(), Until: t0}},
	}
	data := st.Marshal()
	got, err := Parse(data, t0)
	if err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	if again := got.Marshal(); string(again) != string(data) {
		t.Errorf("round trip changed it:\n%s\n---\n%s", data, again)
	}
	if got.Lease != st.Lease || got.Generation != 42 || got.Devices[1].Lineage[0] != root.ID || got.Accounts[0].Manage ||
		got.Revoked[0].Rest != st.Revoked[0].Rest {
		t.Errorf("parsed %+v", got)
	}
}

func TestValidate(t *testing.T) {
	base := func() *State {
		a := &Account{ID: NewID(), Name: "a", MaxDevices: 1}
		return &State{Accounts: []*Account{a}, Devices: []*Device{{ID: NewID(), Account: a.ID, Name: "d", TokenHash: [32]byte{1}, Created: t0}}}
	}
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*State){
		"over the cap": func(s *State) {
			s.Devices = append(s.Devices, &Device{ID: NewID(), Account: s.Accounts[0].ID, Name: "e", TokenHash: [32]byte{2}})
		},
		"no account":   func(s *State) { s.Devices[0].Account = NewID() },
		"cap too high": func(s *State) { s.Accounts[0].MaxDevices = MaxDevicesLimit + 1 },
		"deep lineage": func(s *State) { s.Devices[0].Lineage = make([]ID, MaxLineage+1) },
		"short key":    func(s *State) { s.Devices[0].Key = []byte{1} },
		"repeated token": func(s *State) {
			s.Accounts[0].MaxDevices = 2
			s.Devices = append(s.Devices, &Device{ID: NewID(), Account: s.Accounts[0].ID, Name: "e", TokenHash: [32]byte{1}})
		},
	} {
		s := base()
		f(s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
}

func TestFileStoreConditionalWrites(t *testing.T) {
	ctx := context.Background()
	fs := FileStore{Path: filepath.Join(t.TempDir(), "accounts")}
	if _, _, err := fs.Get(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: %v", err)
	}
	if _, err := fs.Put(ctx, []byte("a"), "nope"); !errors.Is(err, ErrConflict) {
		t.Fatalf("put to a missing object with a version: %v", err)
	}
	v1, err := fs.Put(ctx, []byte("a"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Put(ctx, []byte("b"), ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("create over an existing object: %v", err)
	}
	v2, err := fs.Put(ctx, []byte("b"), v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Put(ctx, []byte("c"), v1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if data, v, _ := fs.Get(ctx); string(data) != "b" || v != v2 {
		t.Fatalf("got %q %s", data, v)
	}
}

func newWriter(t *testing.T, store Store, holder string, c *clock) *Writer {
	t.Helper()
	return &Writer{Store: store, Holder: holder, Now: c.Now}
}

func TestWriterLease(t *testing.T) {
	ctx := context.Background()
	store := FileStore{Path: filepath.Join(t.TempDir(), "accounts")}
	c := &clock{t: t0}
	var published []*State
	a := newWriter(t, store, "a", c)
	a.TokenFile = filepath.Join(t.TempDir(), "lease-token")
	a.OnState = func(s *State) { published = append(published, s) }
	a.Seed = func() (*State, error) { return Parse([]byte("lane tok relay\n"), c.Now()) }
	if err := a.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.Serving() || len(published) != 1 || a.State().Generation != 1 || a.State().AccountByName("lane") == nil {
		t.Fatalf("after acquiring: serving %v, %d published, %s", a.Serving(), len(published), a.State().Marshal())
	}

	// Another holder waits while the lease is live.
	b := newWriter(t, store, "b", c)
	var held *HeldError
	if err := b.Acquire(ctx); !errors.As(err, &held) || held.Lease.Holder != "a" {
		t.Fatalf("second holder: %v", err)
	}
	// A holder's name proves nothing: another writer named a waits.
	if err := newWriter(t, store, "a", c).Acquire(ctx); !errors.As(err, &held) {
		t.Fatalf("same name took a live lease: %v", err)
	}
	// The same writer, restarted, retakes its own by the token it kept.
	a2 := newWriter(t, store, "a", c)
	a2.TokenFile = a.TokenFile
	if err := a2.Acquire(ctx); err != nil {
		t.Fatalf("restarted holder: %v", err)
	}
	// Which leaves the old a unable to commit: the object changed.
	if err := a.Commit(ctx, func(s *State) error { _, err := AddAccount(s, "x", false, 0); return err }); !errors.Is(err, ErrNotWriter) || a.Serving() {
		t.Fatalf("stale writer committed: %v", err)
	}

	// Renewal keeps a2 serving past the first lease's end.
	c.Add(10 * time.Minute)
	a2.mu.Lock()
	if err := a2.renewLocked(ctx); err != nil {
		t.Fatal(err)
	}
	a2.mu.Unlock()
	c.Add(10 * time.Minute)
	if !a2.Serving() {
		t.Fatal("renewed writer not serving")
	}
	// Unrenewed, it stops serving before the lease in the store ends, so
	// no successor can start while it still serves.
	c.Add(DefaultLease - DefaultMargin - 10*time.Minute)
	if a2.Serving() {
		t.Fatal("serving past its deadline")
	}
	if err := a2.Commit(ctx, func(*State) error { return nil }); !errors.Is(err, ErrNotWriter) {
		t.Fatalf("expired writer committed: %v", err)
	}
	if err := b.Acquire(ctx); !errors.As(err, &held) {
		t.Fatalf("lease taken before it expired in the store: %v", err)
	}
	c.Add(DefaultMargin)
	if err := b.Acquire(ctx); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// TestTakeoverFencesPreparedCommit: a writer whose lease is broken by a
// takeover cannot commit a change it had prepared before.
func TestTakeoverFencesPreparedCommit(t *testing.T) {
	ctx := context.Background()
	store := FileStore{Path: filepath.Join(t.TempDir(), "accounts")}
	c := &clock{t: t0}
	a := newWriter(t, store, "a", c)
	lost := 0
	a.OnLost = func(error) { lost++ }
	if err := a.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	cli := newWriter(t, store, "cli", c)
	err := a.Commit(ctx, func(s *State) error {
		// The takeover lands between preparing and writing.
		if err := cli.Takeover(ctx); err != nil {
			t.Fatal(err)
		}
		_, err := AddAccount(s, "late", false, 0)
		return err
	})
	if !errors.Is(err, ErrNotWriter) || lost != 1 {
		t.Fatalf("commit after takeover: %v, lost %d", err, lost)
	}
	data, _, _ := store.Get(ctx)
	if strings.Contains(string(data), "late") {
		t.Fatal("the fenced commit reached the store")
	}
	if err := cli.Release(ctx); err != nil {
		t.Fatal(err)
	}
	b := newWriter(t, store, "b", c)
	if err := b.Acquire(ctx); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

// failingStore fails writes while down.
type failingStore struct {
	Store
	down bool
}

func (f *failingStore) Put(ctx context.Context, data []byte, ifMatch string) (string, error) {
	if f.down {
		return "", errors.New("store unreachable")
	}
	return f.Store.Put(ctx, data, ifMatch)
}

func TestStoreOutage(t *testing.T) {
	ctx := context.Background()
	store := &failingStore{Store: FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	c := &clock{t: t0}
	w := newWriter(t, store, "a", c)
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	store.down = true
	err := w.Commit(ctx, func(s *State) error { _, err := AddAccount(s, "x", false, 0); return err })
	if !errors.Is(err, ErrUnavailable) || w.State().AccountByName("x") != nil {
		t.Fatalf("commit during outage: %v", err)
	}
	// Shorter than the lease, an outage leaves the relay serving.
	c.Add(DefaultLease / 2)
	if !w.Serving() {
		t.Fatal("not serving during a short outage")
	}
	store.down = false
	if err := w.Commit(ctx, func(s *State) error { _, err := AddAccount(s, "x", false, 0); return err }); err != nil {
		t.Fatal(err)
	}
}

func TestOps(t *testing.T) {
	st := &State{}
	if _, err := AddAccount(st, "alexei", false, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := AddAccount(st, "alexei", false, 0); err == nil {
		t.Error("added an account twice")
	}
	_, tok, err := AddToken(st, "alexei", "", t0)
	if err != nil || !ValidToken(tok) || len(tok) != 43 {
		t.Fatalf("token %q: %v", tok, err)
	}
	if _, _, err := AddToken(st, "alexei", "laptop", t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddToken(st, "alexei", "third", t0); err == nil {
		t.Error("past the device cap")
	}
	if !strings.Contains(List(st), "device-1") {
		t.Errorf("list:\n%s", List(st))
	}
	if _, err := Revoke(st, "alexei/device-1", t0); err != nil {
		t.Fatal(err)
	}
	if len(st.Devices) != 1 || len(st.Revoked) != 1 || !st.Revoked[0].Until.Equal(t0.Add(TombstoneLife)) {
		t.Errorf("after revoke: %s", st.Marshal())
	}
	if _, err := RemoveAccount(st, "alexei", t0); err != nil || len(st.Accounts)+len(st.Devices) != 0 || len(st.Revoked) != 2 {
		t.Errorf("after remove (%v): %s", err, st.Marshal())
	}
}

func TestControlSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	ctl := Control{Dir: filepath.Join(dir, "ctl")}
	unlock, err := ctl.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Lock(); !errors.Is(err, ErrLocked) {
		t.Errorf("second lock: %v", err)
	}
	if _, err := ctl.Send(Request{Op: "list"}); !errors.Is(err, ErrNoRelay) {
		t.Errorf("send with no relay: %v", err)
	}
	w := &Writer{Store: FileStore{Path: filepath.Join(dir, "accounts")}, Holder: "a"}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	go ctl.Serve(ctx, w)
	var resp Response
	for range 100 {
		if resp, err = ctl.Send(Request{Op: "add", Args: []string{"alexei"}}); !errors.Is(err, ErrNoRelay) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || resp.Error != "" {
		t.Fatalf("add: %v %+v", err, resp)
	}
	if resp, _ = ctl.Send(Request{Op: "add-token", Args: []string{"alexei", "laptop"}}); resp.Error != "" || resp.Token == "" {
		t.Fatalf("add-token: %+v", resp)
	}
	if resp, _ = ctl.Send(Request{Op: "list"}); !strings.Contains(resp.Output, "laptop") {
		t.Errorf("list: %+v", resp)
	}
	if resp, _ = ctl.Send(Request{Op: "frobnicate"}); resp.Error == "" {
		t.Error("unknown op accepted")
	}
	unlock()
}

// lossyStore's writes reach the store but, while lossy, report failure,
// as a request whose response was lost does; while blind, reads fail too.
type lossyStore struct {
	Store
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

// TestUnconfirmedWrite: a write the store kept but did not confirm is
// confirmed by reading it back, or, if it cannot be read, reported as
// indeterminate, never as not made; the next write resolves it first,
// so retrying does not repeat the change.
func TestUnconfirmedWrite(t *testing.T) {
	ctx := context.Background()
	store := &lossyStore{Store: FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	c := &clock{t: t0}
	w := newWriter(t, store, "a", c)
	published := 0
	w.OnState = func(*State) { published++ }
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	add := func(name string) error {
		return w.Commit(ctx, func(s *State) error { _, err := AddAccount(s, name, false, 0); return err })
	}

	store.lossy = true
	if err := add("x"); err != nil || w.State().AccountByName("x") == nil || published != 2 {
		t.Fatalf("write read back: %v, published %d", err, published)
	}

	store.blind = true
	resp := Do(ctx, w, Request{Op: "add-token", Args: []string{"x", "laptop"}}, t0)
	if !strings.Contains(resp.Error, "may or may not") || !ValidToken([]byte(resp.Token)) {
		t.Fatalf("unconfirmed add-token: %+v", resp)
	}
	if !w.Serving() {
		t.Fatal("an unconfirmed write ended serving")
	}
	if err := add("y"); !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("commit over an unresolved write: %v", err)
	}
	// Once the store can be read, the device is found made: the token
	// handed out is its, and adding it again is refused, not repeated.
	store.lossy, store.blind = false, false
	token := resp.Token
	resp = Do(ctx, w, Request{Op: "add-token", Args: []string{"x", "laptop"}}, t0)
	if !strings.Contains(resp.Error, "already has a device laptop") {
		t.Fatalf("retried add-token: %+v", resp)
	}
	if d := w.State().device(w.State().AccountByName("x").ID, "laptop"); d == nil || d.TokenHash != TokenHash([]byte(token)) {
		t.Fatal("the device found is not the one whose token was handed out")
	}
}

// stuckStore's writes hang until released.
type stuckStore struct {
	Store
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

// TestStuckWrite: a write that hangs in the store blocks neither Serving
// nor State, and the lease still ends on time, closing sessions, while
// the write hangs.
func TestStuckWrite(t *testing.T) {
	ctx := context.Background()
	store := &stuckStore{Store: FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	c := &clock{t: t0}
	w := newWriter(t, store, "a", c)
	lost := make(chan error, 1)
	w.OnLost = func(err error) { lost <- err }
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	store.stuck, store.release = make(chan struct{}), make(chan struct{})
	stuck := store.stuck
	done := make(chan error)
	go func() {
		done <- w.Commit(ctx, func(s *State) error { _, err := AddAccount(s, "x", false, 0); return err })
	}()
	<-stuck
	answered := make(chan bool)
	go func() { answered <- w.Serving() && w.State() != nil }()
	select {
	case ok := <-answered:
		if !ok {
			t.Error("not serving during a stuck write")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serving waited for the store")
	}
	c.Add(DefaultLease)
	w.expire()
	select {
	case <-lost:
	case <-time.After(5 * time.Second):
		t.Fatal("the lease did not end while a write hung")
	}
	if w.Serving() {
		t.Error("serving past the deadline")
	}
	close(store.release)
	<-done
	if w.Serving() {
		t.Error("a write that returned after the deadline revived the lease")
	}
}

// TestServingAfterAcquisition: a writer serves only once its
// acquisition is in the store and its state applied, not while the
// write hangs.
func TestServingAfterAcquisition(t *testing.T) {
	ctx := context.Background()
	store := &stuckStore{Store: FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	c := &clock{t: t0}
	w := newWriter(t, store, "a", c)
	w.OnState = func(*State) {
		if w.Serving() {
			t.Error("serving before the state was applied")
		}
	}
	store.stuck, store.release = make(chan struct{}), make(chan struct{})
	stuck := store.stuck
	done := make(chan error)
	go func() { done <- w.Acquire(ctx) }()
	<-stuck
	if w.Serving() {
		t.Error("serving while the acquisition hangs")
	}
	close(store.release)
	if err := <-done; err != nil || !w.Serving() {
		t.Fatalf("after acquiring: %v, serving %v", err, w.Serving())
	}
}

// TestHoldExpiresDuringStuckWrite: a running writer whose store hangs
// past renewals and the lease's end still loses the lease on time,
// closing its sessions, though renewal waits for the hung write.
func TestHoldExpiresDuringStuckWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &stuckStore{Store: FileStore{Path: filepath.Join(t.TempDir(), "accounts")}}
	w := &Writer{Store: store, Holder: "a", Lease: 3 * time.Second, Renew: 100 * time.Millisecond, Margin: 500 * time.Millisecond}
	lost := make(chan time.Time, 1)
	w.OnLost = func(error) { lost <- time.Now() }
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := w.deadline()
	held := make(chan struct{})
	go func() { w.hold(ctx); close(held) }()
	store.stuck, store.release = make(chan struct{}), make(chan struct{})
	stuck := store.stuck
	done := make(chan error)
	go func() {
		done <- w.Commit(ctx, func(s *State) error { _, err := AddAccount(s, "x", false, 0); return err })
	}()
	<-stuck
	select {
	case at := <-lost:
		if late := at.Sub(deadline); late > time.Second {
			t.Errorf("lease lost %v after its deadline", late)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the lease was not lost while a write hung")
	}
	close(store.release)
	<-done
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("hold kept going after the lease was lost")
	}
	if w.Serving() {
		t.Error("serving after the lease was lost")
	}
}
