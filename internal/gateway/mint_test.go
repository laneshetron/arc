package gateway

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/invite"
	"github.com/laneshetron/arc/internal/wire"
)

var mintKey = bytes.Repeat([]byte{0x5a}, accounts.InviteKeySize)

// mintFixture is an enrollFixture whose gateway lets devices mint, with
// one device enrolled and leased.
type mintFixture struct {
	*enrollFixture
	token []byte
	key   []byte
	addr  netip.Addr
}

func newMintFixture(t *testing.T) *mintFixture {
	t.Helper()
	f := &mintFixture{enrollFixture: newEnrollFixture(t), token: invite.NewToken(), key: bytes.Repeat([]byte{7}, 32)}
	f.g.cfg.InviteKey = mintKey
	f.g.Apply(f.w.State())
	a, err := f.enroll(f.credential(f.token, "laptop"), f.key)
	if err != nil {
		t.Fatal(err)
	}
	if a.Result.Features&wire.FeatureInvites == 0 {
		t.Fatalf("a key-bound device is not offered invites: features %#x", a.Result.Features)
	}
	f.addr = netip.AddrFrom4(a.Result.IPv4)
	return f
}

// ask repeats a request, as a client does, until it is answered.
func (f *mintFixture) ask(id [8]byte) wire.Invite {
	f.t.Helper()
	for range 500 {
		if a, ok := f.g.mint(f.addr, nil, wire.InviteRequest{RequestID: id}); ok {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("request still unanswered")
	return wire.Invite{}
}

func TestMint(t *testing.T) {
	f := newMintFixture(t)
	req := [8]byte{1}
	// The first request starts the commit and is left unanswered.
	if a, ok := f.g.mint(f.addr, nil, wire.InviteRequest{RequestID: req}); ok {
		t.Fatalf("answered before the commit: %+v", a)
	}
	a := f.ask(req)
	if a.Status != 0 || a.Expires == 0 {
		t.Fatalf("answer: %+v", a)
	}
	if _, err := f.w.State().CheckInvite(accounts.ID(a.ID), a.Secret[:]); err != nil {
		t.Fatalf("the answer is not the stored invite: %v", err)
	}
	// Repeated, the same invite.
	if again := f.ask(req); again != a {
		t.Errorf("repeat: %+v, want %+v", again, a)
	}
	// Past its expiry, the repeat is refused.
	f.advance(accounts.MintedInviteTTL)
	if late := f.ask(req); late.Status != wire.CodeInviteExpired {
		t.Errorf("repeat past expiry: %+v", late)
	}
}

// TestMintOnePerDevice: while one of a device's requests is committing,
// its others wait, and take no slot.
func TestMintOnePerDevice(t *testing.T) {
	f := newMintFixture(t)
	release := make(chan struct{})
	var once sync.Once
	commit := f.g.cfg.Commit
	f.g.cfg.Commit = func(ctx context.Context, fn func(*accounts.State) error) error {
		once.Do(func() { <-release })
		return commit(ctx, fn)
	}
	if _, ok := f.g.mint(f.addr, nil, wire.InviteRequest{RequestID: [8]byte{1}}); ok {
		t.Fatal("first request answered at once")
	}
	for n := range 100 {
		if _, ok := f.g.mint(f.addr, nil, wire.InviteRequest{RequestID: [8]byte{2, byte(n)}}); ok {
			t.Fatal("a second request answered while the first commits")
		}
	}
	f.g.mu.Lock()
	n := len(f.g.minting)
	f.g.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d requests tracked, want 1", n)
	}
	close(release)
	if a := f.ask([8]byte{1}); a.Status != 0 {
		t.Fatalf("first: %+v", a)
	}
	if a := f.ask([8]byte{2, 0}); a.Status != 0 {
		t.Fatalf("second, after the first: %+v", a)
	}
	// Two outstanding: a third is refused.
	if a := f.ask([8]byte{3}); a.Status != wire.CodeCapacity {
		t.Errorf("third outstanding: %+v", a)
	}
}

// TestMintStoreDown: a request the store cannot take stays unanswered,
// and is minted once the store is back.
func TestMintStoreDown(t *testing.T) {
	f := newMintFixture(t)
	commit := f.g.cfg.Commit
	var mu sync.Mutex
	down := true
	f.g.cfg.Commit = func(ctx context.Context, fn func(*accounts.State) error) error {
		mu.Lock()
		d := down
		mu.Unlock()
		if d {
			return accounts.ErrUnavailable
		}
		return commit(ctx, fn)
	}
	for range 50 {
		if a, ok := f.g.mint(f.addr, nil, wire.InviteRequest{RequestID: [8]byte{1}}); ok {
			t.Fatalf("answered with the store down: %+v", a)
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	down = false
	mu.Unlock()
	if a := f.ask([8]byte{1}); a.Status != 0 {
		t.Fatalf("after the store came back: %+v", a)
	}
}

// TestMintRevoked: a device revoked while its session lives is refused.
func TestMintRevoked(t *testing.T) {
	f := newMintFixture(t)
	if err := f.w.Commit(context.Background(), func(st *accounts.State) error {
		_, err := accounts.Revoke(st, "alexei/laptop", f.now, false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if a := f.ask([8]byte{1}); a.Status != wire.CodeUnauthorized {
		t.Errorf("revoked device: %+v", a)
	}
}

// TestMintPolicyOff: an account with invites=no offers its devices no
// invites, and refuses their requests.
func TestMintPolicyOff(t *testing.T) {
	f := newMintFixture(t)
	if err := f.w.Commit(context.Background(), func(st *accounts.State) error {
		st.AccountByName("alexei").Invites = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if a := f.ask([8]byte{1}); a.Status != wire.CodeUnauthorized {
		t.Errorf("invites=no: %+v", a)
	}
	r, err := f.g.Authorize(f.token, f.key, nil)
	if err != nil || r.Features&wire.FeatureInvites != 0 {
		t.Errorf("invites=no still offered: %#x %v", r.Features, err)
	}
}

// TestMintSlotsFreed: requests whose commits are done, but whose clients
// never came back, take no slot from other devices.
func TestMintSlotsFreed(t *testing.T) {
	f := newMintFixture(t)
	f.g.mu.Lock()
	for range maxMinting {
		f.g.minting[accounts.NewID()] = &pending{request: accounts.NewID(), started: f.now, done: true}
	}
	f.g.mu.Unlock()
	if a := f.ask([8]byte{1}); a.Status != 0 {
		t.Fatalf("answer: %+v", a)
	}
	f.g.mu.Lock()
	defer f.g.mu.Unlock()
	if f.g.committing != 0 {
		t.Errorf("%d commits counted after they finished", f.g.committing)
	}
}

// TestMintAuditIndeterminate: a mint whose write the store took but did
// not confirm is logged once the relay adopts the state that has it.
func TestMintAuditIndeterminate(t *testing.T) {
	f := newMintFixture(t)
	var logs bytes.Buffer
	var logMu sync.Mutex
	f.g.cfg.Log = slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &logMu}, nil))
	var mu sync.Mutex
	hold, first := true, true
	var held *accounts.State
	f.w.OnState = func(st *accounts.State) {
		mu.Lock()
		defer mu.Unlock()
		if hold {
			held = st
			return
		}
		f.g.Apply(st)
	}
	commit := f.g.cfg.Commit
	f.g.cfg.Commit = func(ctx context.Context, fn func(*accounts.State) error) error {
		err := commit(ctx, fn)
		mu.Lock()
		defer mu.Unlock()
		if err == nil && first {
			first = false
			return accounts.ErrIndeterminate // the write made, its answer lost
		}
		return err
	}
	if _, ok := f.g.mint(f.addr, nil, wire.InviteRequest{RequestID: [8]byte{1}}); ok {
		t.Fatal("answered before the commit")
	}
	for done := false; !done; time.Sleep(5 * time.Millisecond) {
		f.g.mu.Lock()
		for _, p := range f.g.minting {
			done = p.done
		}
		f.g.mu.Unlock()
	}
	// The writer resolves the write and adopts its state.
	mu.Lock()
	hold = false
	st := held
	mu.Unlock()
	f.g.Apply(st)
	if a := f.ask([8]byte{1}); a.Status != 0 {
		t.Fatalf("answer: %+v", a)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if n := strings.Count(logs.String(), "invite minted"); n != 1 {
		t.Errorf("%d audit entries, want 1:\n%s", n, logs.String())
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}
