package gateway

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/invite"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// enrollFixture is a gateway authenticating from a writer's store, with
// an account and an operator invite to it.
type enrollFixture struct {
	t      *testing.T
	g      *Gateway
	w      *accounts.Writer
	invite *accounts.Invite
	secret [16]byte
	mu     sync.Mutex
	now    time.Time
}

func newEnrollFixture(t *testing.T) *enrollFixture {
	t.Helper()
	ctx := context.Background()
	f := &enrollFixture{t: t, now: time.Now()}
	w := &accounts.Writer{Store: accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}, Holder: "a"}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{Network: netip.MustParsePrefix("10.77.0.1/16"), TunMTU: 1280, Gate: w.Serving, Commit: w.Commit,
		Now: func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(w.State())
	w.OnState = g.Apply
	err = w.Commit(ctx, func(st *accounts.State) error {
		if _, err := accounts.AddAccount(st, "alexei", false, 0); err != nil {
			return err
		}
		f.invite, f.secret, err = accounts.AddInvite(st, "alexei", time.Hour, f.now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	f.g, f.w = g, w
	return f
}

func (f *enrollFixture) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

func (f *enrollFixture) credential(token []byte, name string) []byte {
	e := &invite.Enrollment{ID: f.invite.ID, Secret: f.secret, Token: token, Name: name}
	return e.Credential()
}

// enroll repeats AUTH, as a client does, until it is answered.
func (f *enrollFixture) enroll(cred, key []byte) (session.Authorization, error) {
	f.t.Helper()
	for range 500 {
		a, err := f.g.AuthorizeSession(cred, key, nil)
		if !errors.Is(err, session.ErrAuthPending) {
			return a, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("enrollment still pending")
	return session.Authorization{}, nil
}

func TestEnroll(t *testing.T) {
	f := newEnrollFixture(t)
	token, key := invite.NewToken(), bytes.Repeat([]byte{7}, 32)
	cred := f.credential(token, "laptop")

	// The first AUTH starts the commit and is left unanswered.
	if _, err := f.g.AuthorizeSession(cred, key, nil); !errors.Is(err, session.ErrAuthPending) {
		t.Fatalf("first AUTH: %v", err)
	}
	a, err := f.enroll(cred, key)
	if err != nil || a.Enrolled == nil || a.Enrolled.Name != "laptop" || a.Result.TunMTU != 1280 {
		t.Fatalf("enrollment: %+v %v", a, err)
	}
	if f.g.AccountName(netip.AddrFrom4(a.Result.IPv4)) != "alexei" {
		t.Error("leased to the wrong account")
	}
	d := f.w.State().DeviceByID(accounts.ID(a.Enrolled.DeviceID))
	if d == nil || !bytes.Equal(d.Key, key) || d.TokenHash != accounts.TokenHash(token) {
		t.Fatalf("device record: %+v", d)
	}

	// From then on the token authenticates, but only from its key.
	if _, err := f.g.Authorize(token, key, nil); err != nil {
		t.Errorf("token: %v", err)
	}
	if _, err := f.g.Authorize(token, bytes.Repeat([]byte{8}, 32), nil); !errors.Is(err, ErrWrongKey) {
		t.Errorf("copied token from another key: %v", err)
	}

	// The answer was lost, and the client retries after the invite
	// expired: it is still the same device.
	f.advance(2 * time.Hour)
	a2, err := f.enroll(cred, key)
	if err != nil || a2.Enrolled == nil || a2.Enrolled.DeviceID != a.Enrolled.DeviceID {
		t.Fatalf("repeat past expiry: %+v %v", a2, err)
	}

	// Another device with the same invite is told it was used.
	_, err = f.enroll(f.credential(invite.NewToken(), "phone"), bytes.Repeat([]byte{9}, 32))
	var ae *session.AuthError
	if !errors.As(err, &ae) || ae.Code != wire.CodeInviteUsed || !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("second redemption: %v", err)
	}
}

func TestEnrollRefusals(t *testing.T) {
	f := newEnrollFixture(t)
	key := bytes.Repeat([]byte{7}, 32)
	// A wrong secret is an unknown invite, like a wrong token.
	bad := &invite.Enrollment{ID: f.invite.ID, Token: invite.NewToken()}
	if _, err := f.g.AuthorizeSession(bad.Credential(), key, nil); !errors.Is(err, ErrUnknownInvite) || !errors.Is(err, ErrBadCredential) {
		t.Errorf("wrong secret: %v", err)
	}
	f.advance(2 * time.Hour)
	_, err := f.enroll(f.credential(invite.NewToken(), "late"), key)
	var ae *session.AuthError
	if !errors.As(err, &ae) || ae.Code != wire.CodeInviteExpired {
		t.Errorf("expired invite: %v", err)
	}
	if len(f.w.State().Devices) != 0 {
		t.Error("an expired invite enrolled a device")
	}
}

// TestEnrollStoreDown: a redemption the store cannot take is refused
// as capacity, which the client retries, and nothing is enrolled.
func TestEnrollStoreDown(t *testing.T) {
	f := newEnrollFixture(t)
	f.g.cfg.Commit = func(context.Context, func(*accounts.State) error) error { return accounts.ErrUnavailable }
	_, err := f.enroll(f.credential(invite.NewToken(), "laptop"), bytes.Repeat([]byte{7}, 32))
	if !errors.Is(err, session.ErrCapacity) {
		t.Fatalf("store down: %v", err)
	}
}

// TestEnrollFloodOneInvite: someone holding an invite who redeems it
// with many keys holds one commit, not the gateway's enrollment slots;
// another invite still enrolls, and the flood's keys are refused once the
// first redemption is made.
func TestEnrollFloodOneInvite(t *testing.T) {
	f := newEnrollFixture(t)
	var other *accounts.Invite
	var otherSecret [16]byte
	err := f.w.Commit(context.Background(), func(st *accounts.State) (err error) {
		other, otherSecret, err = accounts.AddInvite(st, "alexei", time.Hour, f.now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// The first commit hangs. The gateway runs each commit in its own
	// goroutine, so which one calls first is up to the scheduler: wait
	// for the flooded invite's to be held before anything else can
	// commit, or the other invite's may be the one held.
	release, held, calls := make(chan struct{}), make(chan struct{}), 0
	var cmu sync.Mutex
	f.g.cfg.Commit = func(ctx context.Context, fn func(*accounts.State) error) error {
		cmu.Lock()
		calls++
		first := calls == 1
		cmu.Unlock()
		if first {
			close(held)
			<-release // the flooded invite's commit hangs
		}
		return f.w.Commit(ctx, fn)
	}

	first, firstCred := bytes.Repeat([]byte{1}, 32), f.credential(invite.NewToken(), "first")
	if _, err := f.g.AuthorizeSession(firstCred, first, nil); !errors.Is(err, session.ErrAuthPending) {
		t.Fatalf("first redemption: %v", err)
	}
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("the first redemption's commit never started")
	}
	for n := range 2 * maxEnrolling {
		key := bytes.Repeat([]byte{byte(n + 2)}, 32)
		if _, err := f.g.AuthorizeSession(f.credential(invite.NewToken(), "flood"), key, nil); !errors.Is(err, session.ErrAuthPending) {
			t.Fatalf("flood %d: %v", n, err)
		}
	}
	f.g.mu.Lock()
	n := len(f.g.enrolling)
	f.g.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d enrollments tracked for one invite, want 1", n)
	}

	// Another invite enrolls while the flood waits.
	e := &invite.Enrollment{ID: other.ID, Secret: otherSecret, Token: invite.NewToken(), Name: "phone"}
	if a, err := f.enroll(e.Credential(), bytes.Repeat([]byte{0xee}, 32)); err != nil || a.Enrolled == nil {
		t.Fatalf("other invite during the flood: %+v %v", a, err)
	}

	close(release)
	if a, err := f.enroll(firstCred, first); err != nil || a.Enrolled == nil || a.Enrolled.Name != "first" {
		t.Fatalf("first redemption: %+v %v", a, err)
	}
	var ae *session.AuthError
	_, err = f.enroll(f.credential(invite.NewToken(), "flood"), bytes.Repeat([]byte{2}, 32))
	if !errors.As(err, &ae) || ae.Code != wire.CodeInviteUsed {
		t.Fatalf("flood key after the first redemption: %v", err)
	}
}
