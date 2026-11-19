package gateway

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/invite"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// manageFixture is a mintFixture with a second key-bound device, the
// desktop, enrolled beside the laptop.
type manageFixture struct {
	*mintFixture
	desktop      netip.Addr
	desktopKey   []byte
	desktopToken []byte
}

func newManageFixture(t *testing.T) *manageFixture {
	t.Helper()
	f := &manageFixture{mintFixture: newMintFixture(t), desktopKey: bytes.Repeat([]byte{9}, 32), desktopToken: invite.NewToken()}
	var inv *accounts.Invite
	var secret [16]byte
	if err := f.w.Commit(context.Background(), func(st *accounts.State) (err error) {
		inv, secret, err = accounts.AddInvite(st, "alexei", time.Hour, f.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e := &invite.Enrollment{ID: inv.ID, Secret: secret, Token: f.desktopToken, Name: "desktop"}
	a, err := f.enroll(e.Credential(), f.desktopKey)
	if err != nil {
		t.Fatal(err)
	}
	if a.Result.Features&wire.FeatureDevices == 0 {
		t.Fatalf("a key-bound device may not manage devices: features %#x", a.Result.Features)
	}
	f.desktop = netip.AddrFrom4(a.Result.IPv4)
	return f
}

// revoke repeats a request from the device leasing addr until answered.
func (f *manageFixture) revoke(addr netip.Addr, req wire.RevokeRequest) wire.RevokeResult {
	f.t.Helper()
	for range 500 {
		if a, ok := f.g.revokeDevice(addr, nil, req); ok {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("revocation still unanswered")
	return wire.RevokeResult{}
}

func (f *manageFixture) device(name string) *accounts.Device {
	for _, d := range f.w.State().Devices {
		if d.Name == name {
			return d
		}
	}
	return nil
}

func TestListDevices(t *testing.T) {
	f := newManageFixture(t)
	d, ok := f.g.listDevices(f.desktop, nil)
	if !ok || d.Status != 0 || len(d.Devices) != 2 {
		t.Fatalf("list: %+v %v", d, ok)
	}
	for _, x := range d.Devices {
		want := f.device(x.Name)
		if want == nil || x.ID != want.ID || !bytes.Equal(x.Key[:], want.Key[:8]) || x.Created != uint32(want.Created.Unix()) {
			t.Errorf("listed %+v, want %+v", x, want)
		}
	}
	// A legacy device is refused.
	var tok []byte
	if err := f.w.Commit(context.Background(), func(st *accounts.State) (err error) {
		_, tok, err = accounts.AddToken(st, "alexei", "old", f.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r, err := f.g.Authorize(tok, nil, nil)
	if err != nil || r.Features&wire.FeatureDevices != 0 {
		t.Fatalf("legacy device: features %#x, %v", r.Features, err)
	}
	if d, _ := f.g.listDevices(netip.AddrFrom4(r.IPv4), nil); d.Status != wire.CodeUnauthorized {
		t.Errorf("legacy device listed: %+v", d)
	}
}

func TestRevokeDevice(t *testing.T) {
	f := newManageFixture(t)
	var logs bytes.Buffer
	var logMu sync.Mutex
	f.g.cfg.Log = slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &logMu}, nil))
	laptop := f.device("laptop")
	req := wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: laptop.ID}

	// Too young to revoke another device.
	if a := f.revoke(f.desktop, req); a.Status != wire.CodeUnauthorized {
		t.Fatalf("young device revoked another: %+v", a)
	}
	if f.device("laptop") == nil {
		t.Fatal("refused, yet revoked")
	}
	f.advance(accounts.CoolingOff)
	req.RequestID = [8]byte{2}
	if a := f.revoke(f.desktop, req); a.Status != 0 {
		t.Fatalf("revoke: %+v", a)
	}
	if f.device("laptop") != nil {
		t.Fatal("answered, yet not revoked")
	}
	f.g.mu.Lock()
	revoked := f.g.leased[f.addr].revoked
	f.g.mu.Unlock()
	if !revoked {
		t.Error("the laptop's lease survives")
	}
	// Repeated: answered at once.
	if a, ok := f.g.revokeDevice(f.desktop, nil, req); !ok || a.Status != 0 {
		t.Errorf("repeat: %+v %v", a, ok)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if !strings.Contains(logs.String(), "device revoked by a device") || !strings.Contains(logs.String(), "by=desktop") ||
		!strings.Contains(logs.String(), "device=laptop") {
		t.Errorf("no warning naming both devices:\n%s", logs.String())
	}
}

// TestRevokeDeviceStoreDown: a revocation the store cannot take stays
// unanswered, and nothing is revoked, until the store is back.
func TestRevokeDeviceStoreDown(t *testing.T) {
	f := newManageFixture(t)
	f.advance(accounts.CoolingOff)
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
	req := wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: f.device("laptop").ID}
	for range 30 {
		if a, ok := f.g.revokeDevice(f.desktop, nil, req); ok {
			t.Fatalf("answered with the store down: %+v", a)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if f.device("laptop") == nil {
		t.Fatal("revoked with the store down")
	}
	mu.Lock()
	down = false
	mu.Unlock()
	if a := f.revoke(f.desktop, req); a.Status != 0 {
		t.Fatalf("after the store came back: %+v", a)
	}
}

// restoreLaptop has the operator restore the laptop.
func (f *manageFixture) restoreLaptop() {
	f.t.Helper()
	if err := f.w.Commit(context.Background(), func(st *accounts.State) error {
		_, err := accounts.Restore(st, "alexei/laptop", f.now)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

// waitRevoked waits until the laptop's revocation is committed.
func (f *manageFixture) waitRevoked() {
	f.t.Helper()
	for range 500 {
		if f.device("laptop") == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("the laptop was never revoked")
}

// stillThere fails the test if the repeat of req, answered as done,
// revoked the restored laptop again.
func (f *manageFixture) stillThere(addr netip.Addr, req wire.RevokeRequest) {
	f.t.Helper()
	if a := f.revoke(addr, req); a.Status != 0 {
		f.t.Fatalf("repeat: %+v", a)
	}
	time.Sleep(50 * time.Millisecond) // a commit, were one started
	if f.device("laptop") == nil {
		f.t.Fatal("the repeat revoked the restored laptop")
	}
}

// TestRevokeRepeatAfterRestore: the operator restores the laptop before
// the desktop heard that its revocation was done. The repeat is answered
// as done and revokes nothing; a new request is a new decision.
func TestRevokeRepeatAfterRestore(t *testing.T) {
	f := newManageFixture(t)
	f.advance(accounts.CoolingOff)
	req := wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: f.device("laptop").ID}
	if _, ok := f.g.revokeDevice(f.desktop, nil, req); ok {
		t.Fatal("answered before the commit")
	}
	f.waitRevoked() // its answer never collected
	f.restoreLaptop()
	f.stillThere(f.desktop, req)
	req.RequestID = [8]byte{2}
	if a := f.revoke(f.desktop, req); a.Status != 0 || f.device("laptop") != nil {
		t.Fatalf("new request: %+v", a)
	}
}

// TestRevokeIndeterminate: the store took the revocation but its answer
// was lost; once the write is confirmed and the laptop restored, the
// request's repeat revokes nothing.
func TestRevokeIndeterminate(t *testing.T) {
	f := newManageFixture(t)
	f.advance(accounts.CoolingOff)
	commit := f.g.cfg.Commit
	var mu sync.Mutex
	first := true
	f.g.cfg.Commit = func(ctx context.Context, fn func(*accounts.State) error) error {
		err := commit(ctx, fn)
		mu.Lock()
		defer mu.Unlock()
		if err == nil && first {
			first = false
			return accounts.ErrIndeterminate
		}
		return err
	}
	req := wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: f.device("laptop").ID}
	f.g.revokeDevice(f.desktop, nil, req)
	f.waitRevoked()
	f.restoreLaptop()
	f.stillThere(f.desktop, req)
}

// TestRevokeAcrossWriterRestart: the relay restarts between the commit
// and the repeat; the new one, reading the store, answers it as done.
func TestRevokeAcrossWriterRestart(t *testing.T) {
	f := newManageFixture(t)
	f.advance(accounts.CoolingOff)
	ctx := context.Background()
	req := wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: f.device("laptop").ID}
	f.g.revokeDevice(f.desktop, nil, req)
	f.waitRevoked()
	f.restoreLaptop()
	if err := f.w.Release(ctx); err != nil {
		t.Fatal(err)
	}
	w := &accounts.Writer{Store: f.w.Store, Holder: "b"}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	cfg := f.g.cfg
	cfg.Gate, cfg.Commit = w.Serving, w.Commit
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(w.State())
	w.OnState = g.Apply
	f.g, f.w = g, w
	r, err := g.Authorize(f.desktopToken, f.desktopKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.stillThere(netip.AddrFrom4(r.IPv4), req)
}

// TestAuthRevoked: a revoked device's token is refused REVOKED, not
// AUTH_FAILED, so a client that missed CLOSE(REVOKED) still learns it,
// until a restore admits it again.
func TestAuthRevoked(t *testing.T) {
	f := newManageFixture(t)
	f.advance(accounts.CoolingOff)
	if a := f.revoke(f.desktop, wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: f.device("laptop").ID}); a.Status != 0 {
		t.Fatalf("revoke: %+v", a)
	}
	_, err := f.g.Authorize(f.token, f.key, nil)
	var ae *session.AuthError
	if !errors.As(err, &ae) || ae.Code != wire.CodeRevoked {
		t.Fatalf("revoked token: %v", err)
	}
	if _, err := f.g.Authorize(invite.NewToken(), f.key, nil); errors.As(err, &ae) {
		t.Errorf("an unknown token was told REVOKED: %v", err)
	}
	if err := f.w.Commit(context.Background(), func(st *accounts.State) error {
		_, err := accounts.Restore(st, "alexei/laptop", f.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.Authorize(f.token, f.key, nil); err != nil {
		t.Errorf("restored laptop: %v", err)
	}
}

// TestAuthRevokedExpires: once the tombstone's life is over, the token is
// unknown, though no state change has been applied since.
func TestAuthRevokedExpires(t *testing.T) {
	f := newManageFixture(t)
	f.advance(accounts.CoolingOff)
	if a := f.revoke(f.desktop, wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: f.device("laptop").ID}); a.Status != 0 {
		t.Fatalf("revoke: %+v", a)
	}
	f.advance(accounts.TombstoneLife)
	_, err := f.g.Authorize(f.token, f.key, nil)
	var ae *session.AuthError
	if errors.As(err, &ae) || !errors.Is(err, ErrBadCredential) {
		t.Errorf("token past its tombstone: %v", err)
	}
}

// TestRevokeSelf: a device may always revoke itself, young or not
// (self-service-accounts.md §3.8). This is the one path where the
// cooling-off must not apply, and the e2e exercises it on a laptop
// enrolled seconds earlier.
func TestRevokeSelf(t *testing.T) {
	f := newManageFixture(t)
	laptop := f.device("laptop")
	req := wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: laptop.ID}

	// The laptop revokes itself while still inside the cooling-off window,
	// which is what makes this different from every other revoke test.
	if a, ok := f.g.revokeDevice(f.addr, nil, req); ok {
		if a.Status != 0 {
			t.Fatalf("a device was refused revoking itself: %+v (within %v of enrolling)", a, accounts.CoolingOff)
		}
	}
	f.waitRevoked()
	if f.device("laptop") != nil {
		t.Fatal("self-revoke left the device")
	}
}

// TestRevokeSelfRepeatAfterCommit: the client repeats its request because
// it never saw the answer. For a self-revoke the first call is left
// unanswered while the commit runs, and by the time the repeat arrives the
// device has revoked itself, so it no longer exists in the state to
// identify itself with. The repeat must still be answered as done.
func TestRevokeSelfRepeatAfterCommit(t *testing.T) {
	f := newManageFixture(t)
	laptop := f.device("laptop")
	req := wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: laptop.ID}
	if _, ok := f.g.revokeDevice(f.addr, nil, req); ok {
		t.Fatal("answered before the commit")
	}
	f.waitRevoked()
	if a, ok := f.g.revokeDevice(f.addr, nil, req); !ok || a.Status != 0 {
		t.Fatalf("repeat after a committed self-revoke: %+v ok=%v", a, ok)
	}
}

// TestRevokeSelfFixIsNotAGrant: a device revoked by another must not be
// able to ride the self-revoke path to submit requests. Its tombstone
// names the revoker, not itself, so the repeat is refused.
func TestRevokeSelfFixIsNotAGrant(t *testing.T) {
	f := newManageFixture(t)
	f.advance(accounts.CoolingOff)
	laptop := f.device("laptop")
	if a := f.revoke(f.desktop, wire.RevokeRequest{RequestID: [8]byte{1}, DeviceID: laptop.ID}); a.Status != 0 {
		t.Fatalf("revoke: %+v", a)
	}
	f.waitRevoked()
	// The laptop's lease is revoked, and it is gone from the state. A
	// request from it must not be answered as done by the new path: its
	// tombstone's revoker is the desktop.
	req := wire.RevokeRequest{RequestID: [8]byte{9}, DeviceID: laptop.ID}
	if a, ok := f.g.revokeDevice(f.addr, nil, req); ok && a.Status == 0 {
		t.Fatalf("a device revoked by another was answered 0: %+v", a)
	}
}
