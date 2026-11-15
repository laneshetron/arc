package engine

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/invite"
	"github.com/laneshetron/arc/internal/session"
)

var mintKey = bytes.Repeat([]byte{0x5a}, accounts.InviteKeySize)

// mintRelay runs a relay that lets devices mint invites, committing
// through w, until ctx ends.
func mintRelay(t *testing.T, ctx context.Context, w *accounts.Writer, relayKey crypto.StaticKey) (*udp.Conn, *logLines) {
	t.Helper()
	gw, err := gateway.New(gateway.Config{Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280,
		Gate: w.Serving, Commit: w.Commit, InviteKey: mintKey})
	if err != nil {
		t.Fatal(err)
	}
	w.OnState, w.OnLost = gw.Apply, gw.Suspend
	if st := w.State(); st != nil {
		gw.Apply(st)
	}
	relayConn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relayConn.Close() })
	relayTUN := newMemTUN()
	t.Cleanup(func() { relayTUN.Close() })
	attempts, lines := newTestAttemptLog()
	go RunRelay(ctx, RelayConfig{
		Session: session.RelayConfig{Static: relayKey, ResetSecret: [32]byte{1}, NoStreams: true},
		Conn:    relayConn, TUN: relayTUN, Gateway: gw, Logger: slog.New(slog.NewJSONHandler(lines, nil)), Attempts: attempts,
	})
	return relayConn, lines
}

// askInvite runs a client as the device (key, token) asking for an invite
// with request id, repeating it every repeat, and returns RunClient's
// result and the answer.
func askInvite(ctx context.Context, t *testing.T, relay *udp.Conn, relayKey, key crypto.StaticKey, token []byte, id [8]byte,
	repeat time.Duration) (<-chan error, <-chan session.InviteAnswer) {
	t.Helper()
	conn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	tun := newMemTUN()
	t.Cleanup(func() { tun.Close() })
	done, answers := make(chan error, 1), make(chan session.InviteAnswer, 1)
	go func() {
		done <- RunClient(ctx, ClientConfig{
			Session: session.ClientConfig{Static: key, RelayPublic: relayKey.Public, Credential: token},
			Relay:   relay.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: conn}}, TUN: tun,
			ReconnectDelay: 50 * time.Millisecond, InviteRequest: &id, InviteRepeat: repeat,
			OnInvite: func(a session.InviteAnswer) error { answers <- a; return errStop },
		})
	}()
	return done, answers
}

var errStop = errors.New("answered")

// TestMintAcrossRestart: a device's request is minted and committed, but
// its relay restarts before the client hears the answer. The same
// request to the new relay is answered with the same invite, which a new
// device redeems, enrolling under the minter.
func TestMintAcrossRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}
	relayKey, _ := crypto.GenerateStaticKey(nil)
	key, _ := crypto.GenerateStaticKey(nil)
	token := accounts.NewToken()

	ctx1, stop1 := context.WithCancel(ctx)
	w1 := &accounts.Writer{Store: store, Holder: "relay1"}
	relay1, _ := mintRelay(t, ctx1, w1, relayKey)
	if err := w1.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	var device accounts.ID
	if err := w1.Commit(ctx, func(st *accounts.State) error {
		if _, err := accounts.AddAccount(st, "alexei", false, 0); err != nil {
			return err
		}
		i, secret, err := accounts.AddInvite(st, "alexei", time.Hour, time.Now())
		if err != nil {
			return err
		}
		d, err := accounts.Redeem(st, i.ID, secret[:], token, key.Public[:], "laptop", time.Now())
		if d != nil {
			device = d.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// The first request is held while its commit runs, and with no
	// repeat, the client never hears the answer.
	req := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	done1, answers1 := askInvite(ctx1, t, relay1, relayKey, key, token, req, time.Hour)
	deadline := time.Now().Add(10 * time.Second)
	for w1.State().MintedBy(device, accounts.ID(req)) == nil {
		if time.Now().After(deadline) {
			t.Fatal("the request was never committed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	minted := *w1.State().MintedBy(device, accounts.ID(req))
	select {
	case a := <-answers1:
		t.Fatalf("answered before the repeat: %+v", a)
	default:
	}
	stop1() // the relay restarts; the answer is lost
	<-done1
	if err := w1.Release(ctx); err != nil {
		t.Fatal(err)
	}

	w2 := &accounts.Writer{Store: store, Holder: "relay2"}
	relay2, _ := mintRelay(t, ctx, w2, relayKey)
	if err := w2.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	done2, answers2 := askInvite(ctx, t, relay2, relayKey, key, token, req, 100*time.Millisecond)
	a := wait(t, answers2, "the repeated request's answer")
	if err := wait(t, done2, "the client"); !errors.Is(err, errStop) {
		t.Fatalf("client: %v", err)
	}
	if a.Status != 0 || accounts.ID(a.ID) != minted.ID {
		t.Fatalf("answer %+v, want invite %v", a.Invite, minted.ID)
	}
	n := 0
	for _, i := range w2.State().Invites {
		if i.By == device {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d invites minted after the repeat, want 1", n)
	}
	if !time.Unix(int64(a.Expires), 0).Equal(minted.Expires) {
		t.Errorf("expires %v, want %v", time.Unix(int64(a.Expires), 0), minted.Expires)
	}

	// A new device redeems it, and enrolls under the minter.
	newKey, _ := crypto.GenerateStaticKey(nil)
	e := &invite.Enrollment{ID: a.ID, Secret: a.Secret, Token: accounts.NewToken(), Name: "phone"}
	conn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tun := newMemTUN()
	defer tun.Close()
	err = RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: newKey, RelayPublic: relayKey.Public, Credential: e.Credential()},
		Relay:   relay2.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: conn}}, TUN: tun,
		OnEnrolled: func(session.Enrolled) error { return errStop },
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("enrolling with the minted invite: %v", err)
	}
	var phone *accounts.Device
	for _, d := range w2.State().Devices {
		if d.Name == "phone" {
			phone = d
		}
	}
	if phone == nil || len(phone.Lineage) != 1 || phone.Lineage[0] != device {
		t.Fatalf("phone: %+v", phone)
	}
}

// TestMintRefusedLegacy: a device bound to no key is not offered invites,
// and the client says so instead of waiting.
func TestMintRefusedLegacy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &accounts.Writer{Store: accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}, Holder: "relay"}
	relayKey, _ := crypto.GenerateStaticKey(nil)
	relay, _ := mintRelay(t, ctx, w, relayKey)
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	var token []byte
	if err := w.Commit(ctx, func(st *accounts.State) (err error) {
		if _, err = accounts.AddAccount(st, "alexei", false, 0); err == nil {
			_, token, err = accounts.AddToken(st, "alexei", "legacy", time.Now())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.GenerateStaticKey(nil)
	done, _ := askInvite(ctx, t, relay, relayKey, key, token, [8]byte{9}, 100*time.Millisecond)
	if err := wait(t, done, "the client"); !errors.Is(err, session.ErrNoInvites) {
		t.Fatalf("legacy device: %v", err)
	}
	if n := len(w.State().Invites); n != 0 {
		t.Errorf("%d invites minted for a legacy device", n)
	}
}
