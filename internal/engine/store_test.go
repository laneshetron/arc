package engine

import (
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
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// storeRelay runs a relay authenticating from an accounts store through
// w, which the caller acquires.
func storeRelay(t *testing.T, ctx context.Context, w *accounts.Writer) (*udp.Conn, crypto.StaticKey, *logLines) {
	t.Helper()
	relayKey, _ := crypto.GenerateStaticKey(nil)
	gw, err := gateway.New(gateway.Config{Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Gate: w.Serving})
	if err != nil {
		t.Fatal(err)
	}
	w.OnState, w.OnLost = gw.Apply, gw.Suspend
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
	return relayConn, relayKey, lines
}

// storeClient runs a client until it gives up, reporting each
// establishment and its final error.
func storeClient(t *testing.T, ctx context.Context, relay *udp.Conn, relayKey crypto.StaticKey, token []byte) (<-chan struct{}, <-chan error) {
	t.Helper()
	key, _ := crypto.GenerateStaticKey(nil)
	conn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	tun := newMemTUN()
	t.Cleanup(func() { tun.Close() })
	up, done := make(chan struct{}, 8), make(chan error, 1)
	go func() {
		done <- RunClient(ctx, ClientConfig{
			Session: session.ClientConfig{Static: key, RelayPublic: relayKey.Public, Credential: token},
			Relay:   relay.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: conn}}, TUN: tun,
			ReconnectDelay: 50 * time.Millisecond,
			OnEstablished:  func(wire.AuthResult) error { up <- struct{}{}; return nil },
		})
	}()
	return up, done
}

func wait[T any](t *testing.T, c <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

// TestStoreRevokesLiveSession: a device revoked in the store loses its
// live session at once, and its client, refused on reconnecting, stops.
func TestStoreRevokesLiveSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &accounts.Writer{Store: accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}, Holder: "relay"}
	relay, relayKey, lines := storeRelay(t, ctx, w)
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	var token []byte
	if err := w.Commit(ctx, func(st *accounts.State) (err error) {
		if _, err = accounts.AddAccount(st, "alexei", false, 0); err == nil {
			_, token, err = accounts.AddToken(st, "alexei", "laptop", time.Now())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	up, done := storeClient(t, ctx, relay, relayKey, token)
	wait(t, up, "the session")
	// The client can hear the relay's answer before the relay's loop has
	// logged the session it established.
	if r := lines.await(t, "session established"); r == nil || r["device"] != "laptop" {
		t.Errorf("established line %v", r)
	}
	if err := w.Commit(ctx, func(st *accounts.State) error {
		_, err := accounts.Revoke(st, "alexei/laptop", time.Now(), false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, done, "the client to stop"); !errors.Is(err, session.ErrAuthFailed) {
		t.Errorf("client ended with %v; want an authentication failure", err)
	}
	if r := lines.find(t, "session revoked"); r == nil || r["device"] != "laptop" {
		t.Errorf("revoked line %v", r)
	}
}

// TestStoreNotServing: until the relay holds the accounts lease, clients
// are told it is full and keep trying; they connect once it has it, and
// are closed and reconnect when it loses it.
func TestStoreNotServing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}
	seed := &accounts.Writer{Store: store, Holder: "seed"}
	if err := seed.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	var token []byte
	seed.Commit(ctx, func(st *accounts.State) (err error) {
		accounts.AddAccount(st, "alexei", false, 0)
		_, token, err = accounts.AddToken(st, "alexei", "laptop", time.Now())
		return err
	})
	if err := seed.Release(ctx); err != nil {
		t.Fatal(err)
	}

	w := &accounts.Writer{Store: store, Holder: "relay"}
	relay, relayKey, lines := storeRelay(t, ctx, w)
	up, done := storeClient(t, ctx, relay, relayKey, token)
	deadline := time.Now().Add(5 * time.Second)
	for lines.find(t, "handshake rejected: relay not serving accounts") == nil {
		if time.Now().After(deadline) {
			t.Fatalf("no refusal while not serving: %v", lines.records(t))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	wait(t, up, "the session once serving")

	// Another writer takes over: this relay loses the lease, closes the
	// session, and the client keeps trying rather than stopping.
	other := &accounts.Writer{Store: store, Holder: "other"}
	if err := other.Takeover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ctx, func(*accounts.State) error { return nil }); !errors.Is(err, accounts.ErrNotWriter) {
		t.Fatalf("commit after takeover: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for lines.find(t, "session revoked") == nil {
		if time.Now().After(deadline) {
			t.Fatal("session not closed after the lease was lost")
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("client stopped: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
}
