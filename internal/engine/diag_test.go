package engine

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/diag"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// TestDiagnosticsUpload runs a client whose journal holds an earlier run's
// records against a relay that keeps diagnostics but declines split TCP:
// the journal reaches the relay's store under the client's account, and
// leaves the client's spool.
func TestDiagnosticsUpload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	relayKey, _ := crypto.GenerateStaticKey(nil)
	gw, err := gateway.New(gateway.Config{Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280,
		Accounts: []gateway.Account{{Name: "friend", Tokens: [][]byte{[]byte("tok")}}}})
	if err != nil {
		t.Fatal(err)
	}
	relayConn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayTUN := newMemTUN()
	defer relayTUN.Close()
	store := &diag.Store{Dir: t.TempDir()}
	go RunRelay(ctx, RelayConfig{
		Session: session.RelayConfig{Static: relayKey, ResetSecret: [32]byte{1}, NoStreams: true},
		Conn:    relayConn, TUN: relayTUN, Gateway: gw, Diagnostics: store,
	})

	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	journal, err := diag.OpenJournal(journalPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	log := slog.New(journal.Handler())
	log.Debug("tls carrier", "carrier", "wlan0/tls", "err", "reset after ClientHello") // an earlier, failing run

	key, _ := crypto.GenerateStaticKey(nil)
	conn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tun := newMemTUN()
	defer tun.Close()
	established := make(chan wire.AuthResult, 1)
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: key, RelayPublic: relayKey.Public, Credential: []byte("tok")},
		Relay:   relayConn.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: conn}}, TUN: tun, Logger: log,
		OnEstablished:    func(r wire.AuthResult) error { established <- r; return nil },
		Diagnostics:      journal,
		DiagnosticsDelay: 10 * time.Millisecond,
	})
	var r wire.AuthResult
	select {
	case r = <-established:
	case <-time.After(5 * time.Second):
		t.Fatal("not established")
	}
	if r.Features&wire.FeatureStreams != 0 || r.Features&wire.FeatureDiagnostics == 0 {
		t.Fatalf("features %#x, want diagnostics without streams", r.Features)
	}

	dir := filepath.Join(store.Dir, "friend")
	var got []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entries, _ := os.ReadDir(dir); len(entries) == 1 && strings.HasSuffix(entries[0].Name(), ".jsonl") {
			got, _ = os.ReadFile(filepath.Join(dir, entries[0].Name()))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(string(got), "reset after ClientHello") || !strings.Contains(string(got), "session established") {
		t.Fatalf("relay kept %q", got)
	}
	for time.Now().Before(deadline) {
		if left, _ := journal.Pending(); !strings.Contains(string(left), "ClientHello") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	left, _ := journal.Pending()
	t.Fatalf("the uploaded records stayed in the journal: %q", left)
}
