package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/stream"
	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// logLines collects JSON log records, safe for concurrent writers.
type logLines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logLines) records(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func (l *logLines) find(t *testing.T, msg string) map[string]any {
	t.Helper()
	for _, r := range l.records(t) {
		if r["msg"] == msg {
			return r
		}
	}
	return nil
}

func newTestAttemptLog() (*AttemptLog, *logLines) {
	lines := &logLines{}
	return NewAttemptLog(slog.New(slog.NewJSONHandler(lines, nil))), lines
}

func TestAttemptLogRateLimit(t *testing.T) {
	a, _ := newTestAttemptLog()
	now := time.Unix(1_000_000, 0)
	for i := range attemptLinesPerMinute {
		if n, ok := a.allow(now); !ok || n != 0 {
			t.Fatalf("line %d: suppressed %d, allowed %v", i, n, ok)
		}
	}
	for range 5 {
		if _, ok := a.allow(now); ok {
			t.Fatal("allowed past the limit")
		}
	}
	// A second later, one line's worth has refilled; it counts the five.
	if n, ok := a.allow(now.Add(time.Second)); !ok || n != 5 {
		t.Fatalf("after a second: suppressed %d, allowed %v; want 5, true", n, ok)
	}
	if n, ok := a.allow(now.Add(time.Second)); ok || n != 0 {
		t.Fatal("allowed a second line after one second")
	}
}

// TestAttemptLogTLSStages names where each failed TLS connection stopped.
func TestAttemptLogTLSStages(t *testing.T) {
	a, lines := newTestAttemptLog()
	peer := netip.MustParseAddrPort("198.51.100.7:50000")
	for _, r := range []stream.ConnReport{
		{Peer: peer, Err: errors.New("EOF")},
		{Peer: peer, BytesIn: 100, Err: errors.New("EOF")},
		{Peer: peer, Hello: true, ServerName: "cover.example", BytesIn: 517, BytesOut: 1800, Err: errors.New("connection reset by peer")},
		{Peer: peer, Hello: true, BytesIn: 517, BytesOut: 1800, Err: stream.ErrALPN},
	} {
		a.TLS(r)
	}
	var stages []string
	for _, r := range lines.records(t) {
		if r["msg"] != "tls connection failed" || r["peer"] != peer.String() {
			t.Errorf("line %v", r)
		}
		stages = append(stages, r["stage"].(string))
	}
	if strings.Join(stages, ",") != "tcp,client_hello,server_hello,alpn" {
		t.Errorf("stages %v", stages)
	}
}

// TestAttemptLogCarrierPeers maps a TLS carrier's synthetic address to its
// TCP peer while it is open and for a while after.
func TestAttemptLogCarrierPeers(t *testing.T) {
	a, lines := newTestAttemptLog()
	peer := netip.MustParseAddrPort("198.51.100.7:50000")
	carrier := netip.MustParseAddrPort("[fd61:7263:2f31::5]:0")
	a.TLS(stream.ConnReport{Open: true, Peer: peer, Addr: carrier})
	if from, kind := a.source(carrier); from != peer || kind != "tls" {
		t.Errorf("open carrier: %v %s", from, kind)
	}
	a.TLS(stream.ConnReport{Peer: peer, Addr: carrier, BytesIn: 4000, Duration: 3 * time.Second, Err: errors.New("EOF")})
	if from, _ := a.source(carrier); from != peer {
		t.Errorf("closed carrier: %v", from)
	}
	if r := lines.find(t, "tls carrier closed"); r == nil || r["carrier"] != carrier.String() || r["seconds"] != 3.0 {
		t.Errorf("carrier line %v", r)
	}
	udpAddr := netip.MustParseAddrPort("203.0.113.9:4000")
	if from, kind := a.source(udpAddr); from != udpAddr || kind != "udp" {
		t.Errorf("udp: %v %s", from, kind)
	}
}

// TestRelayLogsRejectedHandshake runs a client with an unknown token
// against a relay: the relay logs the rejection with the client's
// address, instead of a session closing at 0.0.0.0.
func TestRelayLogsRejectedHandshake(t *testing.T) {
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
	attempts, lines := newTestAttemptLog()
	go RunRelay(ctx, RelayConfig{
		Session: session.RelayConfig{Static: relayKey, ResetSecret: [32]byte{1}, NoStreams: true},
		Conn:    relayConn, TUN: relayTUN, Gateway: gw, Logger: slog.New(slog.NewJSONHandler(lines, nil)), Attempts: attempts,
	})

	key, _ := crypto.GenerateStaticKey(nil)
	conn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tun := newMemTUN()
	defer tun.Close()
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: key, RelayPublic: relayKey.Public, Credential: []byte("wrong")},
		Relay:   relayConn.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: conn}}, TUN: tun,
		OnEstablished: func(wire.AuthResult) error { return nil },
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r := lines.find(t, "handshake rejected: unknown token"); r != nil {
			if r["client"] != conn.LocalAddr().String() || r["carrier"] != "udp" {
				t.Errorf("rejection %v; want client %v over udp", r, conn.LocalAddr())
			}
			if lines.find(t, "session closed") != nil {
				t.Error("also logged a session closing")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no rejection logged: %v", lines.records(t))
}
