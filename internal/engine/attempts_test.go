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

// await is find for a line another goroutine may still be about to
// write: it polls for up to 5 s.
func (l *logLines) await(t *testing.T, msg string) map[string]any {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if r := l.find(t, msg); r != nil || time.Now().After(deadline) {
			return r
		}
	}
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
		{Peer: peer, Hello: true, BytesIn: 517, Err: errors.New("no certificate")},
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
	if strings.Join(stages, ",") != "tcp,client_hello,after_client_hello,after_server_hello,alpn" {
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

// TestAttemptLogBoundsHello cuts what an unauthenticated ClientHello
// can put in a line: a long SNI, many ALPN protocols, long ones.
func TestAttemptLogBoundsHello(t *testing.T) {
	a, lines := newTestAttemptLog()
	alpn := []string{strings.Repeat("x", 1000)}
	for range 100 {
		alpn = append(alpn, "h2")
	}
	a.TLS(stream.ConnReport{Peer: netip.MustParseAddrPort("198.51.100.7:50000"), Hello: true,
		ServerName: strings.Repeat("s", 5000), ALPN: alpn, Err: errors.New("EOF")})
	r := lines.find(t, "tls connection failed")
	if r == nil {
		t.Fatal("no line")
	}
	got := r["alpn"].([]any)
	if len(got) != attemptALPNs+1 || got[0] != strings.Repeat("x", attemptALPNBytes)+"..." ||
		got[attemptALPNs] != "(93 more)" {
		t.Errorf("alpn %v", got)
	}
	if sni := r["sni"].(string); len(sni) != attemptSNIBytes+3 {
		t.Errorf("sni of %d bytes", len(sni))
	}
}

// TestAttemptLogPeerChurn fills the peer map with carriers that just
// closed: a new carrier still gets its peer remembered, at the cost of
// the one closed first, while open carriers are kept.
func TestAttemptLogPeerChurn(t *testing.T) {
	a, _ := newTestAttemptLog()
	carrier := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte{0: 0xfd, 1: 0x61, 2: 0x72, 3: 0x63, 4: 0x2f, 5: 0x31, 14: byte(i >> 8), 15: byte(i)}), 0)
	}
	peer := func(i int) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), uint16(i)) }
	a.TLS(stream.ConnReport{Open: true, Peer: peer(1), Addr: carrier(1)}) // stays open
	for i := 2; i <= attemptPeers; i++ {
		a.notePeer(carrier(i), peer(i), true)
		a.notePeer(carrier(i), peer(i), false)
	}
	n := attemptPeers + 1
	a.notePeer(carrier(n), peer(n), true)
	if from, _ := a.source(carrier(n)); from != peer(n) {
		t.Errorf("new carrier: %v; want %v", from, peer(n))
	}
	if from, _ := a.source(carrier(1)); from != peer(1) {
		t.Errorf("open carrier evicted: %v", from)
	}
	if len(a.peers) != attemptPeers {
		t.Errorf("%d peers remembered", len(a.peers))
	}
}

// TestAttemptLogRefusals logs one line for what admission limits refused
// in an interval, and nothing for a quiet one.
func TestAttemptLogRefusals(t *testing.T) {
	a, lines := newTestAttemptLog()
	a.refusals(session.RelayStats{InitsRefusedFull: 3, InitsRefusedLimited: 40}, stream.Refusals{})
	a.refusals(session.RelayStats{InitsRefusedFull: 3, InitsRefusedLimited: 40}, stream.Refusals{})
	top := netip.MustParseAddr("198.51.100.7")
	a.refusals(session.RelayStats{InitsRefusedFull: 3, InitsRefusedLimited: 45},
		stream.Refusals{SourcePending: 9, Pending: 1, Sources: 2, TopSource: top, TopSourceRefusals: 9})
	recs := lines.records(t)
	if len(recs) != 2 {
		t.Fatalf("%d lines: %v", len(recs), recs)
	}
	if r := recs[0]; r["udp_relay_full"] != 3.0 || r["udp_rate_limited"] != 40.0 || r["tls_sources"] != nil {
		t.Errorf("first %v", r)
	}
	if r := recs[1]; r["udp_relay_full"] != 0.0 || r["udp_rate_limited"] != 5.0 || r["tls_source_handshakes_full"] != 9.0 ||
		r["tls_handshakes_full"] != 1.0 || r["tls_top_source"] != top.String() || r["tls_top_source_refused"] != 9.0 {
		t.Errorf("second %v", r)
	}
}

// rejectionRelay runs a relay with one account, token "tok", leasing
// from network, logging to the returned lines.
func rejectionRelay(t *testing.T, ctx context.Context, network string) (*udp.Conn, crypto.StaticKey, *logLines) {
	t.Helper()
	relayKey, _ := crypto.GenerateStaticKey(nil)
	gw, err := gateway.New(gateway.Config{Network: netip.MustParsePrefix(network), TunMTU: 1280,
		Accounts: []gateway.Account{{Name: "friend", Tokens: [][]byte{[]byte("tok")}}}})
	if err != nil {
		t.Fatal(err)
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
	return relayConn, relayKey, lines
}

func rejectionClient(t *testing.T, ctx context.Context, relay *udp.Conn, relayKey crypto.StaticKey, token string, established chan<- struct{}) *udp.Conn {
	t.Helper()
	key, _ := crypto.GenerateStaticKey(nil)
	conn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	tun := newMemTUN()
	t.Cleanup(func() { tun.Close() })
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: key, RelayPublic: relayKey.Public, Credential: []byte(token)},
		Relay:   relay.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: conn}}, TUN: tun,
		OnEstablished: func(wire.AuthResult) error {
			if established != nil {
				select {
				case established <- struct{}{}:
				default:
				}
			}
			return nil
		},
	})
	return conn
}

// waitRejection waits for msg, from conn over udp, and no session closing.
func waitRejection(t *testing.T, lines *logLines, msg string, conn *udp.Conn) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r := lines.find(t, msg); r != nil {
			if r["client"] != conn.LocalAddr().String() || r["carrier"] != "udp" {
				t.Errorf("rejection %v; want client %v over udp", r, conn.LocalAddr())
			}
			if lines.find(t, "session closed") != nil {
				t.Error("also logged a session closing")
			}
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %q logged: %v", msg, lines.records(t))
	return nil
}

// TestRelayLogsRejectedHandshake runs a client with an unknown token
// against a relay: the relay logs the rejection with the client's
// address, instead of a session closing at 0.0.0.0.
func TestRelayLogsRejectedHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, relayKey, lines := rejectionRelay(t, ctx, "10.77.0.1/24")
	conn := rejectionClient(t, ctx, relay, relayKey, "wrong", nil)
	waitRejection(t, lines, "handshake rejected: unknown token", conn)
}

// TestRelayLogsExhaustedPool: a valid token refused because the address
// pool is used up is not logged as an unknown token.
func TestRelayLogsExhaustedPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, relayKey, lines := rejectionRelay(t, ctx, "10.77.0.1/30") // one client address
	first := make(chan struct{}, 1)
	rejectionClient(t, ctx, relay, relayKey, "tok", first)
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("first client did not establish")
	}
	conn := rejectionClient(t, ctx, relay, relayKey, "tok", nil)
	r := waitRejection(t, lines, "handshake rejected: authorization failed", conn)
	if !strings.Contains(r["reason"].(string), gateway.ErrPoolExhausted.Error()) {
		t.Errorf("reason %v; want the pool exhausted", r["reason"])
	}
	if lines.find(t, "handshake rejected: unknown token") != nil {
		t.Error("logged as an unknown token")
	}
}
