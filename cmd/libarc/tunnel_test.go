package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/keyfile"
	"github.com/laneshetron/arc/internal/session"
)

// chanDevice is a closable PacketDevice backed by channels.
type chanDevice struct {
	in        chan [][]byte
	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newChanDevice() *chanDevice {
	return &chanDevice{in: make(chan [][]byte, 4), out: make(chan []byte, 64), closed: make(chan struct{})}
}

func (d *chanDevice) Read() ([][]byte, error) {
	select {
	case p := <-d.in:
		return p, nil
	case <-d.closed:
		return nil, errors.New("closed")
	}
}

func (d *chanDevice) Write(pkts [][]byte) error {
	for _, p := range pkts {
		select {
		case d.out <- append([]byte(nil), p...):
		default:
		}
	}
	return nil
}

func (d *chanDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (d *chanDevice) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

// startRelay runs a relay on loopback until the test ends, and returns its
// address, its device and its public key.
func startRelay(t *testing.T) (netip.AddrPort, *chanDevice, []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	key, _ := crypto.GenerateStaticKey(nil)
	gw, err := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1300, DNS: netip.MustParseAddr("10.77.0.53"),
		Tokens: [][]byte{[]byte("secret")},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	dev := newChanDevice()
	t.Cleanup(func() { dev.Close() })
	go engine.RunRelay(ctx, engine.RelayConfig{
		Session: session.RelayConfig{Static: key}, Conn: conn, TUN: dev, Gateway: gw,
		Logger: slog.New(slog.DiscardHandler),
	})
	return conn.LocalAddr(), dev, key.Public
}

func configFor(t *testing.T, relay netip.AddrPort, relayKey []byte, extra map[string]any) []byte {
	t.Helper()
	k, _ := crypto.GenerateStaticKey(nil)
	c := map[string]any{
		"relay": relay.String(), "relay_key": keyfile.Encode(relayKey), "token": "secret",
		"private_key": keyfile.Encode(k.Private),
	}
	for name, v := range extra {
		c[name] = v
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// recorder collects a tunnel's events and answers network events with rc.
type recorder struct {
	mu     sync.Mutex
	events []map[string]any
	rc     int
	ch     chan map[string]any
}

func newRecorder(rc int) *recorder { return &recorder{rc: rc, ch: make(chan map[string]any, 1024)} }

func (r *recorder) fn(t *testing.T) func([]byte) int {
	return func(b []byte) int {
		var ev map[string]any
		if err := json.Unmarshal(b, &ev); err != nil {
			t.Errorf("event is not a JSON object: %q: %v", b, err)
			return 0
		}
		r.mu.Lock()
		r.events = append(r.events, ev)
		r.mu.Unlock()
		select {
		case r.ch <- ev:
		default:
		}
		if ev["event"] == "network" {
			return r.rc
		}
		return 0
	}
}

func (r *recorder) waitFor(t *testing.T, kind string) map[string]any {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-r.ch:
			if ev["event"] == kind {
				return ev
			}
		case <-deadline:
			t.Fatalf("no %q event within 5 s", kind)
		}
	}
}

func (r *recorder) snapshot() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]any(nil), r.events...)
}

func udpPacket(src, dst netip.Addr) []byte {
	p := make([]byte, 64)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, 17
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

// TestTunnel: a tunnel reports the leased network as a network event,
// carries packets over its device, logs as log events, and on stop sends
// a stopped event last, closes its device, and sends nothing after.
func TestTunnel(t *testing.T) {
	relay, relayDev, relayKey := startRelay(t)
	rec := newRecorder(0)
	dev := newChanDevice()
	tn, err := start(configFor(t, relay, relayKey, map[string]any{"log_level": "debug"}), dev, rec.fn(t))
	if err != nil {
		t.Fatal(err)
	}
	tn.begin()
	ev := rec.waitFor(t, "network")
	addr, err := netip.ParseAddr(ev["address"].(string))
	if err != nil || !netip.MustParsePrefix("10.77.0.0/24").Contains(addr) {
		t.Errorf("address %v, want one in 10.77.0.0/24", ev["address"])
	}
	if ev["prefix"] != 24.0 || ev["mtu"] != 1300.0 || ev["dns"] != "10.77.0.53" {
		t.Errorf("network event %v, want prefix 24, mtu 1300, dns 10.77.0.53", ev)
	}

	pkt := udpPacket(addr, netip.MustParseAddr("198.51.100.7"))
	dev.in <- [][]byte{pkt}
	select {
	case got := <-relayDev.out:
		if string(got) != string(pkt) {
			t.Errorf("relay received % x, want % x", got, pkt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet from the tunnel's device never reached the relay")
	}

	tn.stop()
	events := rec.snapshot()
	last := events[len(events)-1]
	if last["event"] != "stopped" || last["error"] != nil {
		t.Errorf("last event %v, want a stopped event without an error", last)
	}
	var starting bool
	for _, ev := range events {
		if ev["event"] == "log" && ev["msg"] == "starting" {
			starting = ev["level"] == "INFO" && ev["relay"] == relay.String()
		}
	}
	if !starting {
		t.Error(`no "starting" log event at INFO naming the relay`)
	}
	if !dev.isClosed() {
		t.Error("device still open after stop")
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(rec.snapshot()); n != len(events) {
		t.Errorf("%d events after stop returned", n-len(events))
	}
}

// TestTunnelAppRejectsNetwork: a nonzero answer to the network event ends
// the tunnel with an error in its stopped event.
func TestTunnelAppRejectsNetwork(t *testing.T) {
	relay, _, relayKey := startRelay(t)
	rec := newRecorder(7)
	dev := newChanDevice()
	tn, err := start(configFor(t, relay, relayKey, nil), dev, rec.fn(t))
	if err != nil {
		t.Fatal(err)
	}
	tn.begin()
	defer tn.stop()
	ev := rec.waitFor(t, "stopped")
	if msg, _ := ev["error"].(string); !strings.Contains(msg, "code 7") {
		t.Errorf("stopped event %v, want an error naming code 7", ev)
	}
	if !dev.isClosed() {
		t.Error("device still open after the tunnel ended")
	}
}

// TestStartRejectsBadConfig: start reports a config's first problem,
// closes the device, and sends no events.
func TestStartRejectsBadConfig(t *testing.T) {
	relay := netip.MustParseAddrPort("127.0.0.1:4433")
	key, _ := crypto.GenerateStaticKey(nil)
	for _, tc := range []struct {
		name   string
		config []byte
		want   string
	}{
		{"not JSON", []byte("{"), "config"},
		{"unknown member", configFor(t, relay, key.Public, map[string]any{"bind": "en0"}), "bind"},
		{"no relay", configFor(t, relay, key.Public, map[string]any{"relay": ""}), "relay"},
		{"short relay key", configFor(t, relay, key.Public, map[string]any{"relay_key": "AAAA"}), "relay_key"},
		{"no token", configFor(t, relay, key.Public, map[string]any{"token": ""}), "token"},
		{"no private key", configFor(t, relay, key.Public, map[string]any{"private_key": ""}), "private_key"},
		{"bad redundancy", configFor(t, relay, key.Public, map[string]any{"redundancy": "sometimes"}), "redundancy"},
		{"bad fec", configFor(t, relay, key.Public, map[string]any{"fec": "on"}), "fec"},
		{"bad split_tcp", configFor(t, relay, key.Public, map[string]any{"split_tcp": "yes"}), "split_tcp"},
		{"negative status_interval", configFor(t, relay, key.Public, map[string]any{"status_interval": -1}), "status_interval"},
		{"bad log_level", configFor(t, relay, key.Public, map[string]any{"log_level": "loud"}), "log_level"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := newChanDevice()
			var events int
			_, err := start(tc.config, dev, func([]byte) int { events++; return 0 })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("start = %v, want an error naming %s", err, tc.want)
			}
			if !dev.isClosed() {
				t.Error("device left open")
			}
			if events != 0 {
				t.Errorf("%d events from a tunnel that never started", events)
			}
		})
	}
}

// TestGenerateKey: the key pair is base64, and the public key is the
// private key's.
func TestGenerateKey(t *testing.T) {
	b, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	var k struct{ Private_key, Public_key string }
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatal(err)
	}
	priv, err := keyfile.Decode32(k.Private_key)
	if err != nil {
		t.Fatal(err)
	}
	static, err := keyfile.StaticFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	if keyfile.Encode(static.Public) != k.Public_key {
		t.Errorf("public key %s is not the private key's (%s)", k.Public_key, keyfile.Encode(static.Public))
	}
}

// TestConcurrentStopsWaitForOneShutdown: while one stop waits on a
// callback that has not returned, a second stop of the same handle waits
// for the same shutdown rather than returning early, and once both have
// returned no event follows.
func TestConcurrentStopsWaitForOneShutdown(t *testing.T) {
	relay, _, relayKey := startRelay(t)
	blocked, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var events []string
	stopsReturned := false
	fn := func(b []byte) int {
		var ev struct{ Event string }
		json.Unmarshal(b, &ev)
		mu.Lock()
		if stopsReturned {
			t.Errorf("event after both stops returned: %s", b)
		}
		events = append(events, ev.Event)
		mu.Unlock()
		if ev.Event == "network" {
			close(blocked)
			<-release
		}
		return 0
	}
	var reg registry
	tn, err := start(configFor(t, relay, relayKey, nil), newChanDevice(), fn)
	if err != nil {
		t.Fatal(err)
	}
	h := reg.add(tn)
	tn.begin()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("no network event within 5 s")
	}

	var wg sync.WaitGroup
	returned := make(chan int, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg.stop(h)
			returned <- i
		}()
	}
	select {
	case i := <-returned:
		t.Fatalf("stop %d returned while a callback was still running", i)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	mu.Lock()
	stopsReturned = true
	if events[len(events)-1] != "stopped" {
		t.Errorf("last event %q, want stopped", events[len(events)-1])
	}
	mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	reg.stop(h) // freed: ignored
}

// TestNoEventBeforeBegin: no event reaches the app before begin, which
// arc_start calls once it has set the handle, so the callback never runs
// on arc_start's thread or before the handle is set. That includes events
// start provokes itself, such as the warning for a journal that won't
// open. (Events may come before arc_start returns; arc.h says so.)
func TestNoEventBeforeBegin(t *testing.T) {
	relay, _, relayKey := startRelay(t)
	var begun atomic.Bool
	warned := make(chan struct{}, 1)
	fn := func(b []byte) int {
		if !begun.Load() {
			t.Errorf("event before begin: %s", b)
		}
		if strings.Contains(string(b), "running without a diagnostics journal") {
			select {
			case warned <- struct{}{}:
			default:
			}
		}
		return 0
	}
	tn, err := start(configFor(t, relay, relayKey, map[string]any{
		"journal": t.TempDir() + "/missing/journal.jsonl", "share_diagnostics": true,
	}), newChanDevice(), fn)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	begun.Store(true)
	tn.begin()
	defer tn.stop()
	select {
	case <-warned:
	case <-time.After(5 * time.Second):
		t.Error("no warning for the journal that would not open")
	}
}
