package stream

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// freezer is a TCP proxy that models the TSPU freeze: it forwards each
// connection's client→server bytes in full, and server→client bytes only
// until budget of them have passed, then silently discards the rest. It
// never closes or resets the client's side on its own.
type freezer struct {
	ln     net.Listener
	target string
	budget int64

	mu    sync.Mutex
	conns int
}

func newFreezer(t *testing.T, target string, budget int64) *freezer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &freezer{ln: ln, target: target, budget: budget}
	t.Cleanup(func() { ln.Close() })
	go f.serve()
	return f
}

func (f *freezer) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.conns++
		f.mu.Unlock()
		go func() {
			s, err := net.Dial("tcp", f.target)
			if err != nil {
				c.Close()
				return
			}
			go func() { io.Copy(s, c); s.Close() }()
			// Down: the budget, then a black hole that keeps draining
			// the server, so it never sees back-pressure close anything.
			io.CopyN(c, s, f.budget)
			io.Copy(io.Discard, s)
			c.Close()
		}()
	}
}

func (f *freezer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

// TestClientRedialsFrozenConnection: a connection whose downlink a censor
// silently stops is reported as ModeTimeoutAtNBytes within the stall
// timeout and replaced, and the new connection carries data again.
func TestClientRedialsFrozenConnection(t *testing.T) {
	certPEM, keyPEM, err := SelfSigned([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", ListenerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	const budget = 16 << 10
	fz := newFreezer(t, ln.Addr().String(), budget)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	states := make(chan error, 64)
	c := Dial(ClientOptions{
		Addr: fz.ln.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"},
		Peer: netip.MustParseAddrPort("192.0.2.1:4433"), StallTimeout: 300 * time.Millisecond,
		OnState: func(err error) { states <- err },
	})
	t.Cleanup(func() { c.Close() })
	if err := <-states; err != nil {
		t.Fatal(err)
	}

	// The relay echoes 1 KB per packet from the client; the client sends
	// one every 10 ms, so the first connection freezes within a second.
	go func() {
		bufs, sizes, addrs := [][]byte{make([]byte, maxFrame)}, []int{0}, []netip.AddrPort{{}}
		down := bytes.Repeat([]byte{9}, 1024)
		for {
			if _, err := ln.ReadBatch(bufs, sizes, addrs); err != nil {
				return
			}
			ln.WriteBatch([][]byte{down}, addrs[:1])
		}
	}()
	received := make(chan struct{}, 1024)
	go func() {
		bufs, sizes, addrs := [][]byte{make([]byte, maxFrame)}, []int{0}, []netip.AddrPort{{}}
		for {
			if _, err := c.ReadBatch(bufs, sizes, addrs); err != nil {
				return
			}
			select {
			case received <- struct{}{}:
			default:
			}
		}
	}()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		up := bytes.Repeat([]byte{7}, 100)
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				c.WriteBatch([][]byte{up}, nil)
			}
		}
	}()

	deadline := time.After(10 * time.Second)
	var stalls int
	for stalls < 2 {
		select {
		case err := <-states:
			var f *Failure
			if err == nil {
				continue
			}
			if !errors.As(err, &f) || f.Mode != ModeTimeoutAtNBytes || f.At < budget {
				t.Fatalf("connection ended with %v, want %s past %d bytes", err, ModeTimeoutAtNBytes, budget)
			}
			stalls++
		case <-deadline:
			t.Fatalf("%d stalls reported in 10 s over %d connections, want 2", stalls, fz.count())
		}
	}
	// The redial follows the second stall at once.
	for start := time.Now(); fz.count() < 3; time.Sleep(10 * time.Millisecond) {
		if time.Since(start) > time.Second {
			t.Fatalf("%d connections a second after two stalls, want a third", fz.count())
		}
	}
	// Data flows again on the latest connection.
	for len(received) > 0 {
		<-received
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Error("nothing received after the redial")
	}
}

// TestIdleConnectionDoesNotStall: with nothing written, silence is not a
// stall, however long it lasts.
func TestIdleConnectionDoesNotStall(t *testing.T) {
	certPEM, keyPEM, err := SelfSigned([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", ListenerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	states := make(chan error, 16)
	c := Dial(ClientOptions{
		Addr: ln.Addr().String(), TLS: &tls.Config{RootCAs: roots},
		Peer: netip.MustParseAddrPort("192.0.2.1:4433"), StallTimeout: 100 * time.Millisecond,
		OnState: func(err error) { states <- err },
	})
	t.Cleanup(func() { c.Close() })
	if err := <-states; err != nil {
		t.Fatal(err)
	}
	// One exchange, answered, then silence.
	c.WriteBatch([][]byte{bytes.Repeat([]byte{1}, 100)}, nil)
	_, from := readOne(t, ln)
	ln.WriteBatch([][]byte{bytes.Repeat([]byte{2}, 100)}, []netip.AddrPort{from})
	readOne(t, c)
	select {
	case err := <-states:
		t.Fatalf("idle connection ended: %v", err)
	case <-time.After(time.Second):
	}
}

// frozenRelay starts a listener behind a freezer with the given budget and
// a relay loop that answers each packet from the client with 1 KB, on the
// connection it came from.
func frozenRelay(t *testing.T, budget int64) (*freezer, *x509.CertPool) {
	t.Helper()
	certPEM, keyPEM, err := SelfSigned([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", ListenerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		bufs, sizes, addrs := [][]byte{make([]byte, maxFrame)}, []int{0}, []netip.AddrPort{{}}
		down := bytes.Repeat([]byte{9}, 1024)
		for {
			if _, err := ln.ReadBatch(bufs, sizes, addrs); err != nil {
				return
			}
			ln.WriteBatch([][]byte{down}, addrs[:1])
		}
	}()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return newFreezer(t, ln.Addr().String(), budget), roots
}

// pump writes a packet every 5 ms and counts packets received, until the
// test ends.
func pump(t *testing.T, c *Client) *atomic.Int64 {
	var got atomic.Int64
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		bufs, sizes, addrs := [][]byte{make([]byte, maxFrame)}, []int{0}, []netip.AddrPort{{}}
		for {
			if _, err := c.ReadBatch(bufs, sizes, addrs); err != nil {
				return
			}
			got.Add(1)
		}
	}()
	go func() {
		up := bytes.Repeat([]byte{7}, 100)
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
				c.WriteBatch([][]byte{up}, nil)
			}
		}
	}()
	return &got
}

// TestClientLearnsCapAndRotates: after two stalls at the same byte count,
// the carrier rotates connections before the cap, so data keeps flowing
// without further stalls.
func TestClientLearnsCapAndRotates(t *testing.T) {
	const budget = 16 << 10
	fz, roots := frozenRelay(t, budget)
	states := make(chan error, 256)
	learned := make(chan int64, 4)
	c := Dial(ClientOptions{
		Addr: fz.ln.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"},
		Peer: netip.MustParseAddrPort("192.0.2.1:4433"), StallTimeout: 300 * time.Millisecond,
		OnState: func(err error) { states <- err }, OnLearn: func(b int64) { learned <- b },
	})
	t.Cleanup(func() { c.Close() })
	got := pump(t, c)

	var b int64
	select {
	case b = <-learned:
	case <-time.After(10 * time.Second):
		t.Fatal("no budget learned in 10 s")
	}
	if b < budget/4 || b > budget/2+2048 {
		t.Errorf("learned budget %d, want about half of %d", b, budget)
	}
	// From here on, no stalls: drain what was reported, then watch.
	time.Sleep(300 * time.Millisecond)
	for len(states) > 0 {
		<-states
	}
	conns, before := fz.count(), got.Load()
	window := time.After(2 * time.Second)
	for done := false; !done; {
		select {
		case err := <-states:
			if err != nil {
				t.Errorf("after learning: %v", err)
			}
		case <-window:
			done = true
		}
	}
	if n := got.Load() - before; n < 200 {
		t.Errorf("%d packets received in 2 s after learning, want ≥ 200 (one per 5 ms write, less rotation gaps)", n)
	}
	if fz.count()-conns < 5 {
		t.Errorf("%d connections in 2 s after learning, want rotations", fz.count()-conns)
	}
}

// TestClientRotatesConfiguredBudget: with RotateBytes, no connection
// ever reaches the cap.
func TestClientRotatesConfiguredBudget(t *testing.T) {
	const budget = 16 << 10
	fz, roots := frozenRelay(t, budget)
	states := make(chan error, 256)
	c := Dial(ClientOptions{
		Addr: fz.ln.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"},
		Peer: netip.MustParseAddrPort("192.0.2.1:4433"), StallTimeout: 300 * time.Millisecond,
		RotateBytes: budget / 2, OnState: func(err error) { states <- err },
	})
	t.Cleanup(func() { c.Close() })
	got := pump(t, c)
	window := time.After(2 * time.Second)
	for done := false; !done; {
		select {
		case err := <-states:
			if err != nil {
				t.Errorf("rotating carrier: %v", err)
			}
		case <-window:
			done = true
		}
	}
	if n := got.Load(); n < 200 {
		t.Errorf("%d packets received in 2 s, want ≥ 200", n)
	}
}
