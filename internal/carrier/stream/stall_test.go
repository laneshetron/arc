package stream

import (
	"bytes"
	"context"
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
	// hangAfter, when positive, holds every connection after the first
	// hangAfter open without forwarding anything: the dial's TCP handshake
	// succeeds and the TLS one never ends.
	hangAfter int
	// failConn, when positive, is the one connection (counting from 1)
	// closed at once, so that dial fails.
	failConn int

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
		hang := f.hangAfter > 0 && f.conns > f.hangAfter
		failed := f.failConn > 0 && f.conns == f.failConn
		f.mu.Unlock()
		if failed {
			c.Close()
			continue
		}
		if hang {
			go func() { io.Copy(io.Discard, c); c.Close() }()
			continue
		}
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
				c.WriteBatchEliciting([][]byte{up}, nil, []bool{true})
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

// TestIdleConnectionDoesNotStall: once every reply-eliciting packet has
// been answered, silence is not a stall, however long it lasts, and
// packets the relay owes no reply (ACK-only) do not make it one.
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
	// One exchange, answered, then an ACK-only packet, then silence.
	c.WriteBatchEliciting([][]byte{bytes.Repeat([]byte{1}, 100)}, nil, []bool{true})
	_, from := readOne(t, ln)
	ln.WriteBatch([][]byte{bytes.Repeat([]byte{2}, 100)}, []netip.AddrPort{from})
	readOne(t, c)
	c.WriteBatchEliciting([][]byte{bytes.Repeat([]byte{3}, 100)}, nil, []bool{false})
	readOne(t, ln)
	c.WriteBatch([][]byte{bytes.Repeat([]byte{4}, 100)}, nil) // no hint: elicits nothing
	readOne(t, ln)
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
				c.WriteBatchEliciting([][]byte{up}, nil, []bool{true})
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
		OnState: func(err error) { states <- err }, OnLearn: func(_ netip.AddrPort, b int64) { learned <- b },
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

// TestFastReplyDoesNotRearmStall: a reply that arrives before the write
// that elicited it has returned answers it. On a synchronous pipe the
// reply is read while the writer is still inside Flush; a link that armed
// stall detection after flushing would then wait for a reply already
// received and close a healthy connection.
func TestFastReplyDoesNotRearmStall(t *testing.T) {
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	go func() { // the peer: answer each frame at once
		fr := newFrameReader(far)
		buf := make([]byte, maxFrame)
		for {
			n, err := fr.next(buf)
			if err != nil {
				return
			}
			if _, err := far.Write(appendFrame(nil, buf[:n])); err != nil {
				return
			}
		}
	}()
	l := newLink(near, netip.AddrPort{}, 16, 0)
	l.stall = 100 * time.Millisecond
	in := make(chan inbound, 16)
	ran := make(chan error, 1)
	go func() { ran <- l.run(in) }()
	l.send(bytes.Repeat([]byte{5}, 100), true)
	select {
	case <-in:
	case <-time.After(2 * time.Second):
		t.Fatal("no reply")
	}
	select {
	case err := <-ran:
		t.Fatalf("answered link closed: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	l.close()
}

// TestActiveLinkHandledWhileSpareDials: a rotation is due but the spare
// is still dialing (here, forever). The active connection's stall must
// still be reported and the link dropped at once, not after the spare's
// dial gives up.
func TestActiveLinkHandledWhileSpareDials(t *testing.T) {
	const budget = 16 << 10
	fz, roots := frozenRelay(t, budget)
	fz.mu.Lock()
	fz.hangAfter = 1
	fz.mu.Unlock()
	states := make(chan error, 64)
	c := Dial(ClientOptions{
		Addr: fz.ln.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"},
		Peer: netip.MustParseAddrPort("192.0.2.1:4433"), StallTimeout: 300 * time.Millisecond,
		RotateBytes: budget / 4, OnState: func(err error) { states <- err },
	})
	t.Cleanup(func() { c.Close() })
	if err := <-states; err != nil {
		t.Fatal(err)
	}
	pump(t, c)
	start := time.Now()
	for {
		select {
		case err := <-states:
			var f *Failure
			if !errors.As(err, &f) || f.Mode != ModeTimeoutAtNBytes {
				continue
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Fatalf("stall reported after %v, want about the 300 ms stall timeout", d)
			}
			if c.Connected() {
				t.Error("still connected after the active link stalled")
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatal("stall of the active link not reported while the spare dialed")
		}
	}
}

// TestFrontUpgradeBounded: a front that completes TLS but never answers
// the HTTP upgrade fails the dial within connectTimeout.
func TestFrontUpgradeBounded(t *testing.T) {
	old := connectTimeout
	connectTimeout = 300 * time.Millisecond
	t.Cleanup(func() { connectTimeout = old })
	certPEM, keyPEM, err := SelfSigned([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { // handshake, read the upgrade, answer nothing
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, conn); conn.Close() }()
		}
	}()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	c := &Client{ctx: context.Background(), opts: ClientOptions{Addr: ln.Addr().String(),
		TLS: &tls.Config{RootCAs: roots}, Front: &FrontDialOptions{Token: "t"}, Queue: 1}}
	start := time.Now()
	d := c.connect()
	var f *Failure
	if !errors.As(d.err, &f) || f.Mode != ModeTimeoutAtNBytes {
		t.Fatalf("unanswered upgrade: %v, want %s", d.err, ModeTimeoutAtNBytes)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("unanswered upgrade took %v, want about %v", el, connectTimeout)
	}
}

// TestLearnedBudgetPerDestination: stalls on two addresses do not agree
// into a cap, and a cap learned on one address does not apply to another.
func TestLearnedBudgetPerDestination(t *testing.T) {
	a, b := netip.MustParseAddrPort("192.0.2.1:443"), netip.MustParseAddrPort("198.51.100.1:443")
	c := &Client{budgets: map[netip.AddrPort]int64{}, lastStall: map[netip.AddrPort]int64{}}
	c.learn(a, 16<<10)
	c.learn(b, 16<<10)
	if c.budget(a) != 0 || c.budget(b) != 0 {
		t.Fatalf("one stall on each address taught budgets %d, %d; want none", c.budget(a), c.budget(b))
	}
	c.learn(a, 17<<10)
	if c.budget(a) != 8<<10 {
		t.Errorf("two stalls on %v taught %d, want %d", a, c.budget(a), 8<<10)
	}
	if c.budget(b) != 0 {
		t.Errorf("%v got budget %d from %v's stalls", b, c.budget(b), a)
	}
}

// TestRefusedPacketDoesNotArmStall: a reply-eliciting packet the full
// queue refuses was never sent, so no reply is owed and the healthy
// link must not stall waiting for one.
func TestRefusedPacketDoesNotArmStall(t *testing.T) {
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	l := newLink(near, netip.AddrPort{}, 1, 0)
	l.stall = 100 * time.Millisecond
	if !l.send(bytes.Repeat([]byte{1}, 100), false) { // fills the queue
		t.Fatal("first packet refused")
	}
	if l.send(bytes.Repeat([]byte{2}, 100), true) {
		t.Fatal("second packet accepted by a full queue")
	}
	go func() { io.Copy(io.Discard, far) }() // the peer drains, owes nothing
	in := make(chan inbound, 1)
	ran := make(chan error, 1)
	go func() { ran <- l.run(in) }()
	select {
	case err := <-ran:
		t.Fatalf("healthy link closed: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	l.close()
}

// TestSpareRetriedAfterFailure: a spare dial that fails once is retried
// while the active link still works, so the carrier rotates before the
// cap instead of riding the link into a stall.
func TestSpareRetriedAfterFailure(t *testing.T) {
	const budget = 16 << 10
	fz, roots := frozenRelay(t, budget)
	fz.mu.Lock()
	fz.failConn = 2 // the first spare
	fz.mu.Unlock()
	states := make(chan error, 64)
	c := Dial(ClientOptions{
		Addr: fz.ln.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"},
		Peer: netip.MustParseAddrPort("192.0.2.1:4433"), StallTimeout: 300 * time.Millisecond,
		RotateBytes: budget / 2, OnState: func(err error) { states <- err },
	})
	t.Cleanup(func() { c.Close() })
	if err := <-states; err != nil {
		t.Fatal(err)
	}
	// Slow enough (1 KB per 50 ms) that the cap is ~0.8 s away: time for
	// the first spare to fail and a retry, 0.5 s later, to come up.
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		bufs, sizes, addrs := [][]byte{make([]byte, maxFrame)}, []int{0}, []netip.AddrPort{{}}
		for {
			if _, err := c.ReadBatch(bufs, sizes, addrs); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				c.WriteBatchEliciting([][]byte{bytes.Repeat([]byte{7}, 100)}, nil, []bool{true})
			}
		}
	}()
	window := time.After(3 * time.Second)
	for {
		select {
		case err := <-states:
			var f *Failure
			if errors.As(err, &f) && f.Mode == ModeTimeoutAtNBytes {
				t.Fatalf("active link stalled at the cap: the failed spare was not retried (%v)", err)
			}
		case <-window:
			if n := fz.count(); n < 4 {
				t.Errorf("%d connections in 3 s, want the failed spare, its retry, and rotations", n)
			}
			return
		}
	}
}
