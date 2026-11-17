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
