package stream

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type admissionListener struct{ conns chan net.Conn }

func (l *admissionListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l *admissionListener) Close() error   { return nil }
func (l *admissionListener) Addr() net.Addr { return nil }

type handshakeReadConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (c *handshakeReadConn) Read(b []byte) (int, error) {
	c.once.Do(func() { c.started <- struct{}{} })
	return c.Conn.Read(b)
}

func TestPendingTLSHandshakesCountTowardAdmissionLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln := &admissionListener{conns: make(chan net.Conn, 3)}
	started := make(chan struct{}, 3)
	peers := make([]net.Conn, 0, 3)
	for range 3 {
		server, peer := net.Pipe()
		peers = append(peers, peer)
		defer peer.Close()
		defer server.Close()
		ln.conns <- tls.Server(&handshakeReadConn{Conn: server, started: started}, &tls.Config{MinVersion: tls.VersionTLS13})
	}
	close(ln.conns)
	l := &Listener{ln: ln, opts: ListenerOptions{MaxConns: 1}, ctx: ctx, stop: cancel, links: map[netip.AddrPort]*link{}, connections: map[*tls.Conn]struct{}{}}
	// accept returns after all three attempts have either reserved a permit
	// or been rejected. No sleep or real sockets are needed to count them.
	l.accept()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first handshake did not start")
	}
	l.mu.Lock()
	admitted := len(l.connections)
	l.mu.Unlock()
	if admitted != 1 {
		t.Fatalf("admitted %d connections, limit 1", admitted)
	}
	for _, peer := range peers[1:] {
		peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("excess connection not closed")
		}
	}
	l.Close()
	peers[0].SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peers[0].Read(make([]byte, 1)); err == nil {
		t.Fatal("shutdown did not close pending handshake")
	}
	deadline := time.After(time.Second)
	for {
		l.mu.Lock()
		n := len(l.connections)
		l.mu.Unlock()
		if n == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("handshake permit leaked")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case <-started:
		t.Fatal("excess handshake performed TLS work")
	default:
	}
}
