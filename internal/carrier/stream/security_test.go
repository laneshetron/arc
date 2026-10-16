package stream

import (
	"crypto/tls"
	"crypto/x509"
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
	peer    netip.AddrPort
}

func (c *handshakeReadConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.peer) }

func (c *handshakeReadConn) Read(b []byte) (int, error) {
	c.once.Do(func() { c.started <- struct{}{} })
	return c.Conn.Read(b)
}

func TestPendingTLSHandshakesCountTowardAdmissionLimit(t *testing.T) {
	ln := &admissionListener{conns: make(chan net.Conn, 3)}
	started := make(chan struct{}, 3)
	peers := make([]net.Conn, 0, 3)
	for range 3 {
		server, peer := net.Pipe()
		peers = append(peers, peer)
		defer peer.Close()
		defer server.Close()
		ln.conns <- tls.Server(&handshakeReadConn{Conn: server, started: started, peer: netip.MustParseAddrPort("192.0.2.1:1234")}, &tls.Config{MinVersion: tls.VersionTLS13})
	}
	close(ln.conns)
	l := &Listener{ln: ln, opts: ListenerOptions{MaxConns: 1, MaxPending: 1, MaxConnsPerSource: 4, MaxPendingPerSource: 4, HandshakeTimeout: 3 * time.Second}, reg: newRegistry(0, 0, 0), connections: map[*tls.Conn]*acceptedConn{}, sources: map[netip.Addr]int{}, pendingSources: map[netip.Addr]int{}}
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

func TestTLSSeparatePendingAndPeerBudgets(t *testing.T) {
	for _, tc := range []struct {
		name                                         string
		maxPending, maxPerPeer, pendingPerPeer, want int
	}{
		{"pending", 2, 10, 1, 2}, {"all-connections-per-peer", 10, 1, 10, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln := &admissionListener{conns: make(chan net.Conn, 4)}
			started := make(chan struct{}, 4)
			for _, ip := range []string{"192.0.2.1:1", "192.0.2.1:2", "192.0.2.2:1", "192.0.2.3:1"} {
				server, peer := net.Pipe()
				defer peer.Close()
				defer server.Close()
				ln.conns <- tls.Server(&handshakeReadConn{Conn: server, started: started, peer: netip.MustParseAddrPort(ip)}, &tls.Config{MinVersion: tls.VersionTLS13})
			}
			close(ln.conns)
			l := &Listener{ln: ln, opts: ListenerOptions{MaxConns: 10, MaxPending: tc.maxPending, MaxConnsPerSource: tc.maxPerPeer, MaxPendingPerSource: tc.pendingPerPeer, HandshakeTimeout: 3 * time.Second}, reg: newRegistry(0, 0, 0), connections: map[*tls.Conn]*acceptedConn{}, sources: map[netip.Addr]int{}, pendingSources: map[netip.Addr]int{}}
			l.accept()
			l.mu.Lock()
			got := len(l.connections)
			pending := l.pending
			first := l.sources[netip.MustParseAddr("192.0.2.1")]
			l.mu.Unlock()
			if got != tc.want || pending != tc.want || first != 1 {
				t.Fatalf("admitted=%d pending=%d first-peer=%d", got, pending, first)
			}
			for range tc.want {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("admitted handshake not started")
				}
			}
			l.Close()
		})
	}
}

func TestPendingTLSTimeoutReleasesAllBudgets(t *testing.T) {
	server, peer := net.Pipe()
	defer peer.Close()
	defer server.Close()
	ln := &admissionListener{conns: make(chan net.Conn, 1)}
	started := make(chan struct{}, 1)
	ln.conns <- tls.Server(&handshakeReadConn{Conn: server, started: started, peer: netip.MustParseAddrPort("192.0.2.1:1")}, &tls.Config{MinVersion: tls.VersionTLS13})
	close(ln.conns)
	l := &Listener{ln: ln, opts: ListenerOptions{MaxConns: 1, MaxPending: 1, MaxConnsPerSource: 1, MaxPendingPerSource: 1, HandshakeTimeout: 30 * time.Millisecond}, reg: newRegistry(0, 0, 0), connections: map[*tls.Conn]*acceptedConn{}, sources: map[netip.Addr]int{}, pendingSources: map[netip.Addr]int{}}
	l.accept()
	defer l.Close()
	deadline := time.After(time.Second)
	for {
		l.mu.Lock()
		empty := len(l.connections) == 0 && l.pending == 0 && len(l.sources) == 0 && len(l.pendingSources) == 0
		l.mu.Unlock()
		if empty {
			break
		}
		select {
		case <-deadline:
			t.Fatal("TLS timeout retained admission state")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestServerNameInferredFromAddr(t *testing.T) {
	// With no explicit ServerName, the certificate is verified against
	// the host in Addr, not the IP the carrier resolved it to.
	certPEM, keyPEM, err := SelfSigned([]string{"localhost"}, time.Hour)
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
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	states := make(chan error, 16)
	c := Dial(ClientOptions{
		Addr: net.JoinHostPort("localhost", port), TLS: &tls.Config{RootCAs: roots},
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort(ln.Addr().String())},
		Peer:      netip.MustParseAddrPort("192.0.2.1:4433"), OnState: func(err error) { states <- err },
	})
	t.Cleanup(func() { c.Close() })
	select {
	case err := <-states:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not connect")
	}
}
