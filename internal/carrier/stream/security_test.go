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
		ln.conns <- &handshakeReadConn{Conn: server, started: started, peer: netip.MustParseAddrPort("192.0.2.1:1234")}
	}
	close(ln.conns)
	opts := ListenerOptions{MaxConns: 1, MaxPending: 1, MaxConnsPerSource: 4, MaxPendingPerSource: 4, HandshakeTimeout: 3 * time.Second}
	l := &Listener{ln: ln, tls: &tls.Config{MinVersion: tls.VersionTLS13}, opts: opts, reg: newRegistry(0, 0, 0), adm: newAdmission(opts.limits())}
	// accept returns after all three attempts have either reserved a permit
	// or been rejected. No sleep or real sockets are needed to count them.
	l.accept()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first handshake did not start")
	}
	admitted, _, _, _ := l.adm.counts()
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
		n, _, _, _ := l.adm.counts()
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
		refused                                      Refusals
	}{
		{"pending", 2, 10, 1, 2, Refusals{SourcePending: 1, Pending: 1, Sources: 2}},
		{"all-connections-per-peer", 10, 1, 10, 3, Refusals{Source: 1, Sources: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln := &admissionListener{conns: make(chan net.Conn, 4)}
			started := make(chan struct{}, 4)
			for _, ip := range []string{"192.0.2.1:1", "192.0.2.1:2", "192.0.2.2:1", "192.0.2.3:1"} {
				server, peer := net.Pipe()
				defer peer.Close()
				defer server.Close()
				ln.conns <- &handshakeReadConn{Conn: server, started: started, peer: netip.MustParseAddrPort(ip)}
			}
			close(ln.conns)
			opts := ListenerOptions{MaxConns: 10, MaxPending: tc.maxPending, MaxConnsPerSource: tc.maxPerPeer, MaxPendingPerSource: tc.pendingPerPeer, HandshakeTimeout: 3 * time.Second}
			l := &Listener{ln: ln, tls: &tls.Config{MinVersion: tls.VersionTLS13}, opts: opts, reg: newRegistry(0, 0, 0), adm: newAdmission(opts.limits())}
			l.accept()
			got, pending, _, _ := l.adm.counts()
			l.adm.mu.Lock()
			first := l.adm.sources[netip.MustParseAddr("192.0.2.1")]
			l.adm.mu.Unlock()
			if got != tc.want || pending != tc.want || first != 1 {
				t.Fatalf("admitted=%d pending=%d first-peer=%d", got, pending, first)
			}
			r := l.Refusals()
			if r.Full != tc.refused.Full || r.Pending != tc.refused.Pending || r.Source != tc.refused.Source ||
				r.SourcePending != tc.refused.SourcePending || r.Sources != tc.refused.Sources || r.TopSourceRefusals != 1 {
				t.Errorf("refusals %+v; want %+v", r, tc.refused)
			}
			if r := l.Refusals(); r.Total() != 0 || r.Sources != 0 {
				t.Errorf("refusals not reset: %+v", r)
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
	ln.conns <- &handshakeReadConn{Conn: server, started: started, peer: netip.MustParseAddrPort("192.0.2.1:1")}
	close(ln.conns)
	opts := ListenerOptions{MaxConns: 1, MaxPending: 1, MaxConnsPerSource: 1, MaxPendingPerSource: 1, HandshakeTimeout: 30 * time.Millisecond}
	l := &Listener{ln: ln, tls: &tls.Config{MinVersion: tls.VersionTLS13}, opts: opts, reg: newRegistry(0, 0, 0), adm: newAdmission(opts.limits())}
	l.accept()
	defer l.Close()
	deadline := time.After(time.Second)
	for {
		conns, pending, sources, pendingSources := l.adm.counts()
		empty := conns == 0 && pending == 0 && sources == 0 && pendingSources == 0
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
