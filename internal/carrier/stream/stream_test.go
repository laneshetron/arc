package stream

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"
)

func TestFrames(t *testing.T) {
	var b []byte
	pkts := [][]byte{bytes.Repeat([]byte{1}, 25), bytes.Repeat([]byte{2}, 1300), bytes.Repeat([]byte{3}, maxFrame)}
	for _, p := range pkts {
		b = appendFrame(b, p)
	}
	fr := newFrameReader(bytes.NewReader(b))
	buf := make([]byte, maxFrame)
	for i, want := range pkts {
		if i > 0 && !fr.buffered() {
			t.Errorf("frame %d not reported buffered", i)
		}
		n, err := fr.next(buf)
		if err != nil || !bytes.Equal(buf[:n], want) {
			t.Fatalf("frame %d: %d bytes, %v", i, n, err)
		}
	}
	if _, err := fr.next(buf); err != io.EOF {
		t.Errorf("after the last frame: %v, want EOF", err)
	}

	for _, bad := range [][]byte{{0, 24}, {0x40, 0x01}} { // below 25, above 16384
		if _, err := newFrameReader(bytes.NewReader(bad)).next(buf); !errors.Is(err, errFrameLen) {
			t.Errorf("length %x: %v, want errFrameLen", bad, err)
		}
	}
	truncated := appendFrame(nil, bytes.Repeat([]byte{4}, 100))[:50]
	if _, err := newFrameReader(bytes.NewReader(truncated)).next(buf); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated frame: %v", err)
	}
}

// pair starts a listener and a client connected to it.
func pair(t *testing.T) (*Listener, *Client, chan error) {
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
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	states := make(chan error, 16)
	c := Dial(ClientOptions{
		// No ServerName: it defaults to Addr's host, as with tls.Dial.
		Addr: ln.Addr().String(), TLS: &tls.Config{RootCAs: roots},
		Peer: netip.MustParseAddrPort("192.0.2.1:4433"), OnState: func(err error) { states <- err },
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
	return ln, c, states
}

func readOne(t *testing.T, r interface {
	ReadBatch([][]byte, []int, []netip.AddrPort) (int, error)
}) ([]byte, netip.AddrPort) {
	t.Helper()
	bufs, sizes, addrs := [][]byte{make([]byte, maxFrame)}, []int{0}, []netip.AddrPort{{}}
	done := make(chan error, 1)
	go func() { _, err := r.ReadBatch(bufs, sizes, addrs); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet")
	}
	return bufs[0][:sizes[0]], addrs[0]
}

func TestClientListenerExchange(t *testing.T) {
	ln, c, _ := pair(t)
	up := bytes.Repeat([]byte{7}, 1200)
	c.WriteBatch([][]byte{up}, nil)
	got, from := readOne(t, ln)
	if !bytes.Equal(got, up) || !IsStreamAddr(from) {
		t.Fatalf("relay got %d bytes from %v", len(got), from)
	}
	down := bytes.Repeat([]byte{8}, 300)
	ln.WriteBatch([][]byte{down}, []netip.AddrPort{from})
	got, peer := readOne(t, c)
	if !bytes.Equal(got, down) || peer != netip.MustParseAddrPort("192.0.2.1:4433") {
		t.Fatalf("client got %d bytes from %v", len(got), peer)
	}
	if IsStreamAddr(netip.MustParseAddrPort("192.0.2.1:4433")) || IsStreamAddr(netip.MustParseAddrPort("[2001:db8::1]:1")) {
		t.Error("ordinary address reported as a stream address")
	}
}

func TestClientReconnects(t *testing.T) {
	ln, c, states := pair(t)
	c.WriteBatch([][]byte{bytes.Repeat([]byte{1}, 100)}, nil)
	_, first := readOne(t, ln)
	// The relay drops the connection; the client redials and arrives from
	// a new address.
	ln.mu.Lock()
	ln.links[first].close()
	ln.mu.Unlock()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case err := <-states:
			if err == nil {
				c.WriteBatch([][]byte{bytes.Repeat([]byte{2}, 100)}, nil)
				_, second := readOne(t, ln)
				if second == first {
					t.Fatal("reconnected from the same address")
				}
				return
			}
		case <-deadline:
			t.Fatal("client did not reconnect")
		}
	}
}

func TestWrongALPNOrCertificateRejected(t *testing.T) {
	ln, _, _ := pair(t)
	// A client that does not trust the certificate never connects.
	states := make(chan error, 4)
	c := Dial(ClientOptions{Addr: ln.Addr().String(), TLS: &tls.Config{ServerName: "127.0.0.1"},
		OnState: func(err error) { states <- err }})
	defer c.Close()
	select {
	case err := <-states:
		if err == nil {
			t.Fatal("connected to an untrusted relay")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no dial result")
	}
	// A TLS client without the ARC ALPN is turned away.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Error("connection without ALPN arc/1 stayed open")
		}
		conn.Close()
	}
}

func TestFullQueueDrops(t *testing.T) {
	// A link whose writer is stuck drops instead of blocking the caller.
	k := newLink(nil, netip.AddrPort{}, 4, 0)
	sent := 0
	for range 10 {
		if k.send(make([]byte, 100)) {
			sent++
		}
	}
	if sent != 4 {
		t.Errorf("queued %d of 10 into a queue of 4", sent)
	}
}
