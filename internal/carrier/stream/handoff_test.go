package stream

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestRotationWaitsForHandoff walks a rotation's handoff through the real
// carrier: the client announces a new connection (Moved), the relay
// challenges the address it heard from, and the reply must leave on that
// same connection, or the relay never validates it (§14.5). With a budget
// that TLS setup has already used up, the challenge alone used to trigger
// the next rotation, sending the reply on a different connection.
func TestRotationWaitsForHandoff(t *testing.T) {
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
	c := Dial(ClientOptions{
		Addr: ln.Addr().String(), TLS: &tls.Config{RootCAs: roots},
		Peer:        netip.MustParseAddrPort("192.0.2.1:4433"),
		RotateBytes: 1, // less than the TLS handshake alone
	})
	t.Cleanup(func() { c.Close() })
	select {
	case <-c.Moved():
	case <-time.After(5 * time.Second):
		t.Fatal("no connection")
	}
	time.Sleep(300 * time.Millisecond) // the spare is up: a rotation would not wait

	frame := func(b byte) []byte { return bytes.Repeat([]byte{b}, 100) }
	c.WriteBatch([][]byte{frame(1)}, nil) // the PING
	got, a := readOne(t, ln)
	if got[0] != 1 {
		t.Fatalf("relay got %d first", got[0])
	}
	ln.WriteBatch([][]byte{frame(2)}, []netip.AddrPort{a}) // PATH_CHALLENGE
	if got, _ := readOne(t, c); got[0] != 2 {
		t.Fatalf("client got %d, want the challenge", got[0])
	}
	// The session answers on whatever connection is active by then; give
	// a rotation the challenge set off time to complete.
	time.Sleep(100 * time.Millisecond)
	c.WriteBatch([][]byte{frame(3)}, nil) // PATH_RESPONSE
	got, from := readOne(t, ln)
	if got[0] != 3 {
		t.Fatalf("relay got %d, want the response", got[0])
	}
	if from != a {
		t.Fatalf("response arrived from %v, but the relay challenged %v", from, a)
	}

	// Past the reserve, the budget applies again: the connection rotates.
	for len(c.Moved()) > 0 {
		<-c.Moved()
	}
	go func() {
		for range 40 { // 4 KB, more than handoffReserve
			ln.WriteBatch([][]byte{frame(4)}, []netip.AddrPort{a})
		}
	}()
	select {
	case <-c.Moved():
	case <-time.After(5 * time.Second):
		t.Fatal("no rotation once the reserve was used")
	}
}

// TestDrainCountsFramesInAFailedFlush: a frame the writer had already
// taken from the queue, and was flushing when the peer went away, never
// reached TCP and counts as unsent, as queued ones do.
func TestDrainCountsFramesInAFailedFlush(t *testing.T) {
	ours, peer := net.Pipe() // synchronous: a write blocks until the peer reads
	l := newLink(ours, netip.MustParseAddrPort("192.0.2.1:1"), 16, 0)
	done := make(chan error, 1)
	go func() { done <- l.run(make(chan inbound, 16)) }()
	l.send(bytes.Repeat([]byte{1}, 100), false)
	time.Sleep(100 * time.Millisecond)          // the writer is in its flush now
	l.send(bytes.Repeat([]byte{2}, 100), false) // and this one waits in the queue
	peer.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("link did not end")
	}
	if n := l.drain(); n != 2 {
		t.Errorf("drain = %d, want 2: one in the failed flush, one queued", n)
	}
}
