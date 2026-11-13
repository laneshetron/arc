package stream

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// reportingListener starts a listener whose reports arrive on the
// returned channel, and returns the PEM of its certificate.
func reportingListener(t *testing.T) (*Listener, chan ConnReport, []byte) {
	t.Helper()
	certPEM, keyPEM, err := SelfSigned([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	reports := make(chan ConnReport, 16)
	ln, err := Listen("127.0.0.1:0", ListenerOptions{
		TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, HandshakeTimeout: 2 * time.Second,
		Report: func(r ConnReport) { reports <- r },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, reports, certPEM
}

func nextReport(t *testing.T, reports chan ConnReport) ConnReport {
	t.Helper()
	select {
	case r := <-reports:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no report")
		return ConnReport{}
	}
}

// TestListenerReportsFailures reports a connection for each way one can
// end before becoming a carrier: nothing sent, a partial ClientHello, a
// handshake the client refuses, and one with no ALPN.
func TestListenerReportsFailures(t *testing.T) {
	ln, reports, _ := reportingListener(t)
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c := dial()
	local, _ := netip.ParseAddrPort(c.LocalAddr().String())
	c.Close()
	if r := nextReport(t, reports); r.Open || r.Addr.IsValid() || r.Hello || r.BytesIn != 0 || r.Err == nil || r.Peer != local {
		t.Errorf("silent connection: %+v; want a failure from %v with nothing read", r, local)
	}

	c = dial()
	c.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01}) // a ClientHello's first bytes
	c.Close()
	if r := nextReport(t, reports); r.Hello || r.BytesIn != 6 || r.Err == nil {
		t.Errorf("partial ClientHello: %+v; want 6 bytes read and no hello", r)
	}

	// The client does not trust the certificate and aborts after the
	// relay's answer.
	if conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "cover.example.org", NextProtos: []string{ALPN}}); err == nil {
		conn.Close()
		t.Fatal("handshake with an untrusted certificate succeeded")
	}
	if r := nextReport(t, reports); !r.Hello || r.ServerName != "cover.example.org" || !slices.Equal(r.ALPN, []string{ALPN}) ||
		r.BytesOut == 0 || r.Err == nil || r.Addr.IsValid() {
		t.Errorf("refused certificate: %+v; want the hello's SNI and ALPN, an answer sent, and an error", r)
	}

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.Read(make([]byte, 1))
	conn.Close()
	if r := nextReport(t, reports); !errors.Is(r.Err, ErrALPN) || !r.Hello || r.Addr.IsValid() {
		t.Errorf("no ALPN: %+v; want ErrALPN", r)
	}
}

// TestListenerReportsCarrier reports a carrier when it opens, with its
// synthetic address, and when it ends, with what it carried.
func TestListenerReportsCarrier(t *testing.T) {
	ln, reports, certPEM := reportingListener(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	states := make(chan error, 4)
	c := Dial(ClientOptions{Addr: ln.Addr().String(), TLS: &tls.Config{RootCAs: roots},
		Peer: netip.MustParseAddrPort("192.0.2.1:4433"), OnState: func(err error) { states <- err }})
	defer c.Close()
	if err := <-states; err != nil {
		t.Fatal(err)
	}
	open := nextReport(t, reports)
	if !open.Open || !IsStreamAddr(open.Addr) || !open.Peer.IsValid() || !slices.Equal(open.ALPN, []string{ALPN}) {
		t.Fatalf("open: %+v", open)
	}
	c.WriteBatch([][]byte{bytes.Repeat([]byte{1}, 1000)}, nil)
	if _, from := readOne(t, ln); from != open.Addr {
		t.Fatalf("packet from %v, carrier %v", from, open.Addr)
	}
	c.Close()
	closed := nextReport(t, reports)
	if closed.Open || closed.Addr != open.Addr || closed.Peer != open.Peer || closed.BytesIn < 1000 || closed.Duration < open.Duration {
		t.Errorf("closed: %+v; open was %+v", closed, open)
	}
}

// TestFrontReportsCarrierOnly reports a carrier riding the front's
// upgrade, with the SNI it presented, but not a visitor.
func TestFrontReportsCarrierOnly(t *testing.T) {
	reports := make(chan ConnReport, 16)
	f, c, _ := frontPair(t, func(o *FrontOptions) { o.Report = func(r ConnReport) { reports <- r } })
	open := nextReport(t, reports)
	if !open.Open || !IsStreamAddr(open.Addr) || open.ServerName != "cdn.example" {
		t.Fatalf("open: %+v", open)
	}
	visitor, err := tls.Dial("tcp", f.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	visitor.Close()
	c.WriteBatch([][]byte{bytes.Repeat([]byte{1}, 500)}, nil)
	readOne(t, f)
	c.Close()
	closed := nextReport(t, reports)
	if closed.Open || closed.Addr != open.Addr || closed.BytesIn < 500 {
		t.Errorf("closed: %+v; open was %+v", closed, open)
	}
	select {
	case r := <-reports:
		t.Errorf("reported a visitor: %+v", r)
	case <-time.After(200 * time.Millisecond):
	}
}
