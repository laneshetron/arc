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
	"slices"
	"sync"
	"testing"
	"time"
)

// camoPair starts a camouflage listener with a self-signed certificate for
// a cover name, and a camouflaged client connected to it.
func camoPair(t *testing.T, camo *Camouflage) (*Listener, *Client, chan error) {
	t.Helper()
	certPEM, keyPEM, err := SelfSigned([]string{"cover.example"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", ListenerOptions{
		TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Camouflage: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	states := make(chan error, 16)
	if err := camo.Validate(); err != nil {
		t.Fatal(err)
	}
	c := Dial(ClientOptions{
		Addr: ln.Addr().String(), TLS: &tls.Config{}, // no trust roots: the cover handshake is unverified
		Camouflage: &Camouflage{Name: "cover.example", Fingerprint: camo.Fingerprint, Fragment: camo.Fragment},
		Peer:       netip.MustParseAddrPort("192.0.2.1:4433"), OnState: func(err error) { states <- err },
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

func TestCamouflageExchange(t *testing.T) {
	for _, fp := range []string{"", "chrome"} {
		t.Run("fingerprint_"+fp, func(t *testing.T) {
			ln, c, _ := camoPair(t, &Camouflage{Fingerprint: fp, Fragment: 64})
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
		})
	}
}

func TestCamouflagePresentsCoverServerName(t *testing.T) {
	// The certificate matches only the endpoint, but the camouflage
	// presents the cover name, so a pinned client's verification of that
	// name fails: proof the ClientHello carries the cover name.
	certPEM, keyPEM, err := SelfSigned([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", ListenerOptions{
		TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Camouflage: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	states := make(chan error, 4)
	c := Dial(ClientOptions{Addr: ln.Addr().String(), TLS: &tls.Config{RootCAs: roots},
		Camouflage: &Camouflage{Name: "cover.example", Fingerprint: "chrome"},
		OnState:    func(err error) { states <- err }})
	defer c.Close()
	select {
	case err := <-states:
		if err == nil {
			t.Fatal("cover name did not take part in verification; client connected anyway")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no dial result")
	}
}

func TestCamouflagedClientNeedsCamouflageListener(t *testing.T) {
	// A camouflage client offers a browser's ALPN, which a plain
	// listener, requiring arc/1, must refuse.
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
	states := make(chan error, 4)
	c := Dial(ClientOptions{Addr: ln.Addr().String(), TLS: &tls.Config{},
		Camouflage: &Camouflage{Name: "127.0.0.1", Fingerprint: "chrome"},
		OnState:    func(err error) { states <- err }})
	defer c.Close()
	select {
	case err := <-states:
		if err == nil {
			t.Fatal("camouflaged client connected to a strict listener")
		}
		// The relay's refusal is a configuration fault, not interference.
		var f *Failure
		if errors.As(err, &f) && f.Mode == ModeKilledAfterServerHello {
			t.Fatalf("relay refusal blamed on the network: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no dial result")
	}
}

func TestCamouflageListenerKeepsBrowserConnection(t *testing.T) {
	// An ordinary browser-alike connection (browser ALPN, no ARC inside)
	// completes its handshake and stays open: the camouflage listener
	// does not reveal itself by refusing it.
	ln, _, _ := camoPair(t, &Camouflage{})
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Errorf("negotiated %q, want h2", p)
	}
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(make([]byte, 1))
	if timeout, ok := err.(interface{ Timeout() bool }); !ok || !timeout.Timeout() {
		t.Errorf("browser-alike connection failed instead of staying open: %v", err)
	}
}

func TestFragmentConnSplitsWrites(t *testing.T) {
	base := &fakeConn{}
	f := &fragmentConn{Conn: base, n: 100}
	if _, err := f.Write(bytes.Repeat([]byte{1}, 250)); err != nil {
		t.Fatal(err)
	}
	want := []int{100, 100, 50}
	if len(base.writes) != len(want) {
		t.Fatalf("writes were %v, want %v", base.writes, want)
	}
	for i, w := range base.writes {
		if w != want[i] {
			t.Fatalf("write %d carried %d bytes, want %d", i, w, want[i])
		}
	}
	f.clear = true
	if _, err := f.Write(bytes.Repeat([]byte{2}, 250)); err != nil {
		t.Fatal(err)
	}
	if base.writes[len(base.writes)-1] != 250 {
		t.Errorf("after clearing, write carried %d bytes, want 250", base.writes[len(base.writes)-1])
	}
}

// fakeConn records the size of each write.
type fakeConn struct {
	writes []int
	once   sync.Once
	done   chan struct{}
}

func (c *fakeConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, len(b))
	return len(b), nil
}
func (c *fakeConn) Read(b []byte) (int, error) { <-c.done; return 0, io.EOF }
func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// Without a cover name the camouflaged client presents the relay's own
// name and verifies it as the plain carrier does: a fingerprint or
// fragmentation alone must not turn verification off.
func TestCamouflageWithoutCoverVerifies(t *testing.T) {
	certPEM, keyPEM, err := SelfSigned([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", ListenerOptions{
		TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Camouflage: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	for _, camo := range []*Camouflage{{Fingerprint: "chrome"}, {Fragment: 64}} {
		dial := func(cfg *tls.Config) error {
			states := make(chan error, 4)
			c := Dial(ClientOptions{Addr: ln.Addr().String(), TLS: cfg, Camouflage: camo,
				OnState: func(err error) { states <- err }})
			defer c.Close()
			select {
			case err := <-states:
				return err
			case <-time.After(5 * time.Second):
				t.Fatal("no dial result")
				return nil
			}
		}
		// Untrusted certificate: refused here, and not blamed on the network.
		err := dial(&tls.Config{})
		var f *Failure
		if !errors.As(err, &f) || f.Mode != ModeDied {
			t.Errorf("%+v with an untrusted relay: %v, want a %s Failure", camo, err, ModeDied)
		}
		if err := dial(&tls.Config{RootCAs: roots}); err != nil {
			t.Errorf("%+v with a pinned CA: %v", camo, err)
		}
	}
}

// Configuration a fingerprinted handshake cannot honor is refused, not
// silently dropped.
func TestUTLSConfigRefusesVerifyConnection(t *testing.T) {
	_, err := utlsConfig(&tls.Config{VerifyConnection: func(tls.ConnectionState) error { return nil }})
	if err == nil {
		t.Fatal("VerifyConnection silently dropped")
	}
	called := false
	u, err := utlsConfig(&tls.Config{VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
		called = true
		return nil
	}})
	if err != nil || u.VerifyPeerCertificate == nil {
		t.Fatalf("VerifyPeerCertificate not carried: %v", err)
	}
	u.VerifyPeerCertificate(nil, nil)
	if !called {
		t.Fatal("wrong VerifyPeerCertificate carried")
	}
}

// captureHello runs cam's handshake against a listener that records the
// first TLS record (the ClientHello) and hangs up.
func captureHello(t *testing.T, cam *Camouflage) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			got <- nil
			return
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(conn, body); err != nil {
			got <- nil
			return
		}
		got <- append(hdr, body...)
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cam.Handshake(ctx, raw, ln.Addr().String(), &tls.Config{}) // fails: the listener hangs up
	hello := <-got
	if hello == nil {
		t.Fatal("no ClientHello captured")
	}
	return hello
}

// helloExtensions parses a ClientHello record into its extensions, by
// type, GREASE values left out (they are random by design).
func helloExtensions(t *testing.T, rec []byte) map[uint16][]byte {
	t.Helper()
	b := rec[5+4+2+32:] // record header, handshake header, version, random
	skip := func(lenBytes int) {
		n := 0
		for i := range lenBytes {
			n = n<<8 | int(b[i])
		}
		b = b[lenBytes+n:]
	}
	skip(1) // session ID
	skip(2) // cipher suites
	skip(1) // compression methods
	b = b[2:]
	exts := map[uint16][]byte{}
	for len(b) >= 4 {
		typ, n := uint16(b[0])<<8|uint16(b[1]), int(b[2])<<8|int(b[3])
		if typ&0x0f0f != 0x0a0a {
			exts[typ] = b[4 : 4+n]
		}
		b = b[4+n:]
	}
	return exts
}

func alpnOffer(data []byte) []string {
	var ps []string
	for b := data[2:]; len(b) > 0; b = b[1+int(b[0]):] {
		ps = append(ps, string(b[1:1+int(b[0])]))
	}
	return ps
}

const (
	extALPN    = 16
	extALPS    = 17513 // application_settings, as Chrome sent it until 2025
	extALPSNew = 17613 // its successor codepoint, in the current Chrome preset
)

// The front's ALPN override is written into the browser preset (which
// otherwise replaces it with h2, http/1.1); the rest of the hello keeps
// the preset's extensions, less ALPS for the h2 no longer offered.
func TestFingerprintHonorsALPNOverride(t *testing.T) {
	for _, fp := range []string{"chrome", "edge", "safari", "ios", "firefox"} {
		t.Run(fp, func(t *testing.T) {
			browser := helloExtensions(t, captureHello(t, &Camouflage{Name: "cover.example", Fingerprint: fp}))
			front := helloExtensions(t, captureHello(t, &Camouflage{Name: "cover.example", Fingerprint: fp, ALPN: []string{"http/1.1"}}))
			if got := alpnOffer(browser[extALPN]); !slices.Contains(got, "h2") {
				t.Errorf("browser profile offers %q, want the preset's h2 offer", got)
			}
			if got := alpnOffer(front[extALPN]); !slices.Equal(got, []string{"http/1.1"}) {
				t.Errorf("front profile offers %q, want only http/1.1", got)
			}
			if _, alps := browser[extALPSNew]; fp == "chrome" && !alps {
				t.Fatal("chrome preset sent no ALPS; the test no longer covers dropping it")
			}
			for typ := range browser {
				_, kept := front[typ]
				if alps := typ == extALPS || typ == extALPSNew; kept == alps {
					t.Errorf("extension %d: in the front hello %v, want %v", typ, kept, !alps)
				}
			}
			if len(front) > len(browser) {
				t.Errorf("front hello has extensions the preset lacks: %d vs %d", len(front), len(browser))
			}
		})
	}
}

func TestCheckFrontALPN(t *testing.T) {
	for alpn, ok := range map[string]bool{"http/1.1": true, "": true, "h2": false, "arc/1": false} {
		if err := checkFrontALPN(alpn); (err == nil) != ok {
			t.Errorf("checkFrontALPN(%q) = %v, want ok=%v", alpn, err, ok)
		}
	}
}
