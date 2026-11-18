package stream

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// allowlistProxy forwards TCP connections to target, but resets any whose
// ClientHello names a server other than allowed: a censor's allowlist
// rejecting a name, as TSPU's whitelists do.
func allowlistProxy(t *testing.T, target, allowed string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				rec := append(hdr, body...)
				sni := helloExtensions(t, rec)[0]
				if len(sni) < 5 || string(sni[5:]) != allowed {
					c.(*net.TCPConn).SetLinger(0) // a reset, as a censor sends
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				up.Write(rec)
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCoverNamesRotateOnRejection(t *testing.T) {
	certPEM, keyPEM, err := SelfSigned([]string{"allowed.example"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", ListenerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Camouflage: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	proxy := allowlistProxy(t, ln.Addr().String(), "allowed.example")

	states := make(chan error, 16)
	rejected := make(chan [2]string, 4)
	c := Dial(ClientOptions{
		Addr: proxy, TLS: &tls.Config{}, MaxBackoff: 100 * time.Millisecond,
		Camouflage: &Camouflage{Fingerprint: "chrome"},
		CoverNames: []string{"denied.example", "other.example", "allowed.example"},
		Peer:       netip.MustParseAddrPort("192.0.2.1:4433"),
		OnState:    func(err error) { states <- err },
		OnCoverRejected: func(name, next string) {
			rejected <- [2]string{name, next}
		},
	})
	defer c.Close()
	deadline := time.After(10 * time.Second)
	for failures := 0; ; {
		select {
		case err := <-states:
			if err == nil {
				if failures != 2 {
					t.Fatalf("connected after %d failures, want 2 (one per rejected name)", failures)
				}
				for _, want := range [][2]string{{"denied.example", "other.example"}, {"other.example", "allowed.example"}} {
					if got := <-rejected; got != want {
						t.Fatalf("rejected %v, want %v", got, want)
					}
				}
				// The working name stays: a fresh dial uses it.
				if got := c.coverFor(netip.MustParseAddrPort(proxy)); got != 2 {
					t.Fatalf("cover index %d after connecting, want 2", got)
				}
				return
			}
			var f *Failure
			if !errors.As(err, &f) || (f.Mode != ModeRSTAfterClientHello && f.Mode != ModeEOFAfterClientHello) {
				t.Fatalf("dial failure %v, want a reset or EOF after the ClientHello", err)
			}
			failures++
		case <-deadline:
			t.Fatal("did not connect with the allowed name")
		}
	}
}

// A failure that says nothing about the name keeps it; so does a single
// name, and a stale dial's failure.
func TestCoverNamesKeepOnOtherFailures(t *testing.T) {
	dest := netip.MustParseAddrPort("192.0.2.7:443")
	other := netip.MustParseAddrPort("192.0.2.8:443")
	c := &Client{opts: ClientOptions{Camouflage: &Camouflage{}, CoverNames: []string{"a.example", "b.example"}}}
	for _, mode := range []string{ModeConnectRefused, ModeConnectTimeout, ModeFrontRefused, ModeDied} {
		c.rejectCover(dest, 0, &Failure{Mode: mode})
		if c.coverFor(dest) != 0 {
			t.Fatalf("%s moved the cover name", mode)
		}
	}
	c.rejectCover(dest, 0, &Failure{Mode: ModeTimeoutAfterClientHello})
	if c.coverFor(dest) != 1 {
		t.Fatal("a timeout after the ClientHello kept the name")
	}
	if c.coverFor(other) != 0 {
		t.Fatal("a rejection at one endpoint moved another's name")
	}
	c.rejectCover(dest, 0, &Failure{Mode: ModeRSTAfterClientHello}) // a spare dial with the old name
	if c.coverFor(dest) != 1 {
		t.Fatal("a stale dial's failure skipped a name")
	}
	one := &Client{opts: ClientOptions{Camouflage: &Camouflage{}, CoverNames: []string{"a.example"}}}
	one.rejectCover(dest, 0, &Failure{Mode: ModeRSTAfterClientHello})
	if one.coverFor(dest) != 0 {
		t.Fatal("a single name moved")
	}
}

// TestCoverNamesWithSeveralEndpoints: each endpoint works through the
// names on its own, so a working pair is found even when the endpoint and
// name rotations would otherwise move in step. Here endpoint 1 approves
// only the second name and endpoint 2 approves none: in lockstep the
// carrier would alternate (1, first) and (2, second) forever.
func TestCoverNamesWithSeveralEndpoints(t *testing.T) {
	certPEM, keyPEM, err := SelfSigned([]string{"b.example"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", ListenerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Camouflage: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	good := allowlistProxy(t, ln.Addr().String(), "b.example")
	bad := allowlistProxy(t, ln.Addr().String(), "nothing.example")
	states := make(chan error, 32)
	c := Dial(ClientOptions{
		Addr: good, TLS: &tls.Config{}, MaxBackoff: 50 * time.Millisecond,
		Endpoints:  []netip.AddrPort{netip.MustParseAddrPort(good), netip.MustParseAddrPort(bad)},
		Camouflage: &Camouflage{Fingerprint: "chrome"},
		CoverNames: []string{"a.example", "b.example"},
		Peer:       netip.MustParseAddrPort("192.0.2.1:4433"),
		OnState:    func(err error) { states <- err },
	})
	defer c.Close()
	deadline := time.After(10 * time.Second)
	for failures := 0; ; {
		select {
		case err := <-states:
			if err == nil {
				if failures > 4 {
					t.Fatalf("connected after %d failures; want at most one per endpoint and name", failures)
				}
				return
			}
			failures++
		case <-deadline:
			t.Fatal("never found the endpoint and name that pass")
		}
	}
}
