package stream

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

const frontToken = "some-token"

// startFront starts a front with the test token and a certificate for
// the cover name, returning it with the certificate PEM for pinning.
// mods adjust the options before the front starts.
func startFront(t *testing.T, mods ...func(*FrontOptions)) (*Front, []byte) {
	t.Helper()
	certPEM, keyPEM, err := SelfSigned([]string{"cdn.example"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	opts := FrontOptions{
		TLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
		Tokens: [][]byte{[]byte(frontToken)},
	}
	for _, mod := range mods {
		mod(&opts)
	}
	f, err := ListenFront("127.0.0.1:0", opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f, certPEM
}

// frontPair starts a front and a client carrier riding its upgrade.
func frontPair(t *testing.T, mods ...func(*FrontOptions)) (*Front, *Client, chan error) {
	t.Helper()
	f, certPEM := startFront(t, mods...)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	states := make(chan error, 16)
	c := Dial(ClientOptions{
		Addr: f.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: "cdn.example"},
		Front: &FrontDialOptions{Token: frontToken},
		Peer:  netip.MustParseAddrPort("192.0.2.1:4433"), OnState: func(err error) { states <- err },
	})
	t.Cleanup(func() { c.Close() })
	select {
	case err := <-states:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not connect through the front")
	}
	return f, c, states
}

func TestFrontCarrierExchange(t *testing.T) {
	f, c, _ := frontPair(t)
	up := bytes.Repeat([]byte{7}, 1200)
	c.WriteBatch([][]byte{up}, nil)
	got, from := readOne(t, f)
	if !bytes.Equal(got, up) || !IsStreamAddr(from) {
		t.Fatalf("relay got %d bytes from %v", len(got), from)
	}
	down := bytes.Repeat([]byte{8}, 300)
	f.WriteBatch([][]byte{down}, []netip.AddrPort{from})
	got, peer := readOne(t, c)
	if !bytes.Equal(got, down) || peer != netip.MustParseAddrPort("192.0.2.1:4433") {
		t.Fatalf("client got %d bytes from %v", len(got), peer)
	}
}

// Ordinary HTTPS visitors get the cover site, and so does a wrong
// admission token: the front reveals nothing by refusing an upgrade.
func TestFrontServesCoverToVisitors(t *testing.T) {
	f, certPEM := startFront(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "cdn.example"},
	}}
	resp, err := client.Get("https://" + f.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("operational")) {
		t.Fatalf("visitor got %d: %q", resp.StatusCode, body)
	}

	// A prober replaying the upgrade shape with a wrong (or no) token
	// gets the same cover content, no 101, nothing distinguishable.
	conn, err := tls.Dial("tcp", f.Addr().String(), &tls.Config{
		RootCAs: roots, ServerName: "cdn.example", MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: cdn.example\r\nUpgrade: %s\r\nConnection: Upgrade\r\nAuthorization: Bearer not-the-token\r\n\r\n", UpgradeToken)
	bresp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	bbody, err := io.ReadAll(bresp.Body)
	bresp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bresp.StatusCode != 200 || !bytes.Contains(bbody, []byte("operational")) {
		t.Fatalf("wrong token got %d: %q", bresp.StatusCode, bbody)
	}
}

func TestFrontRefusesBadToken(t *testing.T) {
	f, certPEM := startFront(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	states := make(chan error, 8)
	c := Dial(ClientOptions{
		Addr: f.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: "cdn.example"},
		Front:   &FrontDialOptions{Token: "wrong-token"},
		OnState: func(err error) { states <- err },
	})
	defer c.Close()
	select {
	case err := <-states:
		var fl *Failure
		if !errors.As(err, &fl) || fl.Mode != ModeFrontRefused {
			t.Fatalf("client reported %v, want a %s Failure", err, ModeFrontRefused)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no dial result")
	}
}
