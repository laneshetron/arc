package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestBootstrapEndpointsKeepTLSReconnectIndependentOfDNS(t *testing.T) {
	certPEM, keyPEM, err := SelfSigned([]string{"relay.invalid"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen("127.0.0.1:0", ListenerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	endpoint := net.JoinHostPort("relay.invalid", strconv.Itoa(port))
	lookups := 0
	endpoints, err := resolveEndpoints(context.Background(), endpoint, func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookups++
		if host != "relay.invalid" || network != "ip" {
			t.Fatal("unexpected bootstrap lookup")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	oldResolver := net.DefaultResolver
	var reconnectDNS atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		reconnectDNS.Add(1)
		return nil, errors.New("tunnel DNS unavailable")
	}}
	defer func() { net.DefaultResolver = oldResolver }()
	c := &Client{ctx: context.Background(), opts: ClientOptions{Addr: endpoint, Endpoints: endpoints, TLS: &tls.Config{ServerName: "relay.invalid", RootCAs: roots}, Queue: 1}}
	for range 2 {
		link, _, err := c.connect()
		if err != nil {
			t.Fatalf("cached endpoint TLS dial: %v", err)
		}
		link.close()
	}
	if lookups != 1 || reconnectDNS.Load() != 0 {
		t.Fatal("reconnect depended on tunnel DNS")
	}
}

func TestResolveEndpointLiteralSkipsDNS(t *testing.T) {
	out, err := resolveEndpoints(context.Background(), "[2001:db8::1]:443", func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("literal invoked resolver")
		return nil, nil
	})
	if err != nil || len(out) != 1 || out[0].String() != "[2001:db8::1]:443" {
		t.Fatalf("literal: %v %v", out, err)
	}
}

func TestResolvesLaterWhenStartupLookupFailed(t *testing.T) {
	// The startup lookup failed (no Endpoints): the carrier keeps trying
	// with each connection attempt and, once a lookup succeeds, connects
	// and keeps the addresses.
	certPEM, keyPEM, err := SelfSigned([]string{"relay.invalid"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen("127.0.0.1:0", ListenerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	endpoint := net.JoinHostPort("relay.invalid", strconv.Itoa(l.Addr().(*net.TCPAddr).Port))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	lookups, dnsUp := 0, false
	c := &Client{ctx: context.Background(), opts: ClientOptions{Addr: endpoint,
		TLS: &tls.Config{ServerName: "relay.invalid", RootCAs: roots}, Queue: 1},
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			if !dnsUp {
				return nil, errors.New("no DNS yet")
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}
	if _, _, err := c.connect(); err == nil {
		t.Fatal("connected without an address")
	}
	dnsUp = true
	for range 2 {
		link, _, err := c.connect()
		if err != nil {
			t.Fatalf("connect after DNS came up: %v", err)
		}
		link.close()
	}
	if lookups != 2 {
		t.Fatalf("%d lookups, want 2: one failed, then one kept", lookups)
	}
}
