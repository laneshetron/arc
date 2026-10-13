package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/stream"
	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// countingConn counts datagrams written through a carrier.
type countingConn struct {
	DatagramConn
	writes atomic.Int64
}

func (c *countingConn) WriteBatch(pkts [][]byte, addrs []netip.AddrPort) error {
	c.writes.Add(int64(len(pkts)))
	return c.DatagramConn.WriteBatch(pkts, addrs)
}

type streamSetup struct {
	relayTUN, clientTUN *memTUN
	established         chan wire.AuthResult
	udp                 *switchConn   // nil when the client has no UDP carrier
	tls                 *countingConn // the client's TLS carrier
}

// startStreamSession runs a relay with UDP and TLS listeners and a client
// with a TLS carrier (as a fallback) and, if withUDP, a UDP carrier.
func startStreamSession(t *testing.T, ctx context.Context, withUDP bool) *streamSetup {
	t.Helper()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	relayKey, _ := crypto.GenerateStaticKey(nil)
	clientKey, _ := crypto.GenerateStaticKey(nil)
	gw, _ := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Tokens: [][]byte{[]byte("secret")},
	})
	relayConn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relayConn.Close() })
	certPEM, keyPEM, err := stream.SelfSigned([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	ln, err := stream.Listen("127.0.0.1:0", stream.ListenerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	st := &streamSetup{relayTUN: newMemTUN(), clientTUN: newMemTUN(), established: make(chan wire.AuthResult, 4)}
	t.Cleanup(st.relayTUN.Close)
	t.Cleanup(st.clientTUN.Close)
	go RunRelay(ctx, RelayConfig{Session: session.RelayConfig{Static: relayKey}, Conn: relayConn,
		Streams: ln, TUN: st.relayTUN, Gateway: gw})

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	tc := stream.Dial(stream.ClientOptions{Addr: ln.Addr().String(), Peer: relayConn.LocalAddr(),
		TLS: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"}})
	t.Cleanup(func() { tc.Close() })
	st.tls = &countingConn{DatagramConn: tc}
	var carriers []Carrier
	if withUDP {
		c, err := udp.Listen(loop, udp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		st.udp = &switchConn{Conn: c}
		carriers = append(carriers, Carrier{Name: "udp", Conn: st.udp})
	}
	carriers = append(carriers, Carrier{Name: "tls", Conn: st.tls, Fallback: true})
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: clientKey, RelayPublic: relayKey.Public, Credential: []byte("secret"),
			PathTimeout: 2 * time.Second},
		Relay: relayConn.LocalAddr(), Carriers: carriers, TUN: st.clientTUN, RejoinDelay: 300 * time.Millisecond,
		OnEstablished: func(r wire.AuthResult) error { st.established <- r; return nil },
	})
	return st
}

func TestSessionOverTLSOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := startStreamSession(t, ctx, false)
	var lease netip.Addr
	select {
	case r := <-st.established:
		lease = netip.AddrFrom4(r.IPv4)
	case <-time.After(5 * time.Second):
		t.Fatal("session over TLS not established")
	}
	internet := netip.MustParseAddr("198.51.100.7")
	if !deliveredWithin(t, 3*time.Second, st.clientTUN, st.relayTUN, lease) {
		t.Fatal("uplink IP not delivered over TLS")
	}
	st.relayTUN.in <- [][]byte{ipv4(internet, lease, 1200, 1)}
	if got := recv(t, st.clientTUN.out); len(got) != 1200 {
		t.Fatalf("downlink packet of %d bytes", len(got))
	}
}

func TestUDPFailsOverToTLSAndBack(t *testing.T) {
	// Spec §20 Stage C exit: the session joins a TLS/TCP path while UDP
	// works, stops using UDP, and keeps carrying IP over TLS/TCP.
	if testing.Short() {
		t.Skip("takes several seconds of wall-clock time")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := startStreamSession(t, ctx, true)
	var lease netip.Addr
	select {
	case r := <-st.established:
		lease = netip.AddrFrom4(r.IPv4)
	case <-time.After(5 * time.Second):
		t.Fatal("session not established")
	}
	time.Sleep(500 * time.Millisecond) // the other carrier joins

	// With UDP working, data stays off the TLS fallback.
	before := st.tls.writes.Load()
	for range 3 {
		busiest(t, []*switchConn{st.udp}, st.clientTUN, st.relayTUN, lease)
	}
	if n := st.tls.writes.Load() - before; n > 20 { // keepalives and ACKs only
		t.Errorf("%d datagrams went over TLS while UDP worked", n)
	}

	// UDP is blocked: traffic moves to TLS without a new session.
	st.udp.down.Store(true)
	start := time.Now()
	if !deliveredWithin(t, 3*time.Second, st.clientTUN, st.relayTUN, lease) {
		t.Fatal("traffic did not move to TLS when UDP was blocked")
	}
	t.Logf("UDP to TLS failover took %v", time.Since(start).Round(10*time.Millisecond))
	internet := netip.MustParseAddr("198.51.100.7")
	drain(st.clientTUN.out)
	st.relayTUN.in <- [][]byte{ipv4(internet, lease, 1200, 9)}
	recv(t, st.clientTUN.out)

	// UDP returns: traffic leaves the fallback again.
	st.udp.down.Store(false)
	time.Sleep(3 * time.Second) // the UDP path turns healthy, or rejoins
	drain(st.relayTUN.out)
	before = st.tls.writes.Load()
	for range 3 {
		busiest(t, []*switchConn{st.udp}, st.clientTUN, st.relayTUN, lease)
	}
	if n := st.tls.writes.Load() - before; n > 20 {
		t.Errorf("%d datagrams still went over TLS after UDP returned", n)
	}
	select {
	case <-st.established:
		t.Error("a new session was established; the TLS path should join the existing one")
	default:
	}
}
