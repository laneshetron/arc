package engine

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// switchConn is a carrier whose link can be cut: while down it drops
// everything in both directions.
type switchConn struct {
	*udp.Conn
	down   atomic.Bool
	writes atomic.Int64 // datagrams sent while up
}

func (s *switchConn) ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	for {
		n, err := s.Conn.ReadBatch(bufs, sizes, addrs)
		if err != nil || !s.down.Load() {
			return n, err
		}
	}
}

func (s *switchConn) WriteBatch(pkts [][]byte, addrs []netip.AddrPort) error {
	if s.down.Load() {
		return nil
	}
	s.writes.Add(int64(len(pkts)))
	return s.Conn.WriteBatch(pkts, addrs)
}

// deliveredWithin sends one uplink packet every 20 ms until the relay's TUN
// receives one, and reports whether that happened before the limit.
func deliveredWithin(t *testing.T, limit time.Duration, client, relay *memTUN, lease netip.Addr) bool {
	t.Helper()
	internet := netip.MustParseAddr("198.51.100.7")
	deadline := time.Now().Add(limit)
	for seq := byte(0); time.Now().Before(deadline); seq++ {
		client.in <- [][]byte{ipv4(lease, internet, 100, seq)}
		select {
		case <-relay.out:
			return true
		case <-time.After(20 * time.Millisecond):
		}
	}
	return false
}

// busiest sends a burst of uplink traffic and returns the index of the
// carrier that carried most of it: the client's current primary path.
func busiest(t *testing.T, links []*switchConn, client, relay *memTUN, lease netip.Addr) int {
	t.Helper()
	before := make([]int64, len(links))
	for i, l := range links {
		before[i] = l.writes.Load()
	}
	internet := netip.MustParseAddr("198.51.100.7")
	for seq := range byte(50) {
		client.in <- [][]byte{ipv4(lease, internet, 100, seq)}
		recv(t, relay.out)
	}
	best, most := 0, int64(-1)
	for i, l := range links {
		if d := l.writes.Load() - before[i]; d > most {
			best, most = i, d
		}
	}
	return best
}

func drain(ch <-chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func TestCarrierFailoverAndRejoin(t *testing.T) {
	if testing.Short() {
		t.Skip("takes several seconds of wall-clock time")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	relayKey, _ := crypto.GenerateStaticKey(nil)
	clientKey, _ := crypto.GenerateStaticKey(nil)
	gw, _ := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Tokens: [][]byte{[]byte("secret")},
	})
	relayConn, _ := udp.Listen(loop, udp.Options{})
	defer relayConn.Close()
	relayTUN := newMemTUN()
	defer relayTUN.Close()
	go RunRelay(ctx, RelayConfig{Session: session.RelayConfig{Static: relayKey}, Conn: relayConn, TUN: relayTUN, Gateway: gw})

	var links [2]*switchConn
	var carriers []Carrier
	for i, name := range []string{"a", "b"} {
		c, err := udp.Listen(loop, udp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		links[i] = &switchConn{Conn: c}
		carriers = append(carriers, Carrier{Name: name, Conn: links[i]})
	}
	clientTUN := newMemTUN()
	defer clientTUN.Close()
	established := make(chan wire.AuthResult, 4)
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{
			Static: clientKey, RelayPublic: relayKey.Public, Credential: []byte("secret"),
			PathTimeout: 2 * time.Second,
		},
		Relay: relayConn.LocalAddr(), Carriers: carriers, TUN: clientTUN,
		RejoinDelay:   300 * time.Millisecond,
		OnEstablished: func(r wire.AuthResult) error { established <- r; return nil },
	})

	var lease netip.Addr
	select {
	case r := <-established:
		lease = netip.AddrFrom4(r.IPv4)
	case <-time.After(5 * time.Second):
		t.Fatal("session not established")
	}
	time.Sleep(500 * time.Millisecond) // the second carrier joins and validates

	// Cut whichever carrier carries traffic now: it must move to the other.
	first := busiest(t, links[:], clientTUN, relayTUN, lease)
	other := 1 - first
	links[first].down.Store(true)
	start := time.Now()
	if !deliveredWithin(t, 3*time.Second, clientTUN, relayTUN, lease) {
		t.Fatalf("traffic did not fail over from carrier %s", carriers[first].Name)
	}
	t.Logf("failover from carrier %s took %v", carriers[first].Name, time.Since(start).Round(10*time.Millisecond))
	if got := busiest(t, links[:], clientTUN, relayTUN, lease); got != other {
		t.Fatalf("traffic is on carrier %s after cutting it", carriers[got].Name)
	}

	// Restore it. After its path times out it rejoins as a new path, so
	// cutting the other carrier must leave a working tunnel without a new
	// session.
	links[first].down.Store(false)
	time.Sleep(2*time.Second + 300*time.Millisecond + time.Second)
	drain(relayTUN.out)
	links[other].down.Store(true)
	start = time.Now()
	if !deliveredWithin(t, 3*time.Second, clientTUN, relayTUN, lease) {
		t.Fatalf("traffic did not move back to the rejoined carrier %s", carriers[first].Name)
	}
	t.Logf("failover back to rejoined carrier %s took %v", carriers[first].Name, time.Since(start).Round(10*time.Millisecond))
	select {
	case <-established:
		t.Error("a new session was established; rejoining should reuse the session")
	default:
	}
}

// startTwoCarrierClient runs a relay and a client with two carriers and
// returns the carriers' switches and a channel of established sessions.
func startTwoCarrierClient(t *testing.T, ctx context.Context, rc session.RelayConfig, aDown bool) ([2]*switchConn, chan wire.AuthResult) {
	t.Helper()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	relayKey, _ := crypto.GenerateStaticKey(nil)
	clientKey, _ := crypto.GenerateStaticKey(nil)
	gw, _ := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Tokens: [][]byte{[]byte("secret")},
	})
	relayConn, _ := udp.Listen(loop, udp.Options{})
	t.Cleanup(func() { relayConn.Close() })
	relayTUN := newMemTUN()
	t.Cleanup(relayTUN.Close)
	rc.Static = relayKey
	go RunRelay(ctx, RelayConfig{Session: rc, Conn: relayConn, TUN: relayTUN, Gateway: gw})

	var links [2]*switchConn
	var carriers []Carrier
	for i, name := range []string{"a", "b"} {
		c, err := udp.Listen(loop, udp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		links[i] = &switchConn{Conn: c}
		carriers = append(carriers, Carrier{Name: name, Conn: links[i]})
	}
	links[0].down.Store(aDown)
	clientTUN := newMemTUN()
	t.Cleanup(clientTUN.Close)
	established := make(chan wire.AuthResult, 4)
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: clientKey, RelayPublic: relayKey.Public, Credential: []byte("secret")},
		Relay:   relayConn.LocalAddr(), Carriers: carriers, TUN: clientTUN,
		OnEstablished: func(r wire.AuthResult) error { established <- r; return nil },
	})
	return links, established
}

func TestHandshakeOnAnyCarrier(t *testing.T) {
	// The first carrier is dead from the start. The handshake goes out on
	// both, so the session comes up through the second without waiting
	// for a handshake timeout.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, established := startTwoCarrierClient(t, ctx, session.RelayConfig{}, true)
	select {
	case <-established:
	case <-time.After(2 * time.Second):
		t.Fatal("session not established through the live carrier")
	}
}

func TestHandshakeWithCookiesOnTwoCarriers(t *testing.T) {
	// Every INIT needs a cookie, which is valid only for the address it was
	// issued to: the handshake must settle on one carrier rather than
	// trading cookies between them.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, established := startTwoCarrierClient(t, ctx, session.RelayConfig{AlwaysRequireCookie: true}, false)
	select {
	case <-established:
	case <-time.After(2 * time.Second):
		t.Fatal("session not established with cookies required")
	}
}
