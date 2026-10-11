package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// memTUN is an in-memory PacketDevice.
type memTUN struct {
	in     chan [][]byte // packets the "kernel" sends into the tunnel
	out    chan []byte   // packets the engine delivers to the "kernel"
	closed chan struct{}
}

func newMemTUN() *memTUN {
	return &memTUN{in: make(chan [][]byte, 16), out: make(chan []byte, 256), closed: make(chan struct{})}
}

func (m *memTUN) Read() ([][]byte, error) {
	select {
	case p := <-m.in:
		return p, nil
	case <-m.closed:
		return nil, errors.New("closed")
	}
}

func (m *memTUN) Write(pkts [][]byte) error {
	for _, p := range pkts {
		m.out <- append([]byte(nil), p...)
	}
	return nil
}

func (m *memTUN) Close() { close(m.closed) }

func ipv4(src, dst netip.Addr, size int, seq byte) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[8], p[9] = 64, 17
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	p[size-1] = seq
	return p
}

func recv(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a packet")
		return nil
	}
}

// TestTunnelOverLoopback runs a real client and relay engine over loopback
// UDP sockets with in-memory TUN devices.
func TestTunnelOverLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	relayKey, _ := crypto.GenerateStaticKey(nil)
	clientKey, _ := crypto.GenerateStaticKey(nil)

	gw, err := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Tokens: [][]byte{[]byte("secret")},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayConn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayTUN := newMemTUN()
	defer relayTUN.Close()
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- RunRelay(ctx, RelayConfig{
			Session: session.RelayConfig{Static: relayKey, ResetSecret: [32]byte{1}},
			Conn:    relayConn, TUN: relayTUN, Gateway: gw,
		})
	}()

	clientConn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	clientTUN := newMemTUN()
	defer clientTUN.Close()
	established := make(chan wire.AuthResult, 1)
	clientCtx, stopClient := context.WithCancel(ctx)
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- RunClient(clientCtx, ClientConfig{
			Session: session.ClientConfig{Static: clientKey, RelayPublic: relayKey.Public, Credential: []byte("secret")},
			Relay:   relayConn.LocalAddr(), Conn: clientConn, TUN: clientTUN,
			OnEstablished: func(r wire.AuthResult) error { established <- r; return nil },
		})
	}()

	var lease netip.Addr
	select {
	case r := <-established:
		lease = netip.AddrFrom4(r.IPv4)
	case <-time.After(5 * time.Second):
		t.Fatal("session not established")
	}
	if lease != netip.MustParseAddr("10.77.0.2") {
		t.Errorf("lease = %v", lease)
	}

	internet := netip.MustParseAddr("198.51.100.7")
	for i := range byte(20) {
		size := 40 + int(i)*60 // up to 1180 bytes, plus full-size below
		up := ipv4(lease, internet, size, i)
		clientTUN.in <- [][]byte{up}
		if got := recv(t, relayTUN.out); !bytes.Equal(got, up) {
			t.Fatalf("uplink %d corrupted", i)
		}
		down := ipv4(internet, lease, size, i)
		relayTUN.in <- [][]byte{down}
		if got := recv(t, clientTUN.out); !bytes.Equal(got, down) {
			t.Fatalf("downlink %d corrupted", i)
		}
	}
	full := ipv4(lease, internet, 1280, 99)
	clientTUN.in <- [][]byte{full}
	if got := recv(t, relayTUN.out); !bytes.Equal(got, full) {
		t.Fatal("full-size uplink corrupted")
	}

	// A packet for an address no session leases goes nowhere.
	relayTUN.in <- [][]byte{ipv4(internet, netip.MustParseAddr("10.77.0.99"), 60, 0)}
	// A spoofed inner source is dropped by the relay.
	clientTUN.in <- [][]byte{ipv4(netip.MustParseAddr("10.77.0.50"), internet, 60, 0)}
	select {
	case p := <-relayTUN.out:
		t.Fatalf("relay forwarded a spoofed packet from %v", netip.AddrFrom4([4]byte(p[12:16])))
	case p := <-clientTUN.out:
		t.Fatalf("client received a packet for another address: %x", p[:20])
	case <-time.After(300 * time.Millisecond):
	}

	// Closing the client releases its lease on the relay.
	stopClient()
	if err := <-clientDone; !errors.Is(err, context.Canceled) {
		t.Errorf("client returned %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := gw.Authorize([]byte("secret"), nil, false); err == nil && netip.AddrFrom4(r.IPv4) == lease {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("lease was not released after the client closed")
}

func TestClientStopsOnAuthFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	relayKey, _ := crypto.GenerateStaticKey(nil)
	clientKey, _ := crypto.GenerateStaticKey(nil)
	gw, _ := gateway.New(gateway.Config{Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Tokens: [][]byte{[]byte("secret")}})
	relayConn, _ := udp.Listen(loop, udp.Options{})
	defer relayConn.Close()
	relayTUN := newMemTUN()
	defer relayTUN.Close()
	go RunRelay(ctx, RelayConfig{Session: session.RelayConfig{Static: relayKey}, Conn: relayConn, TUN: relayTUN, Gateway: gw})

	clientConn, _ := udp.Listen(loop, udp.Options{})
	defer clientConn.Close()
	clientTUN := newMemTUN()
	defer clientTUN.Close()
	err := RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: clientKey, RelayPublic: relayKey.Public, Credential: []byte("wrong")},
		Relay:   relayConn.LocalAddr(), Conn: clientConn, TUN: clientTUN,
	})
	if !errors.Is(err, session.ErrAuthFailed) {
		t.Fatalf("RunClient returned %v", err)
	}
}
