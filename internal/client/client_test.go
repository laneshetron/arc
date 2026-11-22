package client

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
)

// chanDevice is a PacketDevice backed by channels.
type chanDevice struct {
	in     chan [][]byte // packets for the engine to read
	out    chan []byte   // packets the engine wrote
	closed chan struct{}
}

func newChanDevice() *chanDevice {
	return &chanDevice{in: make(chan [][]byte, 4), out: make(chan []byte, 64), closed: make(chan struct{})}
}

func (d *chanDevice) Read() ([][]byte, error) {
	select {
	case p := <-d.in:
		return p, nil
	case <-d.closed:
		return nil, errors.New("closed")
	}
}

func (d *chanDevice) Write(pkts [][]byte) error {
	for _, p := range pkts {
		d.out <- append([]byte(nil), p...)
	}
	return nil
}

func udpPacket(src, dst netip.Addr) []byte {
	p := make([]byte, 64)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, 17
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

// TestRunReportsNetworkAndCarriesTraffic: Run opens its carriers from the
// config, reports the network the relay leased through OnNetwork, carries
// packets over the device it was given, and returns nil when its context
// ends.
func TestRunReportsNetworkAndCarriesTraffic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	quiet := slog.New(slog.DiscardHandler)

	relayKey, _ := crypto.GenerateStaticKey(nil)
	gw, err := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1300, DNS: netip.MustParseAddr("10.77.0.53"),
		Tokens: [][]byte{[]byte("secret")},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayConn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayDev := newChanDevice()
	defer close(relayDev.closed)
	go engine.RunRelay(ctx, engine.RelayConfig{
		Session: session.RelayConfig{Static: relayKey}, Conn: relayConn, TUN: relayDev, Gateway: gw, Logger: quiet,
	})

	clientKey, _ := crypto.GenerateStaticKey(nil)
	var pin [32]byte
	copy(pin[:], relayKey.Public)
	networks := make(chan Network, 4)
	clientDev := newChanDevice()
	defer close(clientDev.closed)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			Relay: relayConn.LocalAddr(), RelayKey: pin, Token: []byte("secret"), Static: clientKey,
			Logger:    quiet,
			OnNetwork: func(n Network) error { networks <- n; return nil },
		}, clientDev)
	}()

	var n Network
	select {
	case n = <-networks:
	case err := <-done:
		t.Fatalf("Run returned before a session was established: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no session within 5 s")
	}
	if !netip.MustParsePrefix("10.77.0.0/24").Contains(n.Addr.Addr()) || n.Addr.Bits() != 24 || n.Addr.Addr() == netip.MustParseAddr("10.77.0.1") {
		t.Errorf("leased %v, want a client address in 10.77.0.0/24", n.Addr)
	}
	if n.MTU != 1300 {
		t.Errorf("MTU %d, want the relay's 1300", n.MTU)
	}
	if n.DNS != netip.MustParseAddr("10.77.0.53") {
		t.Errorf("DNS %v, want the relay's 10.77.0.53", n.DNS)
	}

	pkt := udpPacket(n.Addr.Addr(), netip.MustParseAddr("198.51.100.7"))
	clientDev.in <- [][]byte{pkt}
	select {
	case got := <-relayDev.out:
		if string(got) != string(pkt) {
			t.Errorf("relay received % x, want % x", got, pkt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet from the client's device never reached the relay's")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel: %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

// TestRunReportsOnNetworkFailure: an OnNetwork error is not swallowed; it
// ends the run with the error, wrapped.
func TestRunReportsOnNetworkFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	quiet := slog.New(slog.DiscardHandler)
	relayKey, _ := crypto.GenerateStaticKey(nil)
	gw, _ := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Tokens: [][]byte{[]byte("secret")},
	})
	relayConn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayDev := newChanDevice()
	defer close(relayDev.closed)
	go engine.RunRelay(ctx, engine.RelayConfig{
		Session: session.RelayConfig{Static: relayKey}, Conn: relayConn, TUN: relayDev, Gateway: gw, Logger: quiet,
	})
	clientKey, _ := crypto.GenerateStaticKey(nil)
	var pin [32]byte
	copy(pin[:], relayKey.Public)
	clientDev := newChanDevice()
	defer close(clientDev.closed)
	boom := errors.New("boom")
	err = Run(ctx, Config{
		Relay: relayConn.LocalAddr(), RelayKey: pin, Token: []byte("secret"), Static: clientKey, Logger: quiet,
		OnNetwork: func(Network) error { return boom },
	}, clientDev)
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %v, want the OnNetwork error", err)
	}
}
