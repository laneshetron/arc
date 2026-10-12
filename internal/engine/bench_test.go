package engine

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// BenchmarkEngineLoopback pushes full-size packets from the client's TUN
// to the relay's TUN through real engines and loopback UDP sockets. It
// measures everything ARC does per packet in user space (reader
// goroutines, channel handoffs, the session, crypto, batching) but not the
// kernel TUN path. Each op is one 1280-byte packet delivered.
func BenchmarkEngineLoopback(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	quiet := slog.New(slog.DiscardHandler)
	relayKey, _ := crypto.GenerateStaticKey(nil)
	clientKey, _ := crypto.GenerateStaticKey(nil)
	gw, _ := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Tokens: [][]byte{[]byte("secret")},
	})
	relayConn, _ := udp.Listen(loop, udp.Options{})
	defer relayConn.Close()
	relayTUN := &memTUN{in: make(chan [][]byte, 16), out: make(chan []byte, 4096), closed: make(chan struct{})}
	defer relayTUN.Close()
	go RunRelay(ctx, RelayConfig{Session: session.RelayConfig{Static: relayKey}, Conn: relayConn, TUN: relayTUN, Gateway: gw, Logger: quiet})

	clientConn, _ := udp.Listen(loop, udp.Options{})
	defer clientConn.Close()
	clientTUN := newMemTUN()
	defer clientTUN.Close()
	established := make(chan wire.AuthResult, 1)
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: clientKey, RelayPublic: relayKey.Public, Credential: []byte("secret")},
		Relay:   relayConn.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: clientConn}}, TUN: clientTUN,
		OnEstablished: func(r wire.AuthResult) error { established <- r; return nil },
		Logger:        quiet,
	})
	var lease netip.Addr
	select {
	case r := <-established:
		lease = netip.AddrFrom4(r.IPv4)
	case <-time.After(5 * time.Second):
		b.Fatal("session not established")
	}
	time.Sleep(200 * time.Millisecond) // MTU probe: full-size packets go unfragmented

	const batch, maxInFlight = 32, 512
	pkts := make([][]byte, batch)
	for i := range pkts {
		pkts[i] = ipv4(lease, netip.MustParseAddr("198.51.100.7"), 1280, byte(i))
	}
	b.SetBytes(1280)
	b.ReportAllocs()
	b.ResetTimer()
	delivered := 0
	for sent := 0; sent < b.N; sent += batch {
		clientTUN.in <- pkts[:min(batch, b.N-sent)]
		// Bound packets in flight: enough to keep the pipeline full, few
		// enough that the loopback socket buffers never overflow.
		for delivered < sent-maxInFlight {
			<-relayTUN.out
			delivered++
		}
	}
	deadline := time.After(10 * time.Second)
	for delivered < b.N {
		select {
		case <-relayTUN.out:
			delivered++
		case <-deadline:
			b.Fatalf("delivered %d of %d packets", delivered, b.N)
		}
	}
}
