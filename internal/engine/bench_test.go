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
	client, relay, lease := loopbackEngines(b)
	pumpPackets(b, client.in, relay.out, ipv4(lease, netip.MustParseAddr("198.51.100.7"), 1280, 0))
}

// BenchmarkEngineLoopbackDownload is BenchmarkEngineLoopback in the other
// direction, relay to client, where the client receives the data and
// sends the acknowledgements.
func BenchmarkEngineLoopbackDownload(b *testing.B) {
	client, relay, lease := loopbackEngines(b)
	pumpPackets(b, relay.in, client.out, ipv4(netip.MustParseAddr("198.51.100.7"), lease, 1280, 0))
}

// loopbackEngines runs a client and a relay engine over loopback UDP
// until the benchmark ends, and returns their TUN devices and the
// client's leased address once the session is up.
func loopbackEngines(b *testing.B) (client, relay *memTUN, lease netip.Addr) {
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	quiet := slog.New(slog.DiscardHandler)
	relayKey, _ := crypto.GenerateStaticKey(nil)
	clientKey, _ := crypto.GenerateStaticKey(nil)
	gw, _ := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Tokens: [][]byte{[]byte("secret")},
	})
	relayConn, _ := udp.Listen(loop, udp.Options{})
	b.Cleanup(func() { relayConn.Close() })
	relay = &memTUN{in: make(chan [][]byte, 16), out: make(chan []byte, 4096), closed: make(chan struct{})}
	b.Cleanup(relay.Close)
	go RunRelay(ctx, RelayConfig{Session: session.RelayConfig{Static: relayKey}, Conn: relayConn, TUN: relay, Gateway: gw, Logger: quiet})

	clientConn, _ := udp.Listen(loop, udp.Options{Peer: relayConn.LocalAddr()}) // as arc-client does
	b.Cleanup(func() { clientConn.Close() })
	client = &memTUN{in: make(chan [][]byte, 16), out: make(chan []byte, 4096), closed: make(chan struct{})}
	b.Cleanup(client.Close)
	established := make(chan wire.AuthResult, 1)
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: clientKey, RelayPublic: relayKey.Public, Credential: []byte("secret")},
		Relay:   relayConn.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: clientConn}}, TUN: client,
		OnEstablished: func(r wire.AuthResult) error { established <- r; return nil },
		Logger:        quiet,
	})
	select {
	case r := <-established:
		lease = netip.AddrFrom4(r.IPv4)
	case <-time.After(5 * time.Second):
		b.Fatal("session not established")
	}
	time.Sleep(200 * time.Millisecond) // MTU probe: full-size packets go unfragmented
	return client, relay, lease
}

// pumpPackets sends b.N copies of pkt into in and waits for them on out.
func pumpPackets(b *testing.B, in chan<- [][]byte, out <-chan []byte, pkt []byte) {
	const batch, maxInFlight = 32, 512
	pkts := make([][]byte, batch)
	for i := range pkts {
		pkts[i] = pkt
	}
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	delivered := 0
	for sent := 0; sent < b.N; sent += batch {
		in <- pkts[:min(batch, b.N-sent)]
		// Bound packets in flight: enough to keep the pipeline full, few
		// enough that the loopback socket buffers never overflow.
		for delivered < sent-maxInFlight {
			<-out
			delivered++
		}
	}
	deadline := time.After(10 * time.Second)
	for delivered < b.N {
		select {
		case <-out:
			delivered++
		case <-deadline:
			b.Fatalf("delivered %d of %d packets", delivered, b.N)
		}
	}
}
