package session

import (
	"testing"
	"time"
)

// BenchmarkUplink measures the full per-packet cost from Client.SendIP to
// the relay delivering the packet, with ACKs fed back to the client. No
// link simulation or sockets are involved.
func BenchmarkUplink(b *testing.B) {
	for _, size := range []int{100, 1000, 1280} {
		b.Run(sizeLabel(size), func(b *testing.B) {
			n := newNetwork(&testing.T{}, 20, defaultRelayConfig(), ClientConfig{})
			n.establish()
			n.runFor(time.Second)
			pkt := ipPacket(lease, internet, size, 1)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			delivered := 0
			for b.Loop() {
				n.now = n.now.Add(10 * time.Microsecond)
				if err := n.client.SendIP(n.now, pkt); err != nil {
					b.Fatal(err)
				}
				for d, ok := n.client.PollTransmit(); ok; d, ok = n.client.PollTransmit() {
					n.relay.HandlePacket(n.now, n.clientAddr, d.Data)
				}
				for e, ok := n.relay.PollEvent(); ok; e, ok = n.relay.PollEvent() {
					if _, isIP := e.(SessionIP); isIP {
						delivered++
					}
				}
				n.relay.Tick(n.now)
				for d, ok := n.relay.PollTransmit(); ok; d, ok = n.relay.PollTransmit() {
					n.client.HandlePacket(n.now, 0, d.Data)
				}
			}
			if delivered != b.N {
				b.Fatalf("delivered %d of %d", delivered, b.N)
			}
		})
	}
}

func sizeLabel(n int) string {
	switch n {
	case 100:
		return "100B"
	case 1000:
		return "1000B"
	}
	return "1280B-fragmented"
}
