package crypto

import (
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

func BenchmarkSealData(b *testing.B) {
	for _, size := range []int{64, 1280} {
		b.Run(sizeName(size), func(b *testing.B) {
			a := NewAEAD([32]byte{1})
			pt := make([]byte, size+wire.FrameHeaderLen)
			buf := make([]byte, 0, 2048)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var pn uint64
			for b.Loop() {
				buf = a.SealData(buf[:0], wire.DataHeader{PacketNumber: pn}, 0, pt)
				pn++
			}
		})
	}
}

func BenchmarkOpenData(b *testing.B) {
	for _, size := range []int{64, 1280} {
		b.Run(sizeName(size), func(b *testing.B) {
			a := NewAEAD([32]byte{1})
			pkt := a.SealData(nil, wire.DataHeader{PacketNumber: 7}, 0, make([]byte, size+wire.FrameHeaderLen))
			h, aad, ct, _ := wire.ParseData(pkt)
			buf := make([]byte, 0, 2048)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				var err error
				if buf, err = a.OpenData(buf[:0], h, aad, 0, ct); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReplayWindow(b *testing.B) {
	var w ReplayWindow
	var pn uint64
	b.ReportAllocs()
	for b.Loop() {
		// Mostly in-order with occasional reordering, as on a real path.
		p := pn
		if pn%8 == 3 {
			p = pn - 2
		}
		if w.Check(p) {
			w.Record(p)
		}
		pn++
	}
}

func BenchmarkHandshake(b *testing.B) {
	client, _ := GenerateStaticKey(nil)
	relay, _ := GenerateStaticKey(nil)
	b.ReportAllocs()
	for b.Loop() {
		ch, err := NewClientHandshake(ClientConfig{Static: client, RelayPublic: relay.Public})
		if err != nil {
			b.Fatal(err)
		}
		init := ch.Init(nil)
		rr, err := RespondHandshake(RelayConfig{Static: relay}, &init, wire.CID{1}, wire.Token{})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ch.Finish(&rr.Resp); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRelayHandshakeCost is the relay's work per HANDSHAKE_INIT, the
// figure that matters for flood resistance.
func BenchmarkRelayHandshakeCost(b *testing.B) {
	client, _ := GenerateStaticKey(nil)
	relay, _ := GenerateStaticKey(nil)
	ch, _ := NewClientHandshake(ClientConfig{Static: client, RelayPublic: relay.Public})
	init := ch.Init(nil)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := RespondHandshake(RelayConfig{Static: relay}, &init, wire.CID{1}, wire.Token{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCookieVerify(b *testing.B) {
	g := NewCookieGenerator(nil, time.Unix(0, 0))
	src := mustAddrPort("192.0.2.1:4433")
	c := g.Make(time.Unix(0, 0), src, wire.CID{1})
	b.ReportAllocs()
	for b.Loop() {
		g.Verify(time.Unix(1, 0), src, wire.CID{1}, c)
	}
}

func sizeName(n int) string {
	if n == 64 {
		return "64B"
	}
	return "1280B"
}

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
