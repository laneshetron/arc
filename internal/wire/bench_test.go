package wire

import (
	"encoding/binary"
	"testing"
)

func benchIPv4(size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	return p
}

func BenchmarkParseData(b *testing.B) {
	h := DataHeader{DestCID: CID{1}, PacketNumber: 42}
	pkt := append(h.Append(nil), make([]byte, 1300)...)
	b.SetBytes(int64(len(pkt)))
	for b.Loop() {
		if _, _, _, err := ParseData(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseFrames(b *testing.B) {
	pt := AppendFrame(nil, Ack{PathID: 0, Largest: 1000, FirstRange: 10})
	pt = AppendFrame(pt, IPPacket{Packet: benchIPv4(1280)})
	dst := make([]Frame, 0, 4)
	b.SetBytes(int64(len(pt)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseFrames(dst[:0], pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppendFrameIPPacket(b *testing.B) {
	f := IPPacket{Packet: benchIPv4(1280)}
	buf := make([]byte, 0, 1400)
	b.SetBytes(1280)
	b.ReportAllocs()
	for b.Loop() {
		buf = AppendFrame(buf[:0], f)
	}
}
