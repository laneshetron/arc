package wire

import (
	"bytes"
	"testing"
)

// Every parser must either reject its input or accept it and re-encode it
// byte for byte: ARC/1 encodings are canonical.

func FuzzPacket(f *testing.F) {
	fx := loadFixtures(f)
	for _, h := range []string{
		fx.Packets.HandshakeInit.PacketHex, fx.Packets.HandshakeResp.PacketHex,
		fx.Packets.CookieReply.PacketHex, fx.Packets.StatelessReset.PacketHex, fx.DataAEAD.PacketHex,
	} {
		f.Add(unhex(f, h))
	}
	for _, h := range fx.Cells.CellsHex {
		f.Add(unhex(f, h))
	}
	for _, c := range fx.InvalidPackets {
		f.Add(unhex(f, c.Hex))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := parsePacket(b)
		if err != nil {
			return
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("round trip mismatch:\n in %x\nout %x", b, out)
		}
	})
}

func FuzzFrames(f *testing.F) {
	fx := loadFixtures(f)
	f.Add(unhex(f, fx.DataAEAD.PlaintextHex))
	for _, fr := range fx.Frames {
		f.Add(unhex(f, fr.FrameHex))
	}
	for _, c := range fx.InvalidFrames {
		f.Add(unhex(f, c.Hex))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		frames, err := ParseFrames(nil, b)
		if err != nil {
			return
		}
		var out []byte
		for _, fr := range frames {
			if a, ok := fr.(Ack); ok {
				if _, err := a.AppendIntervals(nil); err != nil {
					t.Fatalf("parsed ACK has invalid ranges: %v", err)
				}
			}
			out = AppendFrame(out, fr)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("round trip mismatch:\n in %x\nout %x", b, out)
		}
	})
}
