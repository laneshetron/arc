package splittcp

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// appHost is a second stack standing in for the client's operating system:
// an application on it connects through the "TUN" to the split stack.
func appHost(t *testing.T, ctx context.Context, split *Stack) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	ep := channel.New(256, 1280, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	addr := tcpip.AddrFrom4([4]byte{10, 77, 0, 2})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	go func() { // app → split
		for {
			pkb := ep.ReadContext(ctx)
			if pkb == nil {
				return
			}
			view := pkb.ToView()
			pkt := append([]byte(nil), view.AsSlice()...)
			view.Release()
			pkb.DecRef()
			if f, _, ok := TCPFlow(pkt); !ok || f.Dst.Addr() != netip.MustParseAddr("198.51.100.7") {
				t.Errorf("unexpected packet from the app host")
			}
			split.Inject(pkt)
		}
	}()
	go func() { // split → app
		for {
			pkts, err := split.ReadOutbound(ctx, 16)
			if err != nil {
				return
			}
			for _, pkt := range pkts {
				pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
				ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
				pkb.DecRef()
			}
		}
	}()
	t.Cleanup(func() { s.Close(); ep.Close() })
	return s
}

func TestAcceptsAnyDestination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	split, err := New(1280)
	if err != nil {
		t.Fatal(err)
	}
	defer split.Close()
	app := appHost(t, ctx, split)

	dst := netip.MustParseAddrPort("198.51.100.7:443")
	go func() {
		c := <-split.Accept()
		if c.Dst != dst || c.Src.Addr() != netip.MustParseAddr("10.77.0.2") {
			t.Errorf("accepted %v -> %v", c.Src, c.Dst)
		}
		io.Copy(c, c) // echo
		c.CloseWrite()
	}()
	conn, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(dst.Addr().As4()),
		Port: dst.Port()}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	reps := 100_000 // 1 MB: many full segments
	if raceEnabled {
		reps = 5_000
	}
	msg := bytes.Repeat([]byte("split tcp "), reps)
	go func() {
		conn.Write(msg)
		conn.CloseWrite()
	}()
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echoed %d of %d bytes: %v", len(got), len(msg), err)
	}
}

func TestTCPFlow(t *testing.T) {
	syn := make([]byte, 40)
	syn[0], syn[9] = 0x45, 6
	copy(syn[12:16], []byte{10, 77, 0, 2})
	copy(syn[16:20], []byte{198, 51, 100, 7})
	syn[20], syn[21], syn[22], syn[23] = 0x9c, 0x40, 0x01, 0xbb // 40000 -> 443
	syn[33] = 0x02
	f, isSyn, ok := TCPFlow(syn)
	if !ok || !isSyn || f.Src.String() != "10.77.0.2:40000" || f.Dst.String() != "198.51.100.7:443" {
		t.Fatalf("SYN: %v %v %v", f, isSyn, ok)
	}
	syn[33] = 0x12 // SYN-ACK
	if _, isSyn, _ := TCPFlow(syn); isSyn {
		t.Error("SYN-ACK taken for an opening SYN")
	}
	syn[9] = 17
	if _, _, ok := TCPFlow(syn); ok {
		t.Error("UDP taken for TCP")
	}
}
