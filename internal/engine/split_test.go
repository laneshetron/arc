package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gvipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// appStack is a TCP/IP stack standing in for the client's operating
// system, with the lease as its address and the client TUN as its link.
func appStack(t *testing.T, ctx context.Context, tun *memTUN, lease netip.Addr) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{gvipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	ep := channel.New(256, 1280, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: gvipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(lease.As4()).WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	go func() {
		for {
			pkb := ep.ReadContext(ctx)
			if pkb == nil {
				return
			}
			view := pkb.ToView()
			tun.in <- [][]byte{append([]byte(nil), view.AsSlice()...)}
			view.Release()
			pkb.DecRef()
		}
	}()
	go func() {
		for {
			select {
			case p := <-tun.out:
				pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
				ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
				pkb.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() { s.Close(); ep.Close() })
	return s
}

// TestSplitTCP runs client and relay engines with split TCP: an
// application's connection ends in the client's userspace stack, its bytes
// travel as a stream, and the relay connects to the destination.
func TestSplitTCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	relayKey, _ := crypto.GenerateStaticKey(nil)
	clientKey, _ := crypto.GenerateStaticKey(nil)
	gw, err := gateway.New(gateway.Config{Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280,
		Tokens: [][]byte{[]byte("secret")}})
	if err != nil {
		t.Fatal(err)
	}

	// The "destination": an echo server on loopback, which the relay dials
	// in place of the address the application asked for.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	open := netip.MustParseAddrPort("198.51.100.7:443")
	refused := netip.MustParseAddrPort("198.51.100.7:444")
	dialed := make(chan netip.AddrPort, 4)

	relayConn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayTUN := newMemTUN()
	defer relayTUN.Close()
	go RunRelay(ctx, RelayConfig{
		Session: session.RelayConfig{Static: relayKey, ResetSecret: [32]byte{1}},
		Conn:    relayConn, TUN: relayTUN, Gateway: gw,
		AllowDial: func(netip.AddrPort) bool { return true },
		Dial: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			dialed <- dst
			if dst != open {
				return nil, errors.New("connection refused")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", echo.Addr().String())
		},
	})

	clientConn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	clientTUN := newMemTUN()
	defer clientTUN.Close()
	established := make(chan wire.AuthResult, 1)
	go RunClient(ctx, ClientConfig{
		Session: session.ClientConfig{Static: clientKey, RelayPublic: relayKey.Public, Credential: []byte("secret")},
		Relay:   relayConn.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: clientConn}}, TUN: clientTUN,
		OnEstablished: func(r wire.AuthResult) error { established <- r; return nil },
		SplitTCP:      SplitAlways,
	})
	var lease netip.Addr
	select {
	case r := <-established:
		lease = netip.AddrFrom4(r.IPv4)
	case <-ctx.Done():
		t.Fatal("session not established")
	}
	app := appStack(t, ctx, clientTUN, lease)
	dial := func(dst netip.AddrPort) (*gonet.TCPConn, error) {
		return gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(dst.Addr().As4()),
			Port: dst.Port()}, gvipv4.ProtocolNumber)
	}

	conn, err := dial(open)
	if err != nil {
		t.Fatal(err)
	}
	reps := 200_000 // 3.8 MB
	if raceEnabled {
		reps = 5_000
	}
	msg := bytes.Repeat([]byte("split tcp over arc "), reps)
	go func() {
		conn.Write(msg)
		conn.CloseWrite()
	}()
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echoed %d of %d bytes: %v", len(got), len(msg), err)
	}
	if d := <-dialed; d != open {
		t.Errorf("relay dialed %v, want %v", d, open)
	}
	select {
	case p := <-relayTUN.out:
		t.Errorf("a split connection's packet reached the relay's TUN: %x", p[:20])
	default:
	}

	// A connection the relay cannot make is reset. The client's stack
	// accepted it first, so the application sees a reset, not a refusal.
	conn, err = dial(refused)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, io.EOF) {
		t.Errorf("read on a refused connection: %v, want a reset", err)
	}
}
