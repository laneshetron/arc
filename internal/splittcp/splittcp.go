// Package splittcp terminates TCP connections from the client's TUN
// device in a userspace TCP/IP stack (gVisor's netstack), so their bytes
// can travel as ARC streams (spec §11.3) instead of as IP packets. The
// stack accepts a connection to any destination: it answers the
// application's SYN as if it were the destination, and hands over the
// connection with the destination address the application asked for.
//
// Only the packets of connections chosen for splitting go to the stack
// (Inject); the stack's replies come back through ReadOutbound for the
// TUN device.
package splittcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1
	// queueLen is the outbound queue between the stack and the TUN; the
	// stack drops beyond it, and TCP recovers.
	queueLen = 1024
	// maxInFlight bounds connections in the middle of their handshake.
	maxInFlight = 1024
	// Buffer limits per connection. The receive buffer is what the
	// application may send before the stream drains it; netstack grows
	// it from the default as needed.
	maxBuffer = 4 << 20
)

// Conn is a connection the stack accepted. Dst is where the application
// meant to connect, Src where it connected from.
type Conn struct {
	*gonet.TCPConn
	ep       tcpip.Endpoint
	Src, Dst netip.AddrPort
}

// Abort ends the connection with a reset, as a refused or failed
// connection does.
func (c *Conn) Abort() { c.ep.Abort() }

// Stack is a userspace TCP/IP stack accepting connections to any address.
type Stack struct {
	s       *stack.Stack
	ep      *channel.Endpoint
	accepts chan *Conn
}

// New creates a stack whose packets are at most mtu bytes, which bounds
// the MSS it advertises.
func New(mtu uint32) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	st := &Stack{s: s, ep: channel.New(queueLen, mtu, ""), accepts: make(chan *Conn, maxInFlight)}
	sack := tcpip.TCPSACKEnabled(true)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	opts := []tcpip.SettableTransportProtocolOption{
		&sack, &moderate,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: maxBuffer},
		&tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: maxBuffer},
	}
	for _, o := range opts {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, o); err != nil {
			return nil, fmt.Errorf("splittcp: option %T: %v", o, err)
		}
	}
	if err := s.CreateNIC(nicID, st.ep); err != nil {
		return nil, fmt.Errorf("splittcp: %v", err)
	}
	// Accept packets for any address, and answer from it.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("splittcp: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("splittcp: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	fwd := tcp.NewForwarder(s, 0, maxInFlight, st.accept)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return st, nil
}

// accept completes a forwarded handshake and queues the connection; with
// the queue full it refuses the connection.
func (st *Stack) accept(r *tcp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	c := &Conn{
		TCPConn: gonet.NewTCPConn(&wq, ep),
		ep:      ep,
		Src:     netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort),
		Dst:     netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort),
	}
	select {
	case st.accepts <- c:
	default:
		c.Abort()
	}
}

func addrOf(a tcpip.Address) netip.Addr {
	addr, _ := netip.AddrFromSlice(a.AsSlice())
	return addr
}

// Accept returns the channel of accepted connections.
func (st *Stack) Accept() <-chan *Conn { return st.accepts }

// Inject delivers an IPv4 packet from the TUN to the stack. It copies the
// packet.
func (st *Stack) Inject(pkt []byte) {
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	st.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
	pkb.DecRef()
}

var errClosed = errors.New("splittcp: closed")

// ReadOutbound returns the packets the stack sends toward the TUN, up to
// max of them, waiting for the first until ctx ends.
func (st *Stack) ReadOutbound(ctx context.Context, max int) ([][]byte, error) {
	pkb := st.ep.ReadContext(ctx)
	if pkb == nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errClosed
	}
	out := [][]byte{take(pkb)}
	for len(out) < max {
		if pkb = st.ep.Read(); pkb == nil {
			break
		}
		out = append(out, take(pkb))
	}
	return out, nil
}

func take(pkb *stack.PacketBuffer) []byte {
	view := pkb.ToView()
	b := append([]byte(nil), view.AsSlice()...)
	view.Release()
	pkb.DecRef()
	return b
}

// Close shuts the stack down, resetting its connections.
func (st *Stack) Close() {
	st.s.Close()
	st.ep.Close()
	st.s.Wait()
}

// Flow identifies a TCP connection from the client's side.
type Flow struct {
	Src, Dst netip.AddrPort
}

// TCPFlow parses an IPv4 TCP packet's flow, and whether it is a SYN that
// opens a connection (SYN without ACK).
func TCPFlow(pkt []byte) (f Flow, syn, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return f, false, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+14 || binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return f, false, false // not the first fragment
	}
	t := pkt[ihl:]
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[12:16])), binary.BigEndian.Uint16(t[0:2]))
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[16:20])), binary.BigEndian.Uint16(t[2:4]))
	flags := t[13]
	return Flow{src, dst}, flags&0x02 != 0 && flags&0x10 == 0, true
}
