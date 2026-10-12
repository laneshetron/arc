// Package udp is the UDP carrier (spec §16.1): one ARC packet per
// datagram, with batched reads and writes where the platform supports them
// (recvmmsg/sendmmsg on Linux).
package udp

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/ipv4"
)

// MaxDatagram is the largest datagram the carrier reads.
const MaxDatagram = 65535

// DefaultBufferSize is the socket send and receive buffer size. TCP inside
// the tunnel sends a window's worth of packets in one burst, and with the
// kernel's default (about 208 KB) a burst that arrives before the reader is
// scheduled overflows and is dropped, which TCP reads as congestion.
const DefaultBufferSize = 7 << 20

// Options controls the carrier's socket.
type Options struct {
	// Mark sets SO_MARK (Linux), so policy routing can keep the carrier's
	// own packets out of the tunnel (§17.1). Zero leaves it unset.
	Mark uint32
	// Device binds the socket to one interface (SO_BINDTODEVICE on Linux),
	// for running one path per underlay. Empty leaves it unbound.
	Device string
	// BufferSize sets SO_RCVBUF and SO_SNDBUF. Zero means
	// DefaultBufferSize. On Linux, privileged processes exceed
	// net.core.rmem_max/wmem_max via SO_RCVBUFFORCE/SO_SNDBUFFORCE; others
	// get what the kernel limits allow.
	BufferSize int
}

// Conn is a UDP carrier socket. Reads and writes may run on different
// goroutines, but each must be used by only one goroutine at a time.
type Conn struct {
	uc *net.UDPConn
	pc *ipv4.PacketConn
	rx []ipv4.Message
	tx []ipv4.Message

	// gso is set when the kernel supports UDP segmentation offload; see
	// gso_linux.go. gsoBufs are reused coalescing buffers.
	gso     bool
	gsoBufs [][]byte

	// Caches for the send path: the last destination's *net.UDPAddr and
	// the last segment size's control message, which would otherwise be
	// allocated per message.
	lastTo   netip.AddrPort
	lastAddr *net.UDPAddr
	lastSeg  int
	lastCmsg []byte
}

// udpAddr returns a *net.UDPAddr for to, reusing the previous one when the
// destination repeats, as it does for every packet a client sends.
func (c *Conn) udpAddr(to netip.AddrPort) *net.UDPAddr {
	if c.lastAddr == nil || to != c.lastTo {
		c.lastTo, c.lastAddr = to, net.UDPAddrFromAddrPort(to)
	}
	return c.lastAddr
}

// Listen opens an IPv4 UDP socket on addr (use port 0 for a client).
func Listen(addr netip.AddrPort, opts Options) (*Conn, error) {
	if opts.BufferSize == 0 {
		opts.BufferSize = DefaultBufferSize
	}
	forced := false
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			if sockErr = setSockopts(int(fd), opts); sockErr == nil {
				forced = forceBuffers(int(fd), opts.BufferSize)
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", addr.String())
	if err != nil {
		return nil, err
	}
	uc := pc.(*net.UDPConn)
	if !forced {
		// Best effort: the kernel caps these at its configured maximums.
		uc.SetReadBuffer(opts.BufferSize)
		uc.SetWriteBuffer(opts.BufferSize)
	}
	return &Conn{uc: uc, pc: ipv4.NewPacketConn(uc), gso: gsoSupported(uc)}, nil
}

// LocalAddr returns the socket's bound address.
func (c *Conn) LocalAddr() netip.AddrPort { return c.uc.LocalAddr().(*net.UDPAddr).AddrPort() }

// ReadBatch reads up to len(bufs) datagrams. Datagram i is bufs[i][:sizes[i]]
// from addrs[i].
func (c *Conn) ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	if len(c.rx) < len(bufs) {
		c.rx = make([]ipv4.Message, len(bufs))
		for i := range c.rx {
			c.rx[i].Buffers = make([][]byte, 1)
		}
	}
	msgs := c.rx[:len(bufs)]
	for i := range msgs {
		msgs[i].Buffers[0] = bufs[i]
	}
	n, err := c.pc.ReadBatch(msgs, 0)
	for i := range n {
		sizes[i] = msgs[i].N
		if ua, ok := msgs[i].Addr.(*net.UDPAddr); ok {
			addrs[i] = ua.AddrPort()
		}
	}
	return n, err
}

// WriteBatch sends each packet to the matching address.
func (c *Conn) WriteBatch(pkts [][]byte, addrs []netip.AddrPort) error {
	if c.gso {
		err := c.writeGSO(pkts, addrs)
		if err == nil || !gsoUnsupported(err) {
			return err
		}
		c.gso = false // the path cannot segment; fall back for good
	}
	return c.writePlain(pkts, addrs)
}

func (c *Conn) writePlain(pkts [][]byte, addrs []netip.AddrPort) error {
	if len(c.tx) < len(pkts) {
		c.tx = make([]ipv4.Message, len(pkts))
		for i := range c.tx {
			c.tx[i].Buffers = make([][]byte, 1)
		}
	}
	msgs := c.tx[:len(pkts)]
	for i := range msgs {
		msgs[i].Buffers[0] = pkts[i]
		msgs[i].Addr = c.udpAddr(addrs[i])
	}
	for len(msgs) > 0 {
		n, err := c.pc.WriteBatch(msgs, 0)
		if err != nil {
			return err
		}
		msgs = msgs[n:]
	}
	return nil
}

func (c *Conn) Close() error { return c.uc.Close() }
