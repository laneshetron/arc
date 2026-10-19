// Package udp is the UDP carrier (spec §16.1): one ARC packet per
// datagram, with batched reads and writes where the platform supports them
// (recvmmsg/sendmmsg on Linux).
package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
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
	// Device binds the socket to one interface (SO_BINDTODEVICE on Linux,
	// IP_BOUND_IF on macOS), for running one path per underlay. Empty
	// leaves it unbound.
	Device string
	// BufferSize sets SO_RCVBUF and SO_SNDBUF. Zero means
	// DefaultBufferSize. On Linux, privileged processes exceed
	// net.core.rmem_max/wmem_max via SO_RCVBUFFORCE/SO_SNDBUFFORCE; others
	// get what the kernel limits allow.
	BufferSize int
	// NoOffload disables UDP GSO and GRO, for comparing against plain
	// per-datagram I/O.
	NoOffload bool
	// Peer, if valid, connects the socket to that address: it then sends
	// only there and receives only from there. The kernel resolves the
	// route and policy once instead of for every datagram (on macOS, a send
	// through a bound interface then takes about 9 µs of CPU instead of 24).
	Peer netip.AddrPort
	// OnReconnect, if set, is called with the socket's new local address
	// after a connected socket whose source address went away connects
	// again (see WriteBatch). It runs on the writing goroutine.
	OnReconnect func(local netip.AddrPort)
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
	gro     *groReader     // non-nil when UDP_GRO is enabled; see gro_linux.go
	peer    netip.AddrPort // the connected peer; zero if unconnected

	raw         syscall.RawConn
	onReconnect func(netip.AddrPort)

	// Caches for the send path: the last destination's *net.UDPAddr and
	// the last segment size's control message, which would otherwise be
	// allocated per message.
	lastTo   netip.AddrPort
	lastAddr *net.UDPAddr
	lastSeg  int
	lastCmsg []byte
}

// udpAddr returns a *net.UDPAddr for to, reusing the previous one when the
// destination repeats, as it does for every packet a client sends. A
// connected socket sends without an address (a nil interface, not a nil
// *net.UDPAddr).
func (c *Conn) udpAddr(to netip.AddrPort) net.Addr {
	if c.peer.IsValid() {
		return nil
	}
	if c.lastAddr == nil || to != c.lastTo {
		c.lastTo, c.lastAddr = to, net.UDPAddrFromAddrPort(to)
	}
	return c.lastAddr
}

// Listen opens an IPv4 UDP socket on addr (use port 0 for a client),
// connected to opts.Peer if that is set.
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
	var uc *net.UDPConn
	if opts.Peer.IsValid() {
		d := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(addr), Control: lc.Control}
		nc, err := d.DialContext(context.Background(), "udp4", opts.Peer.String())
		if err != nil {
			return nil, err
		}
		uc = nc.(*net.UDPConn)
	} else {
		pc, err := lc.ListenPacket(context.Background(), "udp4", addr.String())
		if err != nil {
			return nil, err
		}
		uc = pc.(*net.UDPConn)
	}
	if !forced {
		// Best effort: the kernel caps these at its configured maximums.
		uc.SetReadBuffer(opts.BufferSize)
		uc.SetWriteBuffer(opts.BufferSize)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		uc.Close()
		return nil, err
	}
	c := &Conn{uc: uc, pc: ipv4.NewPacketConn(uc), peer: opts.Peer, raw: raw, onReconnect: opts.OnReconnect}
	if !opts.NoOffload {
		c.gso = gsoSupported(uc)
		c.gro = enableGRO(uc)
	}
	return c, nil
}

// LocalAddr returns the socket's local address, which for a connected
// socket changes when it connects again.
func (c *Conn) LocalAddr() netip.AddrPort {
	var sa unix.Sockaddr
	var err error
	if cerr := c.raw.Control(func(fd uintptr) { sa, err = unix.Getsockname(int(fd)) }); cerr == nil && err == nil {
		if sa4, ok := sa.(*unix.SockaddrInet4); ok {
			return netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), uint16(sa4.Port))
		}
	}
	return c.uc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// ReadBatch reads up to len(bufs) datagrams. Datagram i is bufs[i][:sizes[i]]
// from addrs[i].
func (c *Conn) ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	for {
		n, err := c.readBatch(bufs, sizes, addrs)
		// A connected socket reports an ICMP or route error from an
		// earlier send on the next read. The peer may come back (a relay
		// restarting, a Wi-Fi link reassociating), so read on, as an
		// unconnected socket would never have noticed.
		if n == 0 && c.peer.IsValid() && refused(err) {
			continue
		}
		return n, err
	}
}

func (c *Conn) readBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	if c.gro != nil {
		return c.gro.read(bufs, sizes, addrs)
	}
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
		} else {
			addrs[i] = c.peer // a connected socket need not report it
		}
	}
	return n, err
}

// WriteBatch sends each packet to the matching address. A datagram the
// kernel refuses is dropped, as the network might drop it, and the rest are
// still sent; the first such error is returned.
//
// A connected socket keeps the source address it had when it connected.
// If that address goes away, as when a Mac wakes from sleep on a new DHCP
// lease, every send fails (EADDRNOTAVAIL on macOS, ENETUNREACH on Linux)
// until the socket connects again, which picks the interface's current
// address. So a send failing that way reconnects the socket, at most once
// per call, and retries the datagram. If reconnecting fails, as while the
// interface has no address, the rest of the batch is dropped and the
// reconnect's error returned; the next call tries again.
func (c *Conn) WriteBatch(pkts [][]byte, addrs []netip.AddrPort) error {
	if c.peer.IsValid() {
		for _, to := range addrs {
			if to != c.peer {
				return fmt.Errorf("udp: send to %v on a socket connected to %v", to, c.peer)
			}
		}
	}
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
	return c.sendAll(msgs)
}

// sendAll sends msgs, skipping any the kernel refuses (ENOBUFS when an
// interface queue is full, say), and returns the first error.
func (c *Conn) sendAll(msgs []ipv4.Message) error {
	var first error
	reconnected := false
	for len(msgs) > 0 {
		n, err := c.pc.WriteBatch(msgs, 0)
		msgs = msgs[max(n, 0):] // sendmmsg's -1 on Linux
		if err == nil {
			continue
		}
		if c.gso && gsoUnsupported(err) {
			return err // the caller resends without GSO
		}
		if !reconnected && c.peer.IsValid() && sourceLost(err) {
			reconnected = true
			rerr := c.reconnect()
			if rerr == nil {
				continue // resend the one that failed
			}
			// The socket may now be unconnected, and every send would
			// fail with EDESTADDRREQ; drop the rest, and report why.
			if first == nil && !refused(rerr) {
				first = fmt.Errorf("udp: reconnecting to %v: %w", c.peer, rerr)
			}
			return first
		}
		if first == nil && !refused(err) {
			first = err
		}
		if len(msgs) > 0 {
			msgs = msgs[1:] // the one that failed
		}
	}
	return first
}

// refused reports whether err is an ICMP error from an earlier datagram,
// which only a connected socket reports, or a route error a send reports
// while the network is briefly unreachable (macOS during a Wi-Fi roam,
// say). Either way a datagram is lost, as the network might lose it; the
// socket is fine.
func refused(err error) bool {
	for _, e := range []syscall.Errno{
		syscall.ECONNREFUSED, // port unreachable
		syscall.ENETUNREACH,  // net unreachable, or no route
		syscall.EHOSTUNREACH, // host unreachable
		syscall.EHOSTDOWN,    // macOS: the next hop doesn't answer ARP
		syscall.ENETDOWN,     // the interface went down
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// sourceLost reports whether a send on a connected socket failed in a way
// that connecting again might cure: the source address is gone, or a
// failed reconnect left the socket unconnected.
func sourceLost(err error) bool {
	for _, e := range []syscall.Errno{
		syscall.EADDRNOTAVAIL, // macOS: the source address is gone
		syscall.ENETUNREACH,   // Linux: likewise; or no route yet
		syscall.EHOSTUNREACH,
		syscall.ENETDOWN,
		syscall.EDESTADDRREQ, // unconnected after a failed reconnect
		syscall.ENOTCONN,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// reconnect connects the socket to its peer again, which picks a source
// address from the interface's current ones. If it fails, as while the
// interface has no address, the socket may be left unconnected, and the
// next send tries again. Reads carry on throughout; the engine discards
// anything that arrives from elsewhere while the socket is unconnected.
func (c *Conn) reconnect() error {
	sa := &unix.SockaddrInet4{Port: int(c.peer.Port()), Addr: c.peer.Addr().As4()}
	var err error
	if cerr := c.raw.Control(func(fd uintptr) { err = connectFD(int(fd), sa) }); cerr != nil {
		return cerr
	}
	if err != nil {
		return err
	}
	if c.onReconnect != nil {
		c.onReconnect(c.LocalAddr())
	}
	return nil
}

func (c *Conn) Close() error { return c.uc.Close() }
