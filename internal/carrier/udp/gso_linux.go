package udp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// UDP generic segmentation offload (Linux 4.18+): one sendmsg carries a run
// of equal-size datagrams to one address, and the kernel splits it as late
// as possible instead of running each datagram through the stack.
const (
	maxGSOSegments = 64
	maxGSOBytes    = 65000 // below the 65535-byte IP limit with headers
)

// gsoSupported reports whether the kernel understands UDP_SEGMENT.
func gsoSupported(uc *net.UDPConn) bool {
	rc, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	rc.Control(func(fd uintptr) {
		_, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		ok = err == nil
	})
	return ok
}

// gsoUnsupported reports whether a send failed because the path cannot
// segment, so the caller should retry without GSO.
func gsoUnsupported(err error) bool {
	return errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL)
}

// segmentCmsg builds the UDP_SEGMENT control message for size-byte segments.
func segmentCmsg(size int) []byte {
	b := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(b[unix.CmsgLen(0):], uint16(size))
	return b
}

// writeGSO coalesces runs of datagrams to the same address in which every
// datagram but the last has the same size, and sends each run as one
// message with UDP_SEGMENT.
func (c *Conn) writeGSO(pkts [][]byte, addrs []netip.AddrPort) error {
	msgs := c.tx[:0]
	used := 0
	for i := 0; i < len(pkts); {
		size, to := len(pkts[i]), addrs[i]
		j := i + 1
		total := size
		for j < len(pkts) && j-i < maxGSOSegments && addrs[j] == to &&
			len(pkts[j]) <= size && total+len(pkts[j]) <= maxGSOBytes {
			total += len(pkts[j])
			short := len(pkts[j]) < size
			j++
			if short {
				break // a shorter datagram must end the run
			}
		}

		var m ipv4.Message
		if used < len(c.tx) {
			m = c.tx[used]
		}
		if m.Buffers == nil {
			m.Buffers = make([][]byte, 1)
		}
		m.Addr = net.UDPAddrFromAddrPort(to)
		m.OOB = nil
		if j-i == 1 {
			m.Buffers[0] = pkts[i]
		} else {
			if used >= len(c.gsoBufs) {
				c.gsoBufs = append(c.gsoBufs, make([]byte, 0, maxGSOBytes))
			}
			buf := c.gsoBufs[used][:0]
			for _, p := range pkts[i:j] {
				buf = append(buf, p...)
			}
			c.gsoBufs[used] = buf
			m.Buffers[0] = buf
			m.OOB = segmentCmsg(size)
		}
		msgs = append(msgs, m)
		used++
		i = j
	}
	c.tx = msgs[:max(len(msgs), len(c.tx))]

	for len(msgs) > 0 {
		n, err := c.pc.WriteBatch(msgs, 0)
		if err != nil {
			return err
		}
		msgs = msgs[n:]
	}
	return nil
}
