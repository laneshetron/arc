package udp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// UDP generic receive offload (Linux 5.0+): with UDP_GRO set, the kernel
// may hand the socket several datagrams from the same flow coalesced into
// one buffer, saving per-datagram receive work; a control message gives
// the segment size. The reader splits them back apart.
const (
	groBufSize  = 65535 // a coalesced buffer can be up to the IP limit
	groMessages = 16    // coalesced buffers per recvmmsg
)

type segment struct {
	data []byte // aliases a groReader buffer until handed out
	from netip.AddrPort
}

// groReader receives with a raw recvmmsg, so it can read the UDP_GRO
// control message and parse the source address without allocating.
type groReader struct {
	rc    syscall.RawConn
	bufs  [][]byte
	oobs  [][]byte
	names []unix.RawSockaddrInet4
	iovs  []unix.Iovec
	hdrs  []unix.Mmsghdr
	pend  []segment // received but not yet returned

	coalesced int // buffers that held more than one datagram, for tests
}

// enableGRO turns on UDP_GRO and returns a reader for the socket, or nil
// if the kernel does not support it.
func enableGRO(uc *net.UDPConn) *groReader {
	rc, err := uc.SyscallConn()
	if err != nil {
		return nil
	}
	var sockErr error
	if err := rc.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil || sockErr != nil {
		return nil
	}
	r := &groReader{
		rc:    rc,
		bufs:  make([][]byte, groMessages),
		oobs:  make([][]byte, groMessages),
		names: make([]unix.RawSockaddrInet4, groMessages),
		iovs:  make([]unix.Iovec, groMessages),
		hdrs:  make([]unix.Mmsghdr, groMessages),
	}
	for i := range r.bufs {
		r.bufs[i] = make([]byte, groBufSize)
		r.oobs[i] = make([]byte, unix.CmsgSpace(4))
	}
	return r
}

// read fills the caller's buffers with whole datagrams, receiving more
// from the socket only when none are pending.
func (r *groReader) read(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	if len(r.pend) == 0 {
		if err := r.receive(); err != nil {
			return 0, err
		}
	}
	n := 0
	for n < len(bufs) && len(r.pend) > 0 {
		s := r.pend[0]
		sizes[n] = copy(bufs[n], s.data)
		addrs[n] = s.from
		r.pend[0] = segment{}
		r.pend = r.pend[1:]
		n++
	}
	if len(r.pend) == 0 {
		r.pend = r.pend[:0:cap(r.pend)]
	}
	return n, nil
}

// receive runs one recvmmsg, waiting in the netpoller until data arrives,
// and splits what it got into pending datagrams.
func (r *groReader) receive() error {
	for i := range r.hdrs {
		r.iovs[i].Base = &r.bufs[i][0]
		r.iovs[i].SetLen(len(r.bufs[i]))
		h := &r.hdrs[i].Hdr
		h.Name = (*byte)(unsafe.Pointer(&r.names[i]))
		h.Namelen = uint32(unsafe.Sizeof(r.names[i]))
		h.Iov = &r.iovs[i]
		h.SetIovlen(1)
		h.Control = &r.oobs[i][0]
		h.SetControllen(len(r.oobs[i]))
		h.Flags = 0
		r.hdrs[i].Len = 0
	}
	var n int
	var errno syscall.Errno
	err := r.rc.Read(func(fd uintptr) bool {
		got, _, e := unix.Syscall6(unix.SYS_RECVMMSG, fd,
			uintptr(unsafe.Pointer(&r.hdrs[0])), uintptr(len(r.hdrs)), 0, 0, 0)
		if e == unix.EAGAIN || e == unix.EINTR {
			return false // wait until readable, then try again
		}
		n, errno = int(got), e
		return true
	})
	if err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	r.pend = r.pend[:0]
	for i := range n {
		h := &r.hdrs[i]
		data := r.bufs[i][:h.Len]
		from := sockaddrToAddrPort(&r.names[i])
		seg := groSegmentSize(r.oobs[i][:h.Hdr.Controllen])
		if seg <= 0 || seg >= len(data) {
			r.pend = append(r.pend, segment{data, from})
			continue
		}
		r.coalesced++
		for len(data) > 0 {
			k := min(seg, len(data))
			r.pend = append(r.pend, segment{data[:k], from})
			data = data[k:]
		}
	}
	return nil
}

func sockaddrToAddrPort(sa *unix.RawSockaddrInet4) netip.AddrPort {
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
	return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port)
}

// groSegmentSize returns the UDP_GRO segment size in a control message
// buffer, or 0 if there is none.
func groSegmentSize(oob []byte) int {
	hdrLen := unix.CmsgLen(0)
	for len(oob) >= hdrLen {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		l := int(h.Len)
		if l < hdrLen || l > len(oob) {
			return 0
		}
		if h.Level == unix.IPPROTO_UDP && h.Type == unix.UDP_GRO && l >= hdrLen+4 {
			return int(binary.NativeEndian.Uint32(oob[hdrLen:]))
		}
		oob = oob[min(unix.CmsgSpace(l-hdrLen), len(oob)):]
	}
	return 0
}
