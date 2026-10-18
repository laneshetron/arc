package udp

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// connectFD connects fd to sa, choosing the source address afresh. Linux
// keeps a connected socket's source address across connect calls, so the
// socket is first disconnected (connect to AF_UNSPEC); that also releases
// its port, and the new connection gets another.
func connectFD(fd int, sa *unix.SockaddrInet4) error {
	unspec := unix.RawSockaddr{Family: unix.AF_UNSPEC}
	if _, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&unspec)), unsafe.Sizeof(unspec)); e != 0 {
		return e
	}
	return unix.Connect(fd, sa)
}
