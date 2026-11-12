package udp

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// connectFD connects fd to sa, choosing the source address afresh. Linux
// keeps a connected socket's source address across connect calls, so the
// socket is first disconnected (connect to AF_UNSPEC); that also releases
// its port, and the new connection gets another. Disconnecting also
// unbinds the socket from its device (SO_BINDTODEVICE), so a socket
// bound to device is bound again before it connects: otherwise it would
// connect through whatever interface the routing table picks.
func connectFD(fd int, sa *unix.SockaddrInet4, device string) error {
	if err := disconnectFD(fd); err != nil {
		return err
	}
	if device != "" {
		if err := unix.BindToDevice(fd, device); err != nil {
			return err
		}
	}
	return unix.Connect(fd, sa)
}

// disconnectFD dissolves a UDP socket's association with its peer.
func disconnectFD(fd int) error {
	unspec := unix.RawSockaddr{Family: unix.AF_UNSPEC}
	if _, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&unspec)), unsafe.Sizeof(unspec)); e != 0 {
		return e
	}
	return nil
}
