//go:build !linux

package udp

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// disconnectFD dissolves a UDP socket's association with its peer, as a
// failed reconnect leaves it. macOS reports EAFNOSUPPORT for the
// AF_UNSPEC address but disconnects the socket regardless.
func disconnectFD(fd int) error {
	unspec := unix.RawSockaddr{Len: uint8(unsafe.Sizeof(unix.RawSockaddr{})), Family: unix.AF_UNSPEC}
	unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&unspec)), unsafe.Sizeof(unspec))
	return nil
}
