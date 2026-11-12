//go:build !linux

package udp

import "golang.org/x/sys/unix"

// connectFD connects fd to sa, choosing the source address afresh: on
// macOS, connecting a connected UDP socket disconnects it first, which
// clears its source address, and the port stays. The socket's interface
// binding (IP_BOUND_IF) survives.
func connectFD(fd int, sa *unix.SockaddrInet4, _ string) error { return unix.Connect(fd, sa) }
