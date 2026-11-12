package sockopt

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Apply sets opts on the socket fd. macOS has no socket marks: a full
// tunnel instead binds each carrier to its underlay interface, and a socket
// bound with IP_BOUND_IF is routed by that interface's scoped routes, never
// the tunnel's.
func Apply(fd int, opts Options) error {
	if opts.Mark != 0 {
		return errors.New("sockopt: socket marks require Linux; bind the carrier to an interface instead")
	}
	if opts.Device == "" {
		return nil
	}
	ifi, err := net.InterfaceByName(opts.Device)
	if err != nil {
		return err
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return err
	}
	if _, v6 := sa.(*unix.SockaddrInet6); v6 {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifi.Index)
	} else {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
	}
	if err != nil {
		return fmt.Errorf("sockopt: bind to %s: %w", opts.Device, err)
	}
	return nil
}
