//go:build linux || darwin

package tun

import (
	"golang.org/x/sys/unix"
)

// FromFD wraps a TUN device that someone else created and configured, such
// as the utun a NetworkExtension packet tunnel provider owns. The Device
// takes ownership of fd and closes it on Close, even when FromFD fails. It
// leaves the MTU, addresses, routes and DNS alone: the owner sets those, so
// callers must not use Configure, AddRoute, FullTunnel or ConfigureDNS on it.
func FromFD(fd int) (*Device, error) {
	// Go's poller adopts an inherited descriptor only if it is already
	// nonblocking, and the engine relies on Close waking a pending Read.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	dev, err := fromFD(fd)
	if err != nil {
		return nil, err
	}
	return wrap(dev)
}
