package tun

import (
	"os"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// FromFD wraps a utun that someone else created and configured, such as the
// one a NetworkExtension packet tunnel provider owns. The Device takes
// ownership of fd and closes it on Close, even when FromFD fails. It leaves
// the MTU, addresses, routes and DNS alone: the owner sets those, so callers
// must not use Configure, AddRoute, FullTunnel or ConfigureDNS on it.
//
// It is darwin only. A utun always frames packets with the 4-byte address
// family header wireguard-go expects, but a Linux TUN descriptor can carry
// packet information or virtio headers, or live in another network
// namespace, none of which a wrapper can check cheaply from the descriptor.
func FromFD(fd int) (*Device, error) {
	// Go's poller adopts an inherited descriptor only if it is already
	// nonblocking, and the engine relies on Close waking a pending Read.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// A child must not inherit the TUN and keep it alive after Close.
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "tun")
	// An MTU of 0 leaves the device's MTU as it is.
	dev, err := wgtun.CreateTUNFromFile(f, 0)
	if err != nil {
		f.Close() // wireguard-go has usually closed it already; a second Close is a no-op
		return nil, err
	}
	return wrap(dev)
}
