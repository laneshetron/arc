//go:build linux || darwin

package tun

import (
	"os"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// FromFD wraps a TUN device that someone else created and configured, such
// as the utun a NetworkExtension packet tunnel provider owns. The Device
// takes ownership of fd and closes it on Close. It leaves the MTU, addresses,
// routes and DNS alone: the owner sets those, so callers must not use
// Configure, AddRoute, FullTunnel or ConfigureDNS on it.
func FromFD(fd int) (*Device, error) {
	f := os.NewFile(uintptr(fd), "tun")
	dev, err := wgtun.CreateTUNFromFile(f, 0)
	if err != nil {
		f.Close() // wireguard-go closes it on darwin but not on linux; a second Close is a no-op
		return nil, err
	}
	return wrap(dev)
}
