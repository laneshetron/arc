package tun

import (
	"os"

	"golang.org/x/sys/unix"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// fromFD takes ownership of fd. An MTU of 0 leaves the device's MTU as it is.
func fromFD(fd int) (wgtun.Device, error) {
	// A child must not inherit the TUN and keep it alive after Close.
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "tun")
	dev, err := wgtun.CreateTUNFromFile(f, 0)
	if err != nil {
		f.Close() // wireguard-go has usually closed it already; a second Close is a no-op
		return nil, err
	}
	return dev, nil
}
