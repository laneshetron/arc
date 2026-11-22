package tun

import (
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// fromFD takes ownership of fd. CreateTUNFromFile would set the MTU
// unconditionally, and Linux rejects 0, so this uses the unmonitored
// constructor, which leaves the MTU alone (as wireguard-android does).
//
// That constructor wraps the descriptor in an os.File but drops it on
// failure, leaving the close to a finalizer. So it gets a duplicate: on
// failure the finalizer closes only the duplicate, and fd is closed here.
func fromFD(fd int) (wgtun.Device, error) {
	defer unix.Close(fd)
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	dev, _, err := wgtun.CreateUnmonitoredTUNFromFD(dup)
	if err != nil {
		return nil, err
	}
	return dev, nil
}
