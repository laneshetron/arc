package tun

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

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
	if err := checkTUNFlags(fd); err != nil {
		return nil, err
	}
	// Plain dup clears close-on-exec; a child must not inherit the TUN and
	// keep it alive after Close.
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dev, _, err := wgtun.CreateUnmonitoredTUNFromFD(dup)
	if err != nil {
		return nil, err
	}
	return dev, nil
}

// checkTUNFlags requires a TUN (not TAP) device without packet information
// headers: the engine reads and writes raw IP packets, and wireguard-go
// accepts either kind without handling the 4-byte header.
//
// IFF_NO_PI comes from sysfs, not TUNGETIFF: the kernel ORs IFF_NOFILTER
// into TUNGETIFF's answer whenever no socket filter is attached, and
// IFF_NOFILTER and IFF_NO_PI are the same bit (0x1000), so TUNGETIFF
// reports IFF_NO_PI for every ordinary device.
func checkTUNFlags(fd int) error {
	ifr, err := unix.NewIfreq("")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
		return fmt.Errorf("not a TUN device: %w", err)
	}
	if ifr.Uint16()&(unix.IFF_TUN|unix.IFF_TAP) != unix.IFF_TUN {
		return errors.New("not a TUN device: it is a TAP device")
	}
	name := ifr.Name()
	b, err := os.ReadFile("/sys/class/net/" + name + "/tun_flags")
	if err != nil {
		return fmt.Errorf("checking %s for packet information headers: %w", name, err)
	}
	flags, err := strconv.ParseUint(strings.TrimSpace(string(b)), 0, 32)
	if err != nil {
		return fmt.Errorf("checking %s for packet information headers: %w", name, err)
	}
	if flags&unix.IFF_NO_PI == 0 {
		return fmt.Errorf("TUN device %s has packet information headers (opened without IFF_NO_PI)", name)
	}
	return nil
}
