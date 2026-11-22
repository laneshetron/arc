package tun

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// FromFD refuses Linux TUN descriptors whose framing is not raw IP, and
// closes them, since it took ownership. Needs root.
func TestFromFDRejectsWrongFraming(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a TUN device")
	}
	for _, tc := range []struct {
		name  string
		flags uint16
	}{
		{"packet-info", unix.IFF_TUN},
		{"tap", unix.IFF_TAP | unix.IFF_NO_PI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			ifr, err := unix.NewIfreq("arcframe0")
			if err != nil {
				t.Fatal(err)
			}
			ifr.SetUint16(tc.flags)
			if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
				unix.Close(fd)
				t.Fatal(err)
			}
			if d, err := FromFD(fd); err == nil {
				d.Close()
				t.Fatalf("FromFD accepted a device with flags %#x", tc.flags)
			}
			var st syscall.Stat_t
			if err := syscall.Fstat(fd, &st); !errors.Is(err, syscall.EBADF) {
				syscall.Close(fd)
				t.Fatalf("FromFD left the rejected descriptor open (fstat: %v)", err)
			}
		})
	}
}
