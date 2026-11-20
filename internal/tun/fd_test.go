//go:build linux || darwin

package tun

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// A descriptor that is not a TUN device is refused, and FromFD still
// closes it, since it took ownership.
func TestFromFDRejectsNonTUN(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := FromFD(fd); err == nil {
		d.Close()
		t.Fatal("FromFD accepted a pipe")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); !errors.Is(err, syscall.EBADF) {
		syscall.Close(fd)
		t.Fatalf("FromFD left the rejected descriptor open (fstat: %v)", err)
	}
}
