package tun

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

// FromFD wraps a real, configured utun without changing its MTU, keeps it
// close-on-exec, and Close wakes a pending Read, even when the owner handed
// over a blocking descriptor without close-on-exec (syscall.Dup clears it).
// Creating the utun needs root, so this skips otherwise; CI runs it with
// sudo on macOS.
func TestFromFDRealTUN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a utun")
	}
	const mtu = 1400
	owner, err := Create(DefaultName, mtu)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ownerFile := owner.dev.(interface{ File() *os.File }).File()
	fd, err := syscall.Dup(int(ownerFile.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	// Hand over a blocking descriptor, as a provider might. The flag is
	// shared with the owner's descriptor, which is never read here.
	if err := unix.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}

	d, err := FromFD(fd)
	if err != nil {
		t.Fatalf("FromFD on a configured utun: %v", err)
	}
	if d.Name() != owner.Name() {
		t.Errorf("name %q, want %q", d.Name(), owner.Name())
	}
	if got, err := d.dev.MTU(); err != nil || got != mtu {
		t.Errorf("MTU after FromFD = %d (%v), want %d left as configured", got, err, mtu)
	}
	// Not File().Fd(): that would put the descriptor back in blocking mode.
	rc, err := d.dev.(interface{ File() *os.File }).File().SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fdFlags int
	var fcntlErr error
	if err := rc.Control(func(fd uintptr) { fdFlags, fcntlErr = unix.FcntlInt(fd, unix.F_GETFD, 0) }); err != nil {
		t.Fatal(err)
	}
	if fcntlErr != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		t.Errorf("kept descriptor is not close-on-exec (flags %#x, %v)", fdFlags, fcntlErr)
	}

	done := make(chan error, 1)
	go func() {
		_, err := d.Read()
		done <- err
	}()
	time.Sleep(100 * time.Millisecond) // let the Read block
	// With a blocking descriptor Close itself can block behind the Read,
	// so it runs aside too, and the test fails rather than hangs.
	go d.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Read returned no error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake a pending Read")
	}
}
