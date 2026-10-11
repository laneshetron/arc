package udp

import "golang.org/x/sys/unix"

func setSockopts(fd int, opts Options) error {
	if opts.Mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(opts.Mark)); err != nil {
			return err
		}
	}
	if opts.Device != "" {
		if err := unix.BindToDevice(fd, opts.Device); err != nil {
			return err
		}
	}
	return nil
}

// forceBuffers sets the socket buffers past net.core.{r,w}mem_max, which
// needs CAP_NET_ADMIN. It reports whether both succeeded.
func forceBuffers(fd, size int) bool {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size) == nil &&
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size) == nil
}
