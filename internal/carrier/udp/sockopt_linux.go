package udp

import (
	"golang.org/x/sys/unix"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
)

func setSockopts(fd int, opts Options) error {
	return sockopt.Apply(fd, sockopt.Options{Mark: opts.Mark, Device: opts.Device})
}

// forceBuffers sets the socket buffers past net.core.{r,w}mem_max, which
// needs CAP_NET_ADMIN. It reports whether both succeeded.
func forceBuffers(fd, size int) bool {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size) == nil &&
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size) == nil
}
