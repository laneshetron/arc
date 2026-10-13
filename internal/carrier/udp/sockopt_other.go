//go:build !linux

package udp

import "github.com/laneshetron/arc/internal/carrier/sockopt"

func setSockopts(fd int, opts Options) error {
	return sockopt.Apply(fd, sockopt.Options{Mark: opts.Mark, Device: opts.Device})
}

func forceBuffers(int, int) bool { return false }
