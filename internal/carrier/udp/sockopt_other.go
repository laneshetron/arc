//go:build !linux

package udp

import "errors"

func setSockopts(_ int, opts Options) error {
	if opts.Mark != 0 || opts.Device != "" {
		return errors.New("udp: socket marks and device binding require Linux")
	}
	return nil
}
