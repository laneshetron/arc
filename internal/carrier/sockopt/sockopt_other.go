//go:build !linux

package sockopt

import "errors"

// Apply sets opts on the socket fd.
func Apply(_ int, opts Options) error {
	if opts.Mark != 0 || opts.Device != "" {
		return errors.New("sockopt: socket marks and device binding require Linux")
	}
	return nil
}
