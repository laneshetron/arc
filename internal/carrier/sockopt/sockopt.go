// Package sockopt applies the socket options that keep a carrier's own
// packets out of the tunnel and on one underlay (spec §17.1): a firewall
// mark for policy routing and binding to a network interface.
package sockopt

import "syscall"

// Options are the carrier socket options; zero values leave them unset.
type Options struct {
	Mark   uint32 // SO_MARK (Linux)
	Device string // SO_BINDTODEVICE (Linux)
}

// Control returns a net.Dialer or net.ListenConfig Control function that
// applies opts.
func Control(opts Options) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) { sockErr = Apply(int(fd), opts) }); err != nil {
			return err
		}
		return sockErr
	}
}
