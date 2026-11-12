package sockopt

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBindDeviceDarwin(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip(err)
	}
	for _, network := range []string{"udp4", "udp6", "tcp4", "tcp6"} {
		var bound int
		lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
			if err := Control(Options{Device: "lo0"})(network, address, c); err != nil {
				return err
			}
			return c.Control(func(fd uintptr) {
				level, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
				if network[len(network)-1] == '6' {
					level, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
				}
				bound, _ = unix.GetsockoptInt(int(fd), level, opt)
			})
		}}
		addr := "127.0.0.1:0"
		if network[len(network)-1] == '6' {
			addr = "[::1]:0"
		}
		var c interface{ Close() error }
		if network[0] == 'u' {
			c, err = lc.ListenPacket(context.Background(), network, addr)
		} else {
			c, err = lc.Listen(context.Background(), network, addr)
		}
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		c.Close()
		if bound != lo.Index {
			t.Fatalf("%s: bound to interface %d, want lo0 (%d)", network, bound, lo.Index)
		}
	}
	if err := Apply(0, Options{Mark: 1}); err == nil {
		t.Fatal("mark accepted on macOS")
	}
	if err := Apply(0, Options{Device: "no-such-interface0"}); err == nil {
		t.Fatal("unknown interface accepted")
	}
}
