//go:build !linux

package udp

import (
	"net"
	"net/netip"
)

func gsoSupported(*net.UDPConn) bool { return false }
func gsoUnsupported(error) bool      { return false }

func (c *Conn) writeGSO(pkts [][]byte, addrs []netip.AddrPort) error {
	return c.writePlain(pkts, addrs)
}

type groReader struct{}

func enableGRO(*net.UDPConn) *groReader { return nil }

func (*groReader) read([][]byte, []int, []netip.AddrPort) (int, error) { return 0, nil }
