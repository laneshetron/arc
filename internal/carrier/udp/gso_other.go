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
