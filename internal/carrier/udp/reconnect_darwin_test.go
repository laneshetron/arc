package udp

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFailedReconnect binds a connected socket to an interface with no
// IPv4 address, as en0 is while Wi-Fi changes networks, so that
// reconnecting fails. The socket is then left unconnected, and a send must
// report why reconnecting failed, not that the unconnected socket needs a
// destination address (EDESTADDRREQ), which said nothing useful and was
// logged on every flush.
func TestFailedReconnect(t *testing.T) {
	ifc := interfaceWithoutIPv4(t)
	relay := netip.MustParseAddrPort("192.0.2.1:4433") // TEST-NET-1: nothing is sent there
	c, err := Listen(netip.MustParseAddrPort("0.0.0.0:0"), Options{Peer: relay})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var serr error
	if err := c.raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifc.Index)
	}); err != nil || serr != nil {
		t.Fatal(err, serr)
	}
	// The route the socket cached when it connected still works; connect
	// again, as a failed send would, and fail.
	if err := c.reconnect(); err == nil {
		t.Fatalf("reconnecting through %s succeeded", ifc.Name)
	}
	pkts := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	to := []netip.AddrPort{relay, relay, relay}
	for i := range 3 {
		if err := c.WriteBatch(pkts, to); errors.Is(err, syscall.EDESTADDRREQ) {
			t.Fatalf("send %d: %v; want the reconnect's error, if any", i, err)
		}
	}
}

// interfaceWithoutIPv4 returns an up interface with no IPv4 address, such
// as awdl0 or an unused Ethernet port, skipping the test if there is none.
func interfaceWithoutIPv4(t *testing.T) net.Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		v4 := false
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
				v4 = true
			}
		}
		if !v4 {
			return ifc
		}
	}
	t.Skip("no up interface without an IPv4 address")
	return net.Interface{}
}
