package udp

import (
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestConnectedSourceAddressChange moves a connected carrier's interface to
// a new address, as DHCP may on waking from sleep, and checks that the
// carrier, bound to that interface as on macOS, then sends from the new
// one. It needs root and ip(8) to create a dummy interface, so it runs
// only in privileged environments such as
//
//	docker run --rm --privileged -v $PWD:/src -w /src golang:1.26 \
//	  sh -c 'apt-get update && apt-get install -y iproute2 && go test -race ./internal/carrier/udp'
func TestConnectedSourceAddressChange(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create an interface")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs ip(8)")
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	const dev = "arcsrc0"
	exec.Command("ip", "link", "del", dev).Run()
	ip("link", "add", dev, "type", "dummy")
	t.Cleanup(func() { exec.Command("ip", "link", "del", dev).Run() })
	ip("link", "set", dev, "up")
	ip("addr", "add", "10.99.0.1/24", "dev", dev)

	// The dummy interface discards what it sends; its counter shows
	// whether a datagram left.
	sent := func() int {
		t.Helper()
		b, err := os.ReadFile("/sys/class/net/" + dev + "/statistics/tx_packets")
		if err != nil {
			t.Fatal(err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	relay := netip.MustParseAddrPort("10.99.0.9:4433")
	var reconnected []netip.AddrPort
	c, err := Listen(netip.MustParseAddrPort("0.0.0.0:0"), Options{
		Peer: relay, Device: dev, OnReconnect: func(local netip.AddrPort) { reconnected = append(reconnected, local) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	send := func() {
		t.Helper()
		if err := c.WriteBatch([][]byte{[]byte("ping")}, []netip.AddrPort{relay}); err != nil {
			t.Fatal(err)
		}
	}
	send()
	if got := c.LocalAddr().Addr(); got != netip.MustParseAddr("10.99.0.1") {
		t.Fatalf("source %v; want 10.99.0.1", got)
	}

	ip("addr", "del", "10.99.0.1/24", "dev", dev)
	ip("addr", "add", "10.99.0.2/24", "dev", dev)
	before := sent()
	send()
	if n := sent() - before; n != 1 {
		t.Errorf("%d datagrams left after the address changed; want 1", n)
	}
	if got := c.LocalAddr().Addr(); got != netip.MustParseAddr("10.99.0.2") {
		t.Errorf("source %v after the address changed; want 10.99.0.2", got)
	}
	if len(reconnected) != 1 || reconnected[0].Addr() != netip.MustParseAddr("10.99.0.2") {
		t.Errorf("OnReconnect calls %v; want one with 10.99.0.2", reconnected)
	}

}
