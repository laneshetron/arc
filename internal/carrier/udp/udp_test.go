package udp

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestBatchRoundTrip(t *testing.T) {
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	a, err := Listen(loop, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Listen(loop, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	const n = 16
	var pkts [][]byte
	var to []netip.AddrPort
	for i := range n {
		pkts = append(pkts, []byte(fmt.Sprintf("datagram %02d", i)))
		to = append(to, b.LocalAddr())
	}
	if err := a.WriteBatch(pkts, to); err != nil {
		t.Fatal(err)
	}

	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, MaxDatagram)
	}
	sizes, from := make([]int, n), make([]netip.AddrPort, n)
	got := 0
	for got < n {
		k, err := b.ReadBatch(bufs[got:], sizes[got:], from[got:])
		if err != nil {
			t.Fatal(err)
		}
		got += k
	}
	for i := range n {
		if !bytes.Equal(bufs[i][:sizes[i]], pkts[i]) || from[i] != a.LocalAddr() {
			t.Errorf("datagram %d: %q from %v", i, bufs[i][:sizes[i]], from[i])
		}
	}
}

// readOne reads one datagram from c, failing the test after a second.
func readOne(t *testing.T, c *Conn) ([]byte, netip.AddrPort) {
	t.Helper()
	c.uc.SetReadDeadline(time.Now().Add(time.Second))
	defer c.uc.SetReadDeadline(time.Time{})
	bufs, sizes, from := [][]byte{make([]byte, MaxDatagram)}, make([]int, 1), make([]netip.AddrPort, 1)
	for {
		n, err := c.ReadBatch(bufs, sizes, from)
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return bufs[0][:sizes[0]], from[0]
		}
	}
}

func TestConnectedPeer(t *testing.T) {
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	peer, err := Listen(loop, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	stranger, err := Listen(loop, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	c, err := Listen(loop, Options{Peer: peer.LocalAddr()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.WriteBatch([][]byte{[]byte("out")}, []netip.AddrPort{peer.LocalAddr()}); err != nil {
		t.Fatal(err)
	}
	if p, from := readOne(t, peer); string(p) != "out" || from != c.LocalAddr() {
		t.Errorf("peer got %q from %v", p, from)
	}
	if err := c.WriteBatch([][]byte{[]byte("astray")}, []netip.AddrPort{stranger.LocalAddr()}); err == nil {
		t.Error("sent to an address other than the peer")
	}

	// The kernel drops the stranger's datagram; the peer's arrives.
	stranger.WriteBatch([][]byte{[]byte("stranger")}, []netip.AddrPort{c.LocalAddr()})
	peer.WriteBatch([][]byte{[]byte("in")}, []netip.AddrPort{c.LocalAddr()})
	if p, from := readOne(t, c); string(p) != "in" || from != peer.LocalAddr() {
		t.Errorf("got %q from %v, want the peer's datagram", p, from)
	}
}

// A connected socket learns of ICMP port unreachable errors; they must not
// end reading or sending, since the peer may only be restarting. As in the
// engine, a read is pending while the peer is away.
func TestConnectedPeerRestart(t *testing.T) {
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	peer, err := Listen(loop, Options{})
	if err != nil {
		t.Fatal(err)
	}
	addr := peer.LocalAddr()
	c, err := Listen(loop, Options{Peer: addr})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer.Close()

	type result struct {
		p   []byte
		err error
	}
	got := make(chan result, 1)
	go func() {
		bufs, sizes, from := [][]byte{make([]byte, MaxDatagram)}, make([]int, 1), make([]netip.AddrPort, 1)
		n, err := c.ReadBatch(bufs, sizes, from)
		for n == 0 && err == nil {
			n, err = c.ReadBatch(bufs, sizes, from)
		}
		got <- result{bufs[0][:sizes[0]], err}
	}()
	time.Sleep(10 * time.Millisecond) // let the read block
	// Unanswered: the peer's port is closed.
	for range 3 {
		if err := c.WriteBatch([][]byte{[]byte("anyone?")}, []netip.AddrPort{addr}); err != nil {
			t.Fatalf("send while the peer is down: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if peer, err = Listen(addr, Options{}); err != nil {
		t.Skipf("cannot reopen the peer's port: %v", err)
	}
	defer peer.Close()
	peer.WriteBatch([][]byte{[]byte("back")}, []netip.AddrPort{c.LocalAddr()})
	select {
	case r := <-got:
		if r.err != nil || string(r.p) != "back" {
			t.Errorf("read %q, %v; want the restarted peer's datagram", r.p, r.err)
		}
	case <-time.After(time.Second):
		t.Error("no datagram from the restarted peer")
	}
}

// ICMP and route errors a connected socket reports must not end its reader
// or count as send failures. macOS reported "recvmsg: network is
// unreachable" on Wi-Fi, and the client exited.
func TestRefused(t *testing.T) {
	for _, errno := range []syscall.Errno{
		syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH,
		syscall.EHOSTDOWN, syscall.ENETDOWN,
	} {
		err := &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvmsg", errno)}
		if !refused(err) {
			t.Errorf("%v is fatal; want it read past", err)
		}
	}
	for _, err := range []error{net.ErrClosed, os.ErrDeadlineExceeded, syscall.EBADF, syscall.EMSGSIZE} {
		if refused(err) {
			t.Errorf("%v is read past; want it returned", err)
		}
	}
}

// A datagram the kernel refuses is dropped alone; the rest of the batch is
// still sent.
func TestWriteBatchSkipsRefused(t *testing.T) {
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	for _, opts := range []Options{{}, {NoOffload: true}} {
		a, err := Listen(loop, opts)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		b, err := Listen(loop, Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		pkts := [][]byte{[]byte("first"), make([]byte, MaxDatagram), []byte("last")} // too big for UDP
		to := []netip.AddrPort{b.LocalAddr(), b.LocalAddr(), b.LocalAddr()}
		if err := a.WriteBatch(pkts, to); err == nil {
			t.Errorf("%+v: oversized datagram sent without error", opts)
		}
		for _, want := range []string{"first", "last"} {
			if p, _ := readOne(t, b); string(p) != want {
				t.Errorf("%+v: got %q, want %q", opts, p, want)
			}
		}
	}
}

// TestReconnect checks that a connected socket still exchanges datagrams
// with its peer after connecting again, which is how it recovers from
// losing its source address (see TestConnectedSourceAddressChange).
func TestReconnect(t *testing.T) {
	peer, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var reconnected []netip.AddrPort
	c, err := Listen(netip.MustParseAddrPort("0.0.0.0:0"), Options{
		Peer: peer.LocalAddr(), OnReconnect: func(a netip.AddrPort) { reconnected = append(reconnected, a) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.reconnect(); err != nil {
		t.Fatal(err)
	}
	if len(reconnected) != 1 || reconnected[0] != c.LocalAddr() || !c.LocalAddr().Addr().IsLoopback() {
		t.Errorf("OnReconnect calls %v; want one with %v", reconnected, c.LocalAddr())
	}
	if err := c.WriteBatch([][]byte{[]byte("out")}, []netip.AddrPort{peer.LocalAddr()}); err != nil {
		t.Fatal(err)
	}
	if p, from := readOne(t, peer); string(p) != "out" || from != c.LocalAddr() {
		t.Errorf("peer got %q from %v; want it from %v", p, from, c.LocalAddr())
	}
	peer.WriteBatch([][]byte{[]byte("in")}, []netip.AddrPort{c.LocalAddr()})
	if p, from := readOne(t, c); string(p) != "in" || from != peer.LocalAddr() {
		t.Errorf("got %q from %v", p, from)
	}
}

func TestSourceLost(t *testing.T) {
	for _, e := range []syscall.Errno{syscall.EADDRNOTAVAIL, syscall.ENETUNREACH, syscall.EDESTADDRREQ} {
		if err := (&net.OpError{Op: "write", Err: os.NewSyscallError("sendmsg", e)}); !sourceLost(err) {
			t.Errorf("%v: want a reconnect", err)
		}
	}
	for _, e := range []syscall.Errno{syscall.ECONNREFUSED, syscall.ENOBUFS, syscall.EMSGSIZE, syscall.EHOSTDOWN} {
		if err := (&net.OpError{Op: "write", Err: os.NewSyscallError("sendmsg", e)}); sourceLost(err) {
			t.Errorf("%v: want no reconnect", err)
		}
	}
}

// TestSendWhileUnconnected checks that a socket a failed reconnect left
// unconnected (on macOS, while the interface has no address) connects
// again on the next send.
func TestSendWhileUnconnected(t *testing.T) {
	peer, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c, err := Listen(netip.MustParseAddrPort("0.0.0.0:0"), Options{Peer: peer.LocalAddr()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var derr error
	if err := c.raw.Control(func(fd uintptr) { derr = disconnectFD(int(fd)) }); err != nil || derr != nil {
		t.Fatal(err, derr)
	}
	if err := c.WriteBatch([][]byte{[]byte("out")}, []netip.AddrPort{peer.LocalAddr()}); err != nil {
		t.Fatal(err)
	}
	if p, from := readOne(t, peer); string(p) != "out" || from != c.LocalAddr() {
		t.Errorf("peer got %q from %v; want it from %v", p, from, c.LocalAddr())
	}
}
