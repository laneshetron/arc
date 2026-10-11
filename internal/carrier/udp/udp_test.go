package udp

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
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
