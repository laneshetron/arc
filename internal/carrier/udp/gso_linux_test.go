package udp

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
)

// TestGSOSegmentsArriveIntact sends runs that GSO coalesces (equal sizes,
// a shorter final datagram, a size change, two destinations) and checks
// each receiver gets exactly the original datagrams in order.
func TestGSOSegmentsArriveIntact(t *testing.T) {
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	tx, err := Listen(loop, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if !tx.gso {
		t.Skip("kernel without UDP_SEGMENT")
	}
	rxs := make([]*Conn, 2)
	for i := range rxs {
		if rxs[i], err = Listen(loop, Options{}); err != nil {
			t.Fatal(err)
		}
		defer rxs[i].Close()
	}

	var pkts [][]byte
	var to []netip.AddrPort
	want := make([][][]byte, 2)
	add := func(rx, size int) {
		p := bytes.Repeat([]byte{byte(len(pkts))}, size)
		copy(p, fmt.Sprintf("#%03d", len(pkts)))
		pkts, to = append(pkts, p), append(to, rxs[rx].LocalAddr())
		want[rx] = append(want[rx], p)
	}
	for range 70 { // more than one run's worth of segments
		add(0, 1317)
	}
	add(0, 500) // shorter: ends a run
	for range 5 {
		add(0, 900) // new size: new run
	}
	for range 3 {
		add(1, 1317) // new destination
	}
	add(0, 1317)
	if err := tx.WriteBatch(pkts, to); err != nil {
		t.Fatal(err)
	}
	if !tx.gso {
		t.Fatal("GSO was disabled by the send")
	}

	for i, rx := range rxs {
		bufs := make([][]byte, len(want[i]))
		for j := range bufs {
			bufs[j] = make([]byte, MaxDatagram)
		}
		sizes, from := make([]int, len(bufs)), make([]netip.AddrPort, len(bufs))
		got := 0
		for got < len(want[i]) {
			n, err := rx.ReadBatch(bufs[got:], sizes[got:], from[got:])
			if err != nil {
				t.Fatal(err)
			}
			got += n
		}
		for j, w := range want[i] {
			if !bytes.Equal(bufs[j][:sizes[j]], w) {
				t.Fatalf("receiver %d datagram %d: got %d bytes starting %q, want %d bytes starting %q",
					i, j, sizes[j], bufs[j][:4], len(w), w[:4])
			}
		}
	}
}
