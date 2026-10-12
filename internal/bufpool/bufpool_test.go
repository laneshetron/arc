package bufpool

import "testing"

func TestGetPutReuse(t *testing.T) {
	b := Get()
	if len(b) != 0 || cap(b) != Packet {
		t.Fatalf("Get: len %d cap %d", len(b), cap(b))
	}
	d := GetDatagram()
	if len(d) != Datagram || cap(d) != Datagram {
		t.Fatalf("GetDatagram: len %d cap %d", len(d), cap(d))
	}
	Put(b[:100])
	Put(d[:5])
	Put(make([]byte, 77)) // foreign buffers are ignored
	allocs := testing.AllocsPerRun(1000, func() {
		p := append(Get(), 1, 2, 3)
		Put(p)
	})
	if allocs > 0 {
		t.Errorf("steady-state Get/Put allocates %v times", allocs)
	}
}
