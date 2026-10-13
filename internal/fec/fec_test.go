package fec

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
	"time"
)

var t0 = time.Unix(1_000_000, 0)

// packet returns an IPv4 packet of size bytes whose contents depend on id.
func packet(id uint64, size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	for i := 20; i < size; i++ {
		p[i] = byte(id) ^ byte(i)
	}
	return p
}

func fixed(m int) func(int) int { return func(int) int { return m } }

func TestRebuildsUpToMLosses(t *testing.T) {
	for _, lost := range [][]int{{0}, {3}, {0, 7}, {2, 3, 4}, {9}} {
		e := Encoder{MaxK: 10, Window: time.Second, Repairs: fixed(3)}
		var sources [][]byte
		var repairs []Repair
		for i := range 10 {
			p := packet(uint64(100+i), 200+37*i) // mixed sizes
			sources = append(sources, p)
			repairs = append(repairs, e.Add(t0, uint64(100+i), p)...)
		}
		if len(repairs) != 3 {
			t.Fatalf("%d repairs for a full block, want 3", len(repairs))
		}
		d := NewDecoder(DecoderConfig{})
		isLost := map[int]bool{}
		for _, i := range lost {
			isLost[i] = true
		}
		for i, p := range sources {
			if !isLost[i] {
				d.Source(t0, uint64(100+i), p)
			}
		}
		var got []Recovered
		for _, r := range repairs {
			got = append(got, d.Repair(t0, r)...)
		}
		if len(got) != len(lost) {
			t.Fatalf("lost %v: rebuilt %d packets", lost, len(got))
		}
		for _, r := range got {
			if !bytes.Equal(r.Pkt, sources[r.ID-100]) {
				t.Fatalf("lost %v: packet %d rebuilt wrong (%d bytes, want %d)", lost, r.ID, len(r.Pkt), len(sources[r.ID-100]))
			}
		}
	}
}

func TestTooManyLossesRebuildNothing(t *testing.T) {
	e := Encoder{MaxK: 8, Window: time.Second, Repairs: fixed(2)}
	var repairs []Repair
	for i := range 8 {
		repairs = append(repairs, e.Add(t0, uint64(i), packet(uint64(i), 300))...)
	}
	d := NewDecoder(DecoderConfig{})
	for i := 3; i < 8; i++ { // three of eight lost, two repairs
		d.Source(t0, uint64(i), packet(uint64(i), 300))
	}
	for _, r := range repairs {
		if got := d.Repair(t0, r); len(got) != 0 {
			t.Fatalf("rebuilt %d packets from too few symbols", len(got))
		}
	}
}

func TestRepairsBeforeSources(t *testing.T) {
	// Reordering: the repairs arrive first, then the sources that make the
	// block decodable.
	e := Encoder{MaxK: 4, Window: time.Second, Repairs: fixed(1)}
	var repairs []Repair
	for i := range 4 {
		repairs = append(repairs, e.Add(t0, uint64(i), packet(uint64(i), 500))...)
	}
	d := NewDecoder(DecoderConfig{})
	if got := d.Repair(t0, repairs[0]); len(got) != 0 {
		t.Fatal("rebuilt before enough symbols")
	}
	d.Source(t0, 0, packet(0, 500))
	d.Source(t0, 1, packet(1, 500))
	got := d.Source(t0, 3, packet(3, 500))
	if len(got) != 1 || got[0].ID != 2 || !bytes.Equal(got[0].Pkt, packet(2, 500)) {
		t.Fatalf("rebuilt %+v, want packet 2", got)
	}
}

func TestWindowAndGapsCloseBlocks(t *testing.T) {
	e := Encoder{MaxK: 32, Window: 10 * time.Millisecond, Repairs: fixed(1)}
	e.Add(t0, 1, packet(1, 100))
	e.Add(t0.Add(time.Millisecond), 2, packet(2, 100))
	if got := e.Flush(t0.Add(5 * time.Millisecond)); got != nil {
		t.Fatal("block closed before its window")
	}
	if d := e.Deadline(); !d.Equal(t0.Add(10 * time.Millisecond)) {
		t.Fatalf("deadline %v", d)
	}
	got := e.Flush(t0.Add(10 * time.Millisecond))
	if len(got) != 1 || got[0].First != 1 || got[0].K != 2 {
		t.Fatalf("window close: %+v", got)
	}
	if !e.Deadline().IsZero() {
		t.Fatal("deadline after the block closed")
	}
	// An ID gap (a packet sent without FEC) closes the block before it.
	e.Add(t0, 10, packet(10, 100))
	got = e.Add(t0, 12, packet(12, 100))
	if len(got) != 1 || got[0].First != 10 || got[0].K != 1 {
		t.Fatalf("gap close: %+v", got)
	}
}

// stream sends n packets through an encoder and a lossy channel and
// returns the fraction of packets the receiver ends up without.
func stream(t *testing.T, n int, lose func() bool, e *Encoder) float64 {
	t.Helper()
	d := NewDecoder(DecoderConfig{})
	have := map[uint64]bool{}
	now := t0
	deliver := func(rs []Repair) {
		for _, r := range rs {
			if !lose() {
				for _, got := range d.Repair(now, r) {
					have[got.ID] = true
				}
			}
		}
	}
	for i := range n {
		now = now.Add(time.Millisecond)
		id := uint64(i)
		p := packet(id, 600+i%700)
		repairs := e.Add(now, id, p)
		if !lose() {
			have[id] = true
			for _, got := range d.Source(now, id, p) {
				have[got.ID] = true
			}
		}
		deliver(repairs)
		deliver(e.Flush(now))
	}
	return 1 - float64(len(have))/float64(n)
}

func TestStreamResidualLoss(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	uniform := func(p float64) func() bool { return func() bool { return rng.Float64() < p } }
	bursty := func(loss, burst float64) func() bool {
		r := 1 / burst
		p := loss * r / (1 - loss)
		bad := false
		return func() bool {
			if bad {
				bad = rng.Float64() >= r
			} else {
				bad = rng.Float64() < p
			}
			return bad
		}
	}
	for _, tc := range []struct {
		name string
		lose func() bool
		k, m int
		want float64 // residual loss at most

		d int
	}{
		{"uniform 1%, 32+2", uniform(0.01), 32, 2, 0.001, 1},
		{"uniform 5%, 32+5", uniform(0.05), 32, 5, 0.005, 1},
		{"bursty 1% (4), 16+3 x4", bursty(0.01, 4), 16, 3, 0.002, 4},
		// Long bursts are hard for FEC: geometric burst lengths have a long
		// tail. Interleaving 8 deep cuts 5% to about 1% at 25% overhead;
		// without it, the same overhead leaves about 4%.
		{"bursty 5% (10), 16+4 x8", bursty(0.05, 10), 16, 4, 0.015, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := stream(t, 200_000, tc.lose, &Encoder{MaxK: tc.k, Depth: tc.d, Window: time.Second, Repairs: fixed(tc.m)})
			t.Logf("residual loss %.4f", got)
			if got > tc.want {
				t.Errorf("residual loss %.4f, want at most %.4f", got, tc.want)
			}
		})
	}
}

func TestDecoderMemoryBounded(t *testing.T) {
	d := NewDecoder(DecoderConfig{StoreBytes: 10_000})
	for i := range 1000 {
		d.Source(t0, uint64(i), packet(uint64(i), 1000))
	}
	if d.bytes > 10_000 || len(d.store) > 10 {
		t.Errorf("store holds %d bytes in %d packets, bound 10000", d.bytes, len(d.store))
	}
	d.Source(t0.Add(3*time.Second), 5000, packet(5000, 100))
	if len(d.store) != 1 {
		t.Errorf("%d stored packets after StoreAge", len(d.store))
	}
}

func TestIPLength(t *testing.T) {
	v6 := make([]byte, 100)
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:6], 20) // 60-byte packet
	if p, err := ipPacket(v6); err != nil || len(p) != 60 {
		t.Errorf("IPv6: %d bytes, %v", len(p), err)
	}
	bad := packet(1, 100)
	binary.BigEndian.PutUint16(bad[2:4], 200) // longer than the shard
	if _, err := ipPacket(bad); err == nil {
		t.Error("accepted a length beyond the shard")
	}
}

func TestInterleaving(t *testing.T) {
	// Depth 3, blocks of 2: IDs 10..15 go to blocks {10,13}, {11,14},
	// {12,15}, and repairs come out interleaved by block.
	e := Encoder{MaxK: 2, Depth: 3, Window: time.Second, Repairs: fixed(2)}
	var repairs []Repair
	for id := uint64(10); id < 16; id++ {
		repairs = append(repairs, e.Add(t0, id, packet(id, 300))...)
	}
	if len(repairs) != 6 {
		t.Fatalf("%d repairs, want 6", len(repairs))
	}
	for i, r := range repairs {
		if r.First != 10+uint64(i%3) || r.Stride != 3 || r.K != 2 || r.Index != i/3 {
			t.Fatalf("repair %d: %+v", i, r)
		}
	}
	// A burst of three consecutive packets costs each block one: all
	// rebuilt.
	d := NewDecoder(DecoderConfig{})
	for _, id := range []uint64{10, 14, 15} {
		d.Source(t0, id, packet(id, 300))
	}
	var got []Recovered
	for _, r := range repairs {
		got = append(got, d.Repair(t0, r)...)
	}
	if len(got) != 3 {
		t.Fatalf("rebuilt %d of a 3-packet burst", len(got))
	}
}

func TestSizing(t *testing.T) {
	if m := RepairsFor(32, 0, 0.001); m != 0 {
		t.Errorf("no loss: %d repairs", m)
	}
	if m := RepairsFor(32, 0.01, 0.001); m < 2 || m > 4 {
		t.Errorf("1%% loss, k=32: %d repairs", m)
	}
	if m := RepairsFor(16, 0.05, 0.001); m < 4 || m > 6 {
		t.Errorf("5%% loss, k=16: %d repairs", m)
	}
	if m := RepairsFor(10, 0.5, 0.001); m != 5 {
		t.Errorf("50%% loss, k=10: %d repairs, want the cap of 5", m)
	}
	if DepthFor(1) != 1 || DepthFor(4) != 4 || DepthFor(30) != 8 {
		t.Error("DepthFor")
	}
}
