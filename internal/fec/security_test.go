package fec

import (
	"testing"
	"time"
)

func TestRepairBytesAndBlocksAreBounded(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, cfg := range []DecoderConfig{
		{RepairBytes: 2400, MaxBlocks: 100},
		{RepairBytes: 1 << 20, MaxBlocks: 2},
	} {
		d := NewDecoder(cfg)
		for i := range 3000 {
			d.Repair(now, Repair{First: uint64(i * 64), Stride: 1, K: 64, M: 1, Index: 0, Data: make([]byte, 1200)})
		}
		if d.repairBytes > d.cfg.RepairBytes || len(d.blocks) > d.cfg.MaxBlocks {
			t.Fatalf("retained %d bytes in %d blocks", d.repairBytes, len(d.blocks))
		}
		actual := 0
		for _, b := range d.blocks {
			for _, p := range b.repairs {
				actual += len(p)
			}
		}
		if actual != d.repairBytes {
			t.Fatalf("accounting %d != actual %d", d.repairBytes, actual)
		}
		d.expire(now.Add(3 * time.Second))
		if d.repairBytes != 0 || len(d.blocks) != 0 {
			t.Fatal("expiry did not release repair budget")
		}
		d.Repair(now.Add(3*time.Second), Repair{First: 999999, Stride: 1, K: 2, M: 1, Index: 0, Data: make([]byte, 1200)})
		if d.repairBytes != 1200 {
			t.Fatal("released budget was not reusable")
		}
	}
}

func TestFinishedRepairBudgetAndMetadata(t *testing.T) {
	d := NewDecoder(DecoderConfig{RepairBytes: 1000, MaxDone: 2})
	e := Encoder{MaxK: 1, Repairs: fixed(1)}
	for id := range uint64(10) {
		rs := e.Add(t0, id, packet(id, 100))
		if len(rs) != 1 {
			t.Fatal("missing repair")
		}
		if got := d.Repair(t0, rs[0]); len(got) != 1 {
			t.Fatal("failed to recover")
		}
		if d.repairBytes != 0 {
			t.Fatal("completed block retained budget")
		}
	}
	if len(d.done) > 2 {
		t.Fatal("finished metadata exceeded budget")
	}
}

func TestCodecCacheBounded(t *testing.T) {
	c := codecs{}
	for k := 1; k <= MaxK; k++ {
		if _, err := c.get(k, 1); err != nil {
			t.Fatal(err)
		}
		if len(c) > maxCachedCodecs {
			t.Fatal("unbounded codec cache")
		}
	}
}

func TestRecentFinishedBlocksSurviveMetadataSaturation(t *testing.T) {
	d := NewDecoder(DecoderConfig{MaxDone: 2})
	e := Encoder{MaxK: 1, Repairs: fixed(2)}
	var last []Repair
	for id := range uint64(10) {
		last = e.Add(t0, id, packet(id, 100))
		if len(d.Repair(t0, last[0])) != 1 {
			t.Fatal("repair did not recover")
		}
	}
	if _, ok := d.done[9]; !ok {
		t.Fatal("newest completion not remembered")
	}
	if _, ok := d.done[8]; !ok {
		t.Fatal("second-newest completion not remembered")
	}
	if _, ok := d.done[0]; ok {
		t.Fatal("oldest completion not evicted")
	}
	if got := d.Repair(t0, last[1]); len(got) != 0 || len(d.blocks) != 0 || d.repairBytes != 0 {
		t.Fatal("late repair reconstructed an already completed block")
	}
	d.expire(t0.Add(3 * time.Second))
	if len(d.done) != 0 || d.doneOrder.Len() != 0 {
		t.Fatal("completed metadata did not expire")
	}
}
