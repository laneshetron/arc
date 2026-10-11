package reassembly

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

var t0 = time.Unix(1000, 0)

func ipv4(n int, fill byte) []byte {
	p := bytes.Repeat([]byte{fill}, n)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(n))
	return p
}

func TestReassembleShuffledWithDuplicates(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	r := New(DefaultConfig())
	for id := range uint64(200) {
		pkt := ipv4(20+rng.IntN(3000), byte(id))
		frags := Fragment(nil, id, pkt, 1+rng.IntN(400))
		frags = append(frags, frags[rng.IntN(len(frags))]) // one duplicate
		rng.Shuffle(len(frags), func(i, j int) { frags[i], frags[j] = frags[j], frags[i] })
		var got []byte
		for i, f := range frags {
			out, err := r.Add(t0, f)
			if err != nil && !errors.Is(err, ErrDuplicate) {
				t.Fatalf("datagram %d fragment %d: %v", id, i, err)
			}
			if out != nil {
				if got != nil {
					t.Fatalf("datagram %d delivered twice", id)
				}
				got = out
			}
		}
		if !bytes.Equal(got, pkt) {
			t.Fatalf("datagram %d: reassembled %d bytes, want %d", id, len(got), len(pkt))
		}
	}
	if n, b := r.Pending(); n != 0 || b != 0 {
		t.Errorf("pending = %d datagrams, %d bytes", n, b)
	}
}

func TestOverlapsMustAgree(t *testing.T) {
	r := New(DefaultConfig())
	pkt := ipv4(100, 7)
	r.Add(t0, wire.IPFragment{DatagramID: 1, TotalLen: 100, Offset: 0, Data: pkt[:60]})
	// A consistent overlap is fine.
	r.Add(t0, wire.IPFragment{DatagramID: 1, TotalLen: 100, Offset: 40, Data: pkt[40:70]})
	bad := bytes.Clone(pkt[50:100])
	bad[0] ^= 1
	if _, err := r.Add(t0, wire.IPFragment{DatagramID: 1, TotalLen: 100, Offset: 50, Data: bad}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting overlap: %v", err)
	}
	if n, _ := r.Pending(); n != 0 {
		t.Error("conflicting datagram not discarded")
	}
	if _, err := r.Add(t0, wire.IPFragment{DatagramID: 2, TotalLen: 100, Data: pkt[:10]}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(t0, wire.IPFragment{DatagramID: 2, TotalLen: 101, Offset: 10, Data: pkt[10:20]}); !errors.Is(err, ErrConflict) {
		t.Errorf("total_len mismatch: %v", err)
	}
}

func TestBoundsAndExpiry(t *testing.T) {
	cfg := Config{MaxDatagrams: 4, MaxBytes: 10000, Timeout: 5 * time.Second, DedupSize: 2}
	r := New(cfg)
	for id := range uint64(10) {
		r.Add(t0, wire.IPFragment{DatagramID: id, TotalLen: 3000, Data: []byte{0x45}})
		if n, b := r.Pending(); n > cfg.MaxDatagrams || b > cfg.MaxBytes {
			t.Fatalf("pending %d datagrams, %d bytes exceeds bounds", n, b)
		}
	}
	r.Expire(t0.Add(5 * time.Second))
	if n, b := r.Pending(); n != 0 || b != 0 {
		t.Errorf("after expiry: %d datagrams, %d bytes", n, b)
	}
	if out, _ := r.Add(t0, wire.IPFragment{DatagramID: 99, TotalLen: 60000, Data: []byte{0x45}}); out != nil {
		t.Error("oversized datagram accepted")
	}
}

func TestDedupAndInvalid(t *testing.T) {
	r := New(Config{MaxDatagrams: 8, MaxBytes: 1 << 20, Timeout: time.Second, DedupSize: 2})
	pkt := ipv4(40, 1)
	whole := wire.IPFragment{DatagramID: 5, TotalLen: 40, Data: pkt}
	if out, err := r.Add(t0, whole); err != nil || out == nil {
		t.Fatal(out, err)
	}
	if _, err := r.Add(t0, whole); !errors.Is(err, ErrDuplicate) {
		t.Errorf("redelivery: %v", err)
	}
	// Push 5 out of the two-entry dedup ring.
	r.Add(t0, wire.IPFragment{DatagramID: 6, TotalLen: 40, Data: ipv4(40, 2)})
	r.Add(t0, wire.IPFragment{DatagramID: 7, TotalLen: 40, Data: ipv4(40, 3)})
	if out, _ := r.Add(t0, whole); out == nil {
		t.Error("ID still remembered after leaving the dedup ring")
	}
	junk := bytes.Repeat([]byte{0x99}, 40)
	if _, err := r.Add(t0, wire.IPFragment{DatagramID: 8, TotalLen: 40, Data: junk}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid IP: %v", err)
	}
}
