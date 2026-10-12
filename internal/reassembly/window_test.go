package reassembly

import (
	"math/rand/v2"
	"testing"
)

func TestWindowBasics(t *testing.T) {
	var w Window
	for _, id := range []uint64{5, 7, 6, 100} {
		if !w.Deliver(id) {
			t.Fatalf("new id %d rejected", id)
		}
	}
	for _, id := range []uint64{5, 6, 7, 100} {
		if w.Deliver(id) {
			t.Fatalf("duplicate id %d accepted", id)
		}
	}
	w.Deliver(100 + WindowSize)
	if w.Deliver(100) || w.Deliver(99) {
		t.Fatal("id older than the window accepted")
	}
	if !w.Deliver(101) {
		t.Fatal("id at the window's edge rejected")
	}
}

// TestWindowMatchesSet checks the window against an exact set over random
// streams with reordering, duplication, and jumps.
func TestWindowMatchesSet(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	var w Window
	seen := map[uint64]bool{}
	var highest uint64
	next := uint64(0)
	for range 200_000 {
		var id uint64
		switch r := rng.IntN(100); {
		case r < 70:
			id = next
			next++
		case r < 90: // a copy or a late arrival
			id = next - min(next, uint64(rng.IntN(2*WindowSize)))
		case r < 99:
			next += uint64(rng.IntN(64))
			id = next
		default:
			next += uint64(rng.IntN(4 * WindowSize))
			id = next
		}
		highest = max(highest, id)
		want := !seen[id] && highest-id < WindowSize
		if got := w.Deliver(id); got != want {
			t.Fatalf("Deliver(%d) = %v, want %v (highest %d)", id, got, want, highest)
		}
		seen[id] = true
	}
}
