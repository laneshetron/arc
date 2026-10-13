package reassembly

// Dedup window geometry: a ring of 1,024 64-bit blocks, 8 KiB. The newest
// block is always partially valid, so the guaranteed window is 1,023
// blocks: copies of a datagram are recognized as long as fewer than about
// 65,000 newer datagram IDs arrive between them, which at 100,000 packets
// per second allows a 650 ms difference between paths.
const (
	windowBlocks = 1024
	WindowSize   = (windowBlocks - 1) * 64
)

// Window remembers which datagram IDs have been delivered, so that a
// datagram sent on several paths is delivered once (§11.1). IDs too old
// for the window are treated as already delivered. The zero value is ready
// to use. It is not safe for concurrent use.
type Window struct {
	highest uint64
	started bool
	ring    [windowBlocks]uint64
}

// Deliver records id and reports whether it is new and within the window.
func (w *Window) Deliver(id uint64) bool {
	switch {
	case !w.started:
		w.highest, w.started = id, true
	case id > w.highest:
		cur, next := w.highest/64, id/64
		gap := min(next-cur, windowBlocks)
		for i := uint64(1); i <= gap; i++ {
			w.ring[(cur+i)%windowBlocks] = 0
		}
		w.highest = id
	case w.highest-id >= WindowSize:
		return false
	}
	block, bit := &w.ring[(id/64)%windowBlocks], uint64(1)<<(id%64)
	if *block&bit != 0 {
		return false
	}
	*block |= bit
	return true
}

// Highest returns the highest ID delivered, and whether any has been.
func (w *Window) Highest() (uint64, bool) { return w.highest, w.started }
