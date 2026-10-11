package crypto

// Replay window geometry: a ring of 128 64-bit blocks. The newest block is
// always partially valid, so the guaranteed window is 127 blocks, which
// exceeds the 4,096-packet minimum in §13.
const (
	replayRingBlocks = 128
	ReplayWindowSize = (replayRingBlocks - 1) * 64
)

// ReplayWindow tracks which packet numbers of one path and direction have
// been accepted. The zero value is ready to use.
//
// Use Check before decrypting and Record only after authentication succeeds,
// so unauthenticated packets never move the window (§13).
type ReplayWindow struct {
	highest uint64
	started bool
	ring    [replayRingBlocks]uint64
}

// Check reports whether pn is neither a duplicate nor too old.
func (w *ReplayWindow) Check(pn uint64) bool {
	if !w.started || pn > w.highest {
		return true
	}
	if w.highest-pn >= ReplayWindowSize {
		return false
	}
	return w.ring[(pn/64)%replayRingBlocks]&(1<<(pn%64)) == 0
}

// Record marks pn as received. It returns false, recording nothing, if pn
// fails Check.
func (w *ReplayWindow) Record(pn uint64) bool {
	if !w.Check(pn) {
		return false
	}
	if !w.started {
		w.highest, w.started = pn, true
	} else if pn > w.highest {
		cur, next := w.highest/64, pn/64
		gap := next - cur
		if gap > replayRingBlocks {
			gap = replayRingBlocks
		}
		for i := uint64(1); i <= gap; i++ {
			w.ring[(cur+i)%replayRingBlocks] = 0
		}
		w.highest = pn
	}
	w.ring[(pn/64)%replayRingBlocks] |= 1 << (pn % 64)
	return true
}
