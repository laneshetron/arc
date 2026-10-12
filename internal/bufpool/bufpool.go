// Package bufpool recycles packet buffers on the data path, so that
// steady-state forwarding does not allocate per packet.
//
// Ownership is explicit: whoever holds a buffer from Get either passes it
// on or returns it with Put exactly once. Put ignores buffers that did not
// come from the pool, so callers may hand it any packet slice they own.
package bufpool

import "sync"

// Packet is the capacity of packet buffers: enough for any ARC packet on a
// path up to a 2048-byte MTU, and any TUN-MTU IP packet.
const Packet = 2048

// Datagram is the capacity of receive buffers for carrier datagrams: the
// largest ARC packet (spec §7).
const Datagram = 16384

// maxFree bounds how many idle buffers each pool keeps.
const maxFree = 8192

// freeList is a LIFO of idle buffers. Unlike sync.Pool it stores slices
// directly, so Put does not allocate.
type freeList struct {
	mu   sync.Mutex
	size int
	free [][]byte
}

func (f *freeList) get() []byte {
	f.mu.Lock()
	if n := len(f.free); n > 0 {
		b := f.free[n-1]
		f.free[n-1] = nil
		f.free = f.free[:n-1]
		f.mu.Unlock()
		return b
	}
	f.mu.Unlock()
	return make([]byte, 0, f.size)
}

func (f *freeList) put(b []byte) {
	f.mu.Lock()
	if len(f.free) < maxFree {
		f.free = append(f.free, b[:0])
	}
	f.mu.Unlock()
}

var (
	packets   = freeList{size: Packet}
	datagrams = freeList{size: Datagram}
)

// Get returns a zero-length buffer with capacity Packet.
func Get() []byte { return packets.get() }

// GetDatagram returns a full-length buffer with capacity Datagram.
func GetDatagram() []byte { return datagrams.get()[:Datagram] }

// Put returns a buffer obtained from Get or GetDatagram. Slicing a buffer
// does not change its capacity, so b may be any slice of one that starts
// at its first byte. Buffers with other capacities are left for the
// garbage collector.
func Put(b []byte) {
	switch cap(b) {
	case Packet:
		packets.put(b)
	case Datagram:
		datagrams.put(b)
	}
}
