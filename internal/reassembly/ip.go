// Package reassembly rebuilds original IP datagrams from IP_FRAGMENT frames
// (spec §11) under fixed memory and time bounds.
package reassembly

import (
	"bytes"
	"container/list"
	"errors"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// Config bounds reassembly state for one session direction.
type Config struct {
	MaxDatagrams int           // incomplete datagrams
	MaxBytes     int           // bytes reserved by incomplete datagrams
	Timeout      time.Duration // lifetime of an incomplete datagram
	DedupSize    int           // recently completed IDs remembered
}

// DefaultConfig returns the §11 defaults.
func DefaultConfig() Config {
	return Config{MaxDatagrams: 1024, MaxBytes: 8 << 20, Timeout: 5 * time.Second, DedupSize: 8192}
}

var (
	ErrConflict  = errors.New("reassembly: conflicting fragments")
	ErrDuplicate = errors.New("reassembly: datagram already delivered")
	ErrInvalid   = errors.New("reassembly: reassembled packet is not valid IP")
)

type span struct{ lo, hi int } // [lo, hi)

type datagram struct {
	id      uint64
	buf     []byte
	spans   []span // sorted, disjoint, non-adjacent
	created time.Time
	elem    *list.Element
}

// IP reassembles datagrams for one session direction. It is not safe for
// concurrent use.
type IP struct {
	cfg     Config
	partial map[uint64]*datagram
	order   *list.List // incomplete datagrams, oldest first
	bytes   int

	done     map[uint64]struct{}
	doneRing []uint64
	doneNext int
}

func New(cfg Config) *IP {
	return &IP{
		cfg:      cfg,
		partial:  make(map[uint64]*datagram),
		order:    list.New(),
		done:     make(map[uint64]struct{}, cfg.DedupSize),
		doneRing: make([]uint64, 0, cfg.DedupSize),
	}
}

// Add records a fragment. When it completes a datagram, Add returns the
// whole packet in a newly allocated slice. A nil packet with a nil error
// means more fragments are needed.
func (r *IP) Add(now time.Time, f wire.IPFragment) ([]byte, error) {
	r.Expire(now)
	if _, ok := r.done[f.DatagramID]; ok {
		return nil, ErrDuplicate
	}
	total := int(f.TotalLen)
	d := r.partial[f.DatagramID]
	if d == nil {
		if total > r.cfg.MaxBytes {
			return nil, nil
		}
		for r.order.Len() > 0 && (len(r.partial) >= r.cfg.MaxDatagrams || r.bytes+total > r.cfg.MaxBytes) {
			r.drop(r.order.Front().Value.(*datagram))
		}
		d = &datagram{id: f.DatagramID, buf: make([]byte, total), created: now}
		d.elem = r.order.PushBack(d)
		r.partial[d.id] = d
		r.bytes += total
	} else if len(d.buf) != total {
		r.drop(d)
		return nil, ErrConflict
	}

	lo, hi := int(f.Offset), int(f.Offset)+len(f.Data)
	if !d.insert(lo, hi, f.Data) {
		r.drop(d)
		return nil, ErrConflict
	}
	if len(d.spans) != 1 || d.spans[0] != (span{0, total}) {
		return nil, nil
	}
	r.drop(d)
	r.remember(d.id)
	if wire.ValidateIPPacket(d.buf) != nil {
		return nil, ErrInvalid
	}
	return d.buf, nil
}

// insert copies data into [lo, hi) and merges the span. Bytes that were
// already received must match exactly.
func (d *datagram) insert(lo, hi int, data []byte) bool {
	for _, s := range d.spans {
		a, b := max(lo, s.lo), min(hi, s.hi)
		if a < b && !bytes.Equal(d.buf[a:b], data[a-lo:b-lo]) {
			return false
		}
	}
	copy(d.buf[lo:hi], data)

	merged := span{lo, hi}
	out := d.spans[:0:0]
	for _, s := range d.spans {
		if s.hi < merged.lo || s.lo > merged.hi {
			out = append(out, s)
			continue
		}
		merged = span{min(s.lo, merged.lo), max(s.hi, merged.hi)}
	}
	i := 0
	for i < len(out) && out[i].lo < merged.lo {
		i++
	}
	out = append(out, span{})
	copy(out[i+1:], out[i:])
	out[i] = merged
	d.spans = out
	return true
}

func (r *IP) drop(d *datagram) {
	r.order.Remove(d.elem)
	delete(r.partial, d.id)
	r.bytes -= len(d.buf)
}

func (r *IP) remember(id uint64) {
	if r.cfg.DedupSize == 0 {
		return
	}
	if len(r.doneRing) < r.cfg.DedupSize {
		r.doneRing = append(r.doneRing, id)
	} else {
		delete(r.done, r.doneRing[r.doneNext])
		r.doneRing[r.doneNext] = id
		r.doneNext = (r.doneNext + 1) % r.cfg.DedupSize
	}
	r.done[id] = struct{}{}
}

// Expire discards incomplete datagrams older than the timeout.
func (r *IP) Expire(now time.Time) {
	for e := r.order.Front(); e != nil; e = r.order.Front() {
		d := e.Value.(*datagram)
		if now.Sub(d.created) < r.cfg.Timeout {
			return
		}
		r.drop(d)
	}
}

// Pending returns the number of incomplete datagrams and their reserved bytes.
func (r *IP) Pending() (datagrams, bytes int) { return len(r.partial), r.bytes }

// Fragment splits pkt into IP_FRAGMENT frames whose data is at most
// maxData bytes each.
func Fragment(dst []wire.IPFragment, id uint64, pkt []byte, maxData int) []wire.IPFragment {
	for off := 0; off < len(pkt); off += maxData {
		end := min(off+maxData, len(pkt))
		dst = append(dst, wire.IPFragment{
			DatagramID: id, TotalLen: uint16(len(pkt)), Offset: uint16(off), Data: pkt[off:end],
		})
	}
	return dst
}
