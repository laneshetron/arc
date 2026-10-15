// Package fec is forward error correction for IP packets (spec §11.2):
// systematic Reed-Solomon over blocks of consecutive datagram IDs. Source
// packets travel unchanged and are delivered as they arrive; repair
// symbols, sent after each block, let the receiver rebuild up to m lost
// packets of a block of k. Nothing waits for repairs unless a packet is
// missing, so FEC adds no delay on a clean path.
//
// Encoder and Decoder are sans-IO and not safe for concurrent use.
package fec

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/klauspost/reedsolomon"
)

// Limits on block geometry: a block's k sources and m repairs together
// stay within one byte's index space, and within what the codec handles
// quickly.
const (
	MaxK            = 64
	MaxM            = 32
	maxCachedCodecs = 32
)

// Repair is one repair symbol: index Index of M for the block of K
// sources with datagram IDs First, First+Stride, First+2*Stride, and so on.
// Data is as long as the block's longest source.
type Repair struct {
	First  uint64
	Stride int
	K, M   int
	Index  int
	Data   []byte
}

// MaxDepth caps interleaving.
const MaxDepth = 16

// codecs caches Reed-Solomon codecs by (k, m).
type codecs map[[2]int]reedsolomon.Encoder

func (c codecs) get(k, m int) (reedsolomon.Encoder, error) {
	key := [2]int{k, m}
	if enc, ok := c[key]; ok {
		return enc, nil
	}
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, err
	}
	if len(c) >= maxCachedCodecs {
		clear(c)
	}
	c[key] = enc
	return enc, nil
}

// Encoder groups outgoing packets into blocks and produces their repairs.
// With Depth d above 1 it interleaves: consecutive packets go round-robin
// to d blocks that close together, and their repairs are sent interleaved
// as well, so a burst of losses costs each block about 1/d of it.
type Encoder struct {
	// MaxK caps sources per block, and Window how long a group of blocks
	// stays open after its first source, which bounds how late a rebuilt
	// packet can be. Repairs gives the repair count for a block of k
	// sources; zero sends none. Depth is the interleaving depth (default 1).
	MaxK    int
	Window  time.Duration
	Repairs func(k int) int
	Depth   int

	first   uint64
	start   time.Time
	sources [][]byte // copies, in ID order from first
	codecs  codecs
	shards  [][]byte
}

// Add records an outgoing packet with datagram ID id. It returns the
// repairs of any block it closes: the open one, if id does not continue it
// or this source fills it.
func (e *Encoder) Add(now time.Time, id uint64, pkt []byte) []Repair {
	var out []Repair
	if len(e.sources) > 0 && id != e.first+uint64(len(e.sources)) {
		out = e.close()
	}
	if len(e.sources) == 0 {
		e.first, e.start = id, now
	}
	e.sources = append(e.sources, append([]byte(nil), pkt...))
	if len(e.sources) >= min(max(e.MaxK, 1), MaxK)*e.depth() {
		out = append(out, e.close()...)
	}
	return out
}

func (e *Encoder) depth() int { return min(max(e.Depth, 1), MaxDepth) }

// Deadline is when the open block must close, or zero if none is open.
func (e *Encoder) Deadline() time.Time {
	if len(e.sources) == 0 {
		return time.Time{}
	}
	return e.start.Add(e.Window)
}

// Flush closes the open block if its window has passed, returning its
// repairs.
func (e *Encoder) Flush(now time.Time) []Repair {
	if len(e.sources) == 0 || now.Before(e.Deadline()) {
		return nil
	}
	return e.close()
}

// close ends the open group, returning its blocks' repairs interleaved:
// each block's first repair, then each block's second, and so on.
func (e *Encoder) close() []Repair {
	defer func() { e.sources = e.sources[:0] }()
	d := min(e.depth(), len(e.sources))
	blocks := make([][]Repair, d)
	most := 0
	for j := range d {
		blocks[j] = e.encode(j, d)
		most = max(most, len(blocks[j]))
	}
	var out []Repair
	for i := range most {
		for j := range d {
			if i < len(blocks[j]) {
				out = append(out, blocks[j][i])
			}
		}
	}
	return out
}

// encode returns the repairs of block j of an interleaved group of depth d:
// the sources at positions j, j+d, j+2d, and so on.
func (e *Encoder) encode(j, d int) []Repair {
	e.shards = e.shards[:0]
	size := 0
	for i := j; i < len(e.sources); i += d {
		size = max(size, len(e.sources[i]))
	}
	for i := j; i < len(e.sources); i += d {
		e.shards = append(e.shards, pad(e.sources[i], size))
	}
	k := len(e.shards)
	m := 0
	if e.Repairs != nil {
		m = min(e.Repairs(k), MaxM)
	}
	if m <= 0 {
		return nil
	}
	if e.codecs == nil {
		e.codecs = codecs{}
	}
	enc, err := e.codecs.get(k, m)
	if err != nil {
		return nil
	}
	repairs := make([]Repair, m)
	for i := range repairs {
		repairs[i] = Repair{First: e.first + uint64(j), Stride: d, K: k, M: m, Index: i, Data: make([]byte, size)}
		e.shards = append(e.shards, repairs[i].Data)
	}
	if err := enc.Encode(e.shards); err != nil {
		return nil
	}
	return repairs
}

// pad extends s with zeros to size, in place when capacity allows.
func pad(s []byte, size int) []byte {
	for len(s) < size {
		s = append(s, 0)
	}
	return s
}

// DecoderConfig bounds a Decoder's memory.
type DecoderConfig struct {
	// StoreBytes and StoreAge bound the copies of received sources kept
	// for rebuilding (defaults 1 MiB and 2 s).
	StoreBytes int
	StoreAge   time.Duration
	// BlockAge is how long a block's repairs wait for enough symbols
	// (default 2 s).
	BlockAge time.Duration
	// RepairBytes bounds copied repair payloads independently of sources
	// (default 1 MiB). MaxBlocks and MaxDone cap metadata and per-input
	// expiry work (defaults 256 and 1024).
	RepairBytes int
	MaxBlocks   int
	MaxDone     int
}

// Decoder rebuilds lost packets from received sources and repairs.
type Decoder struct {
	cfg         DecoderConfig
	store       map[uint64]stored
	order       []uint64 // store keys, oldest first
	bytes       int
	repairBytes int
	blocks      map[uint64]*block
	done        map[uint64]time.Time // blocks finished, for ignoring late repairs
	codecs      codecs
}

type stored struct {
	pkt []byte
	at  time.Time
}

type block struct {
	k, m, size int
	stride     uint64
	repairs    map[int][]byte
	created    time.Time
	bytes      int
}

// NewDecoder returns a Decoder.
func NewDecoder(cfg DecoderConfig) *Decoder {
	if cfg.StoreBytes == 0 {
		cfg.StoreBytes = 1 << 20
	}
	if cfg.StoreAge == 0 {
		cfg.StoreAge = 2 * time.Second
	}
	if cfg.BlockAge == 0 {
		cfg.BlockAge = 2 * time.Second
	}
	if cfg.RepairBytes <= 0 {
		cfg.RepairBytes = 1 << 20
	}
	if cfg.MaxBlocks <= 0 {
		cfg.MaxBlocks = 256
	}
	if cfg.MaxDone <= 0 {
		cfg.MaxDone = 1024
	}
	return &Decoder{cfg: cfg, store: map[uint64]stored{}, blocks: map[uint64]*block{},
		done: map[uint64]time.Time{}, codecs: codecs{}}
}

// Recovered is a packet rebuilt from repairs.
type Recovered struct {
	ID  uint64
	Pkt []byte
}

// Source records a received packet with datagram ID id, which a pending
// block may need. It returns any packets that this source lets the decoder
// rebuild.
func (d *Decoder) Source(now time.Time, id uint64, pkt []byte) []Recovered {
	d.expire(now)
	if _, ok := d.store[id]; !ok {
		d.store[id] = stored{append([]byte(nil), pkt...), now}
		d.order = append(d.order, id)
		d.bytes += len(pkt)
		for d.bytes > d.cfg.StoreBytes && len(d.order) > 0 {
			d.evict()
		}
	}
	var out []Recovered
	for first, b := range d.blocks {
		if id >= first && (id-first)%b.stride == 0 && (id-first)/b.stride < uint64(b.k) {
			out = append(out, d.try(now, first, b)...)
		}
	}
	return out
}

// Repair records a repair symbol and returns any packets it lets the
// decoder rebuild.
func (d *Decoder) Repair(now time.Time, r Repair) []Recovered {
	d.expire(now)
	if r.K < 1 || r.K > MaxK || r.M < 1 || r.M > MaxM || r.Index < 0 || r.Index >= r.M || len(r.Data) == 0 ||
		r.Stride < 1 || r.Stride > MaxDepth {
		return nil
	}
	if _, ok := d.done[r.First]; ok {
		return nil
	}
	// Check before either metadata or payload allocation. A timeout alone
	// bounds lifetime, not memory at an adversarial arrival rate.
	if len(r.Data) > d.cfg.RepairBytes-d.repairBytes {
		return nil
	}
	b := d.blocks[r.First]
	if b == nil {
		if len(d.blocks) >= d.cfg.MaxBlocks {
			return nil
		}
		b = &block{k: r.K, m: r.M, size: len(r.Data), stride: uint64(r.Stride), repairs: map[int][]byte{}, created: now}
		d.blocks[r.First] = b
	} else if b.k != r.K || b.m != r.M || b.size != len(r.Data) || b.stride != uint64(r.Stride) {
		return nil // inconsistent with the block's other repairs
	}
	if _, ok := b.repairs[r.Index]; !ok {
		b.repairs[r.Index] = append([]byte(nil), r.Data...)
		b.bytes += len(r.Data)
		d.repairBytes += len(r.Data)
	}
	return d.try(now, r.First, b)
}

// try rebuilds a block's missing sources if enough symbols are present.
func (d *Decoder) try(now time.Time, first uint64, b *block) []Recovered {
	id := func(i int) uint64 { return first + uint64(i)*b.stride }
	var missing []int
	for i := range b.k {
		if _, ok := d.store[id(i)]; !ok {
			missing = append(missing, i)
		}
	}
	if len(missing) == 0 {
		d.finish(now, first)
		return nil
	}
	if len(missing) > len(b.repairs) {
		return nil
	}
	enc, err := d.codecs.get(b.k, b.m)
	if err != nil {
		d.finish(now, first)
		return nil
	}
	shards := make([][]byte, b.k+b.m)
	for i := range b.k {
		if s, ok := d.store[id(i)]; ok {
			if len(s.pkt) > b.size {
				d.finish(now, first) // not the block the repairs describe
				return nil
			}
			shards[i] = pad(append(make([]byte, 0, b.size), s.pkt...), b.size)
		}
	}
	for i, r := range b.repairs {
		shards[b.k+i] = r
	}
	if err := enc.ReconstructData(shards); err != nil {
		d.finish(now, first)
		return nil
	}
	var out []Recovered
	for _, i := range missing {
		if pkt, err := ipPacket(shards[i]); err == nil {
			out = append(out, Recovered{ID: id(i), Pkt: pkt})
		}
	}
	d.finish(now, first)
	return out
}

func (d *Decoder) finish(now time.Time, first uint64) {
	d.dropBlock(first)
	if len(d.done) < d.cfg.MaxDone {
		d.done[first] = now
	}
}

func (d *Decoder) dropBlock(first uint64) {
	if b := d.blocks[first]; b != nil {
		d.repairBytes -= b.bytes
		delete(d.blocks, first)
	}
}

func (d *Decoder) evict() {
	id := d.order[0]
	d.order = d.order[1:]
	if s, ok := d.store[id]; ok {
		d.bytes -= len(s.pkt)
		delete(d.store, id)
	}
}

// expire drops old sources, blocks, and finished-block records.
func (d *Decoder) expire(now time.Time) {
	for len(d.order) > 0 {
		s, ok := d.store[d.order[0]]
		if ok && now.Sub(s.at) < d.cfg.StoreAge {
			break
		}
		d.evict()
	}
	for first, b := range d.blocks {
		if now.Sub(b.created) >= d.cfg.BlockAge {
			d.dropBlock(first)
		}
	}
	for first, at := range d.done {
		if now.Sub(at) >= d.cfg.BlockAge {
			delete(d.done, first)
		}
	}
}

var errLength = errors.New("fec: rebuilt packet has an invalid length")

// ipPacket trims a rebuilt, zero-padded shard to the IP packet it holds,
// using the packet's own length field.
func ipPacket(shard []byte) ([]byte, error) {
	if len(shard) < 20 {
		return nil, errLength
	}
	var n int
	switch shard[0] >> 4 {
	case 4:
		n = int(binary.BigEndian.Uint16(shard[2:4]))
	case 6:
		if len(shard) < 40 {
			return nil, errLength
		}
		n = int(binary.BigEndian.Uint16(shard[4:6])) + 40
	default:
		return nil, errLength
	}
	if n < 20 || n > len(shard) {
		return nil, errLength
	}
	return shard[:n], nil
}
