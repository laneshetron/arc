package session

import (
	"errors"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// Streams (spec §11.3) carry TCP connections that the client terminates
// locally: the client asks the relay to connect a stream to a destination,
// and the two ends exchange the connection's bytes reliably. Unlike IP
// packets, stream data is retransmitted: frames lost with their packets go
// out again, so the application's TCP never sees the tunnel's loss, and a
// rate controller that ignores random loss (streamcc.go) paces what goes
// on the path. Flow control bounds what each end buffers: a receiver
// advertises how far each stream, and all streams together, may send.
const (
	// streamWindow and connWindow are the receive windows, per stream and
	// for the session, and also the limits each end assumes before the
	// peer advertises any.
	streamWindow = 2 << 20
	connWindow   = 16 << 20
	// streamSendBuffer bounds the bytes a stream holds that the peer has
	// not acknowledged.
	streamSendBuffer = 2 << 20
	// maxStreams bounds streams per session, at each end.
	maxStreams = 256
)

var (
	ErrStreamsUnsupported = errors.New("session: relay does not support streams")
	// ErrDiagnosticsUnsupported: the relay does not accept diagnostics.
	ErrDiagnosticsUnsupported = errors.New("session: relay does not accept diagnostics")
	ErrTooManyStreams         = errors.New("session: too many streams")
	ErrStreamClosed           = errors.New("session: stream closed")
	ErrStreamWriteClosed      = errors.New("session: stream closed for writing")
)

// StreamResetError reports a stream reset by the peer.
type StreamResetError struct{ Code wire.ErrorCode }

func (e *StreamResetError) Error() string { return "session: stream reset by peer" }

// StreamInfo is a stream's state, from StreamInfo.
type StreamInfo struct {
	Readable int  // bytes StreamRead returns without waiting
	EOF      bool // the peer finished sending, and everything was read
	Writable int  // bytes StreamWrite accepts now
	// Done reports that both directions finished, or that the stream was
	// reset; Err is the reset, if any. The stream is then gone.
	Done bool
	Err  error
}

type byteRange struct{ lo, hi uint64 }

// rangeSet is a sorted set of disjoint, non-adjacent byte ranges.
type rangeSet []byteRange

func (s *rangeSet) add(lo, hi uint64) {
	if lo >= hi {
		return
	}
	r := *s
	i, _ := slices.BinarySearchFunc(r, lo, func(x byteRange, lo uint64) int {
		switch {
		case x.hi < lo:
			return -1
		case x.lo > lo:
			return 1
		}
		return 0
	})
	// r[i] is the first range ending at or after lo.
	j := i
	for j < len(r) && r[j].lo <= hi {
		lo, hi = min(lo, r[j].lo), max(hi, r[j].hi)
		j++
	}
	*s = slices.Replace(r, i, j, byteRange{lo, hi})
}

func (s rangeSet) contains(x uint64) bool {
	_, found := slices.BinarySearchFunc(s, x, func(r byteRange, x uint64) int {
		switch {
		case r.hi <= x:
			return -1
		case r.lo > x:
			return 1
		}
		return 0
	})
	return found
}

// remove deletes [lo, hi) from the set.
func (s *rangeSet) remove(lo, hi uint64) {
	var out rangeSet
	for _, x := range *s {
		if x.hi <= lo || x.lo >= hi {
			out = append(out, x)
			continue
		}
		if x.lo < lo {
			out = append(out, byteRange{x.lo, lo})
		}
		if x.hi > hi {
			out = append(out, byteRange{hi, x.hi})
		}
	}
	*s = out
}

// trimBelow removes everything below x.
func (s *rangeSet) trimBelow(x uint64) {
	r := *s
	i := 0
	for i < len(r) && r[i].hi <= x {
		i++
	}
	r = r[i:]
	if len(r) > 0 && r[0].lo < x {
		r[0].lo = x
	}
	*s = r
}

type sendStream struct {
	buf      []byte // bytes from base not yet acknowledged, then unsent ones
	base     uint64
	next     uint64   // first byte never sent
	acked    rangeSet // acknowledged ranges above base
	lost     rangeSet // ranges to send again
	limit    uint64   // the peer's MAX_STREAM_DATA
	fin      bool     // no more bytes: the stream ends at base+len(buf)
	finSent  bool     // FIN is in flight or acknowledged
	finAcked bool
	// Where repeating bytes in flight resumes, and whether this pass
	// repeated the FIN; see nextRepeatFrame.
	repeat      uint64
	finRepeated bool
}

func (s *sendStream) end() uint64 { return s.base + uint64(len(s.buf)) }

// done reports that every byte and the FIN were acknowledged.
func (s *sendStream) done() bool { return s.fin && s.finAcked && s.base == s.end() }

type segment struct {
	off  uint64
	data []byte
}

type recvStream struct {
	data     []byte    // contiguous bytes from read, not yet read
	read     uint64    // offset of data[0]
	segs     []segment // out of order, by offset, above read+len(data)
	high     uint64    // highest offset received, as counted for MAX_DATA
	limit    uint64    // our MAX_STREAM_DATA
	final    uint64
	finKnown bool
}

func (r *recvStream) done() bool {
	return r.finKnown && r.read == r.final
}

type stream struct {
	id   uint32
	dst  netip.AddrPort
	diag bool // a diagnostics upload (§11.4)
	send sendStream
	recv recvStream
	// resetSent marks a stream this end reset: the application is done
	// with it, and it stays only until the peer's own STREAM_RESET gives
	// the final size of what the peer sent, for connection flow control.
	resetSent bool
	err       error // reset by the peer
	queued    bool  // in streamSet.ready
	notified  bool  // a StreamUpdate is outstanding
}

// streamSet is a session's streams, shared by both roles.
type streamSet struct {
	enabled bool
	client  bool
	// What the relay advertised: STREAM_OPEN (connect) and
	// DIAGNOSTICS_OPEN (diagnostics) streams; either enables streams.
	connect, diagnostics bool
	streams              map[uint32]*stream
	list                 []*stream // the streams in creation order, for repeats
	repeatI              int       // index in list where repeats resume
	nextID               uint32    // client: the next stream ID
	seen                 rangeSet  // relay: stream IDs seen; those no longer in streams are closed
	ready                []*stream

	// Connection flow control: what this end may send in total (the
	// peer's MAX_DATA) and has used (the highest offset sent on every
	// stream, past and present), and likewise for receiving.
	sendLimit, sendUsed            uint64
	recvLimit, recvHigh, recvTaken uint64

	updates []uint32          // streams with news for the application
	opened  []wire.StreamOpen // relay: streams to connect; no Dst for a diagnostics upload
}

func (ss *streamSet) init(client bool) {
	ss.enabled, ss.client = true, client
	ss.streams = map[uint32]*stream{}
	ss.nextID = 1
	ss.sendLimit, ss.recvLimit = connWindow, connWindow
}

func (ss *streamSet) newStream(id uint32, dst netip.AddrPort) *stream {
	s := &stream{id: id, dst: dst}
	s.send.limit, s.recv.limit = streamWindow, streamWindow
	ss.streams[id] = s
	ss.list = append(ss.list, s)
	return s
}

// notify queues a StreamUpdate for s unless one is outstanding.
func (ss *streamSet) notify(s *stream) {
	if !s.notified {
		s.notified = true
		ss.updates = append(ss.updates, s.id)
	}
}

// schedule marks s as having something to send.
func (ss *streamSet) schedule(s *stream) {
	if !s.queued {
		s.queued = true
		ss.ready = append(ss.ready, s)
	}
}

// openDiagnostics starts a client stream uploading diagnostics (§11.4).
func (c *conn) openDiagnostics(now time.Time) (uint32, error) {
	ss := &c.streams
	if !ss.diagnostics {
		return 0, ErrDiagnosticsUnsupported
	}
	id, err := ss.nextStream()
	if err != nil {
		return 0, err
	}
	ss.newStream(id, netip.AddrPort{}).diag = true
	c.queue(wire.DiagOpen{ID: id})
	c.flush(now)
	return id, nil
}

// nextStream allocates a client stream ID.
func (ss *streamSet) nextStream() (uint32, error) {
	if len(ss.streams) >= maxStreams || ss.nextID == 0 { // nextID 0: all 2^32-1 IDs used
		return 0, ErrTooManyStreams
	}
	id := ss.nextID
	ss.nextID++
	return id, nil
}

// openStream starts a client stream to dst.
func (c *conn) openStream(now time.Time, dst netip.AddrPort) (uint32, error) {
	ss := &c.streams
	if !ss.connect {
		return 0, ErrStreamsUnsupported
	}
	id, err := ss.nextStream()
	if err != nil {
		return 0, err
	}
	ss.newStream(id, dst)
	c.queue(wire.StreamOpen{ID: id, Dst: dst})
	c.flush(now)
	return id, nil
}

func (c *conn) stream(id uint32) (*stream, error) {
	s := c.streams.streams[id]
	if s == nil || s.resetSent {
		return nil, ErrStreamClosed
	}
	if s.err != nil {
		return nil, s.err
	}
	return s, nil
}

// writable is how many bytes s accepts now.
func (c *conn) writable(s *stream) int {
	if s.send.fin {
		return 0
	}
	return max(streamSendBuffer-len(s.send.buf), 0)
}

func (c *conn) streamWrite(now time.Time, id uint32, p []byte) (int, error) {
	s, err := c.stream(id)
	if err != nil {
		return 0, err
	}
	if s.send.fin {
		return 0, ErrStreamWriteClosed
	}
	n := min(len(p), c.writable(s))
	if n == 0 {
		return 0, nil
	}
	s.send.buf = append(s.send.buf, p[:n]...)
	c.streams.schedule(s)
	c.flush(now)
	return n, nil
}

func (c *conn) streamRead(now time.Time, id uint32, p []byte) (int, error) {
	s, err := c.stream(id)
	if err != nil {
		return 0, err
	}
	r := &s.recv
	if len(r.data) == 0 {
		if r.done() {
			return 0, io.EOF
		}
		return 0, nil
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		r.data = nil // release the buffer
	}
	r.read += uint64(n)
	c.streams.recvTaken += uint64(n)
	c.updateWindows(s)
	c.maybeFinish(s)
	c.flush(now)
	return n, nil
}

// updateWindows advertises more stream and connection credit once half of
// the current credit has been read.
func (c *conn) updateWindows(s *stream) {
	r := &s.recv
	if !r.finKnown && r.limit-r.read < streamWindow/2 {
		r.limit = r.read + streamWindow
		c.queue(wire.MaxStreamData{ID: s.id, Max: r.limit})
	}
	ss := &c.streams
	if ss.recvLimit-ss.recvTaken < connWindow/2 {
		ss.recvLimit = ss.recvTaken + connWindow
		c.queue(wire.MaxData{Max: ss.recvLimit})
	}
}

func (c *conn) streamCloseWrite(now time.Time, id uint32) error {
	s, err := c.stream(id)
	if err != nil {
		return err
	}
	if !s.send.fin {
		s.send.fin = true
		c.streams.schedule(s)
		c.flush(now)
	}
	return nil
}

// streamReset abandons a stream in both directions.
func (c *conn) streamReset(now time.Time, id uint32, code wire.ErrorCode) {
	s := c.streams.streams[id]
	if s == nil || s.resetSent {
		return
	}
	c.resetStream(s, code)
	c.flush(now)
}

// resetStream sends STREAM_RESET with the final size of what this end
// sent. Unless the peer already reset the stream, or finished sending,
// the stream lingers until the peer's own reset arrives.
func (c *conn) resetStream(s *stream, code wire.ErrorCode) {
	c.queue(wire.StreamReset{ID: s.id, Code: code, Final: s.send.next})
	s.resetSent = true
	s.send.buf, s.send.lost, s.send.acked = nil, nil, nil
	c.dropRecvData(s)
	if s.err != nil || s.recv.finKnown {
		c.removeStream(s)
	}
}

// dropRecvData discards what the application has not read, returning its
// credit.
func (c *conn) dropRecvData(s *stream) {
	r := &s.recv
	c.streams.recvTaken += r.high - r.read
	r.read = r.high
	r.data, r.segs = nil, nil
}

func (c *conn) removeStream(s *stream) {
	ss := &c.streams
	delete(ss.streams, s.id)
	s.queued = false // drops out of ready when next visited
	if i := slices.Index(ss.list, s); i >= 0 {
		ss.list = slices.Delete(ss.list, i, i+1)
		if ss.repeatI > i {
			ss.repeatI--
		}
	}
}

// streamInfo reports a stream's state and lets the next change raise a
// StreamUpdate again. A finished stream is removed once reported.
func (c *conn) streamInfo(id uint32) StreamInfo {
	s := c.streams.streams[id]
	if s == nil || s.resetSent {
		return StreamInfo{Done: true, Err: ErrStreamClosed}
	}
	s.notified = false
	if s.err != nil {
		c.removeStream(s)
		return StreamInfo{Done: true, Err: s.err}
	}
	info := StreamInfo{Readable: len(s.recv.data), EOF: len(s.recv.data) == 0 && s.recv.done(), Writable: c.writable(s)}
	if info.EOF && s.send.done() {
		c.removeStream(s)
		info.Done = true
	}
	return info
}

// maybeFinish raises a StreamUpdate when both directions have finished,
// so the application learns the stream is done.
func (c *conn) maybeFinish(s *stream) {
	if s.recv.done() && s.send.done() {
		c.streams.notify(s)
	}
}

// onStreamOpen handles STREAM_OPEN on the relay.
func (c *conn) onStreamOpen(f wire.StreamOpen) {
	ss := &c.streams
	if !ss.connect || ss.client {
		return
	}
	s := c.relayStream(f.ID)
	if s == nil || s.dst.IsValid() || s.diag || s.resetSent || s.err != nil {
		return // closed, reset before it opened, or a retransmission
	}
	s.dst = f.Dst
	ss.opened = append(ss.opened, f)
}

// onDiagOpen handles DIAGNOSTICS_OPEN on the relay (§11.4): the stream is
// an upload, reported to the application as a StreamOpen without Dst.
func (c *conn) onDiagOpen(f wire.DiagOpen) {
	ss := &c.streams
	if !ss.diagnostics || ss.client {
		return
	}
	s := c.relayStream(f.ID)
	if s == nil || s.dst.IsValid() || s.diag || s.resetSent || s.err != nil {
		return
	}
	s.diag = true
	ss.opened = append(ss.opened, wire.StreamOpen{ID: f.ID})
}

// relayStream returns the relay's stream for a client-chosen ID, creating
// it if the ID is new: frames for a stream may arrive before its
// STREAM_OPEN. It returns nil for a closed stream, and resets a new one
// beyond maxStreams.
func (c *conn) relayStream(id uint32) *stream {
	ss := &c.streams
	if s := ss.streams[id]; s != nil {
		return s
	}
	if ss.seen.contains(uint64(id)) {
		return nil
	}
	ss.seen.add(uint64(id), uint64(id)+1)
	s := ss.newStream(id, netip.AddrPort{})
	if len(ss.streams) > maxStreams {
		c.resetStream(s, wire.CodeCapacity)
		return nil
	}
	return s
}

// peerStream returns the stream a peer's frame is about, or nil.
func (c *conn) peerStream(id uint32) *stream {
	if c.streams.client {
		return c.streams.streams[id]
	}
	return c.relayStream(id)
}

// onStream handles a STREAM frame. It reports false for a flow control or
// final size violation, which ends the session.
func (c *conn) onStream(f wire.Stream) bool {
	ss := &c.streams
	if !ss.enabled {
		return true
	}
	s := c.peerStream(f.ID)
	if s == nil {
		return true
	}
	r := &s.recv
	end := f.Offset + uint64(len(f.Data))
	if end > r.limit || (r.finKnown && end > r.final) || (f.Fin && (end < r.high || r.finKnown && end != r.final)) {
		return false
	}
	if end > r.high {
		ss.recvHigh += end - r.high
		r.high = end
		if ss.recvHigh > ss.recvLimit {
			return false
		}
	}
	if f.Fin && !r.finKnown {
		r.final, r.finKnown = end, true
	}
	if s.resetSent || s.err != nil {
		c.dropRecvData(s)
		return true
	}
	before := len(r.data)
	c.insert(s, f.Offset, f.Data)
	if len(r.data) > before || r.done() {
		ss.notify(s)
	}
	return true
}

// insert adds received bytes at off, delivering them in order.
func (c *conn) insert(s *stream, off uint64, data []byte) {
	r := &s.recv
	top := r.read + uint64(len(r.data))
	if end := off + uint64(len(data)); end <= top {
		return // a duplicate
	}
	if off < top {
		data = data[top-off:]
		off = top
	}
	if off == top {
		r.data = append(r.data, data...)
		top += uint64(len(data))
		// Pull in out-of-order segments that are now contiguous.
		i := 0
		for ; i < len(r.segs) && r.segs[i].off <= top; i++ {
			sg := r.segs[i]
			if end := sg.off + uint64(len(sg.data)); end > top {
				r.data = append(r.data, sg.data[top-sg.off:]...)
				top = end
			}
		}
		r.segs = r.segs[i:]
		return
	}
	// Keep only bytes no segment holds yet: repeats and retransmissions
	// cover the same bytes with different frame boundaries, and overlaps
	// would let the buffer outgrow the window.
	end := off + uint64(len(data))
	segs := make([]segment, 0, len(r.segs)+2)
	for _, sg := range r.segs {
		sgEnd := sg.off + uint64(len(sg.data))
		if off < end && off < sg.off {
			hi := min(end, sg.off)
			segs = append(segs, segment{off, append([]byte(nil), data[:hi-off]...)})
			data, off = data[hi-off:], hi
		}
		if off < end && off < sgEnd {
			skip := min(end, sgEnd) - off
			data, off = data[skip:], off+skip
		}
		segs = append(segs, sg)
	}
	if off < end {
		segs = append(segs, segment{off, append([]byte(nil), data...)})
	}
	r.segs = segs
}

func (c *conn) onMaxStreamData(f wire.MaxStreamData) {
	if !c.streams.enabled {
		return
	}
	if s := c.peerStream(f.ID); s != nil && f.Max > s.send.limit {
		s.send.limit = f.Max
		c.streams.schedule(s)
	}
}

func (c *conn) onMaxData(f wire.MaxData) {
	ss := &c.streams
	if ss.enabled && f.Max > ss.sendLimit {
		ss.sendLimit = f.Max
		for _, s := range ss.streams {
			if s.send.next < s.send.end() {
				ss.schedule(s)
			}
		}
	}
}

// onStreamReset handles the peer's STREAM_RESET. It reports false for a
// final size violation.
func (c *conn) onStreamReset(f wire.StreamReset) bool {
	ss := &c.streams
	if !ss.enabled {
		return true
	}
	s := c.peerStream(f.ID)
	if s == nil {
		return true
	}
	r := &s.recv
	if f.Final < r.high || r.finKnown && f.Final != r.final || f.Final > r.limit {
		return false
	}
	ss.recvHigh += f.Final - r.high
	r.high, r.final, r.finKnown = f.Final, f.Final, true
	if ss.recvHigh > ss.recvLimit {
		return false
	}
	c.dropRecvData(s)
	if s.resetSent {
		c.removeStream(s) // the reset this end sent is answered
		return true
	}
	if s.err != nil {
		return true
	}
	// Answer with this end's final size, and report the reset.
	c.queue(wire.StreamReset{ID: s.id, Code: f.Code, Final: s.send.next})
	s.send.buf, s.send.lost, s.send.acked = nil, nil, nil
	s.err = &StreamResetError{Code: f.Code}
	ss.notify(s)
	return true
}

// onStreamAcked records that a STREAM frame's bytes arrived.
func (c *conn) onStreamAcked(f wire.Stream) {
	s := c.streams.streams[f.ID]
	if s == nil || s.resetSent || s.err != nil {
		return
	}
	ts := &s.send
	end := f.Offset + uint64(len(f.Data))
	if f.Fin {
		ts.finAcked = true
	}
	if end <= ts.base {
		c.maybeFinish(s)
		return
	}
	ts.acked.add(max(f.Offset, ts.base), end)
	ts.lost.remove(f.Offset, end)
	if len(ts.acked) > 0 && ts.acked[0].lo == ts.base {
		freed := ts.acked[0].hi - ts.base
		ts.buf = ts.buf[freed:]
		if len(ts.buf) == 0 {
			ts.buf = nil
		}
		ts.base = ts.acked[0].hi
		ts.acked = ts.acked[1:]
		c.streams.notify(s)
	}
	c.maybeFinish(s)
}

// onStreamLost queues a lost STREAM frame's bytes, and its FIN, to be sent
// again.
func (c *conn) onStreamLost(f wire.Stream) {
	s := c.streams.streams[f.ID]
	if s == nil || s.resetSent || s.err != nil {
		return
	}
	ts := &s.send
	end := f.Offset + uint64(len(f.Data))
	if f.Fin && !ts.finAcked {
		ts.finSent = false
	}
	if lo := max(f.Offset, ts.base); lo < end {
		ts.lost.add(lo, end)
		for _, a := range ts.acked {
			ts.lost.remove(a.lo, a.hi)
		}
	}
	c.streams.schedule(s)
}

// nextStreamFrame returns the next STREAM frame to send within budget
// bytes (including its frame header), rotating among streams. It returns
// false when no stream has anything it may send now.
func (c *conn) nextStreamFrame(budget int) (wire.Stream, bool) {
	ss := &c.streams
	maxData := budget - wire.FrameHeaderLen - 13
	if maxData < 0 {
		return wire.Stream{}, false
	}
	for len(ss.ready) > 0 {
		s := ss.ready[0]
		ss.ready = ss.ready[1:]
		if !s.queued || ss.streams[s.id] != s {
			continue // removed
		}
		f, ok := c.streamFrame(s, maxData)
		if ok && c.streamPending(s) {
			ss.ready = append(ss.ready, s) // round robin
		} else {
			// Done for now, or blocked by flow control: credit arriving
			// schedules it again.
			s.queued = false
		}
		if ok {
			return f, true
		}
	}
	return wire.Stream{}, false
}

// streamFrame builds s's next frame of at most maxData bytes: lost bytes
// first, then new ones as flow control allows.
func (c *conn) streamFrame(s *stream, maxData int) (wire.Stream, bool) {
	if s.resetSent || s.err != nil {
		return wire.Stream{}, false
	}
	ts := &s.send
	ts.lost.trimBelow(ts.base)
	if len(ts.lost) > 0 {
		r := ts.lost[0]
		hi := min(r.hi, r.lo+uint64(maxData))
		f := wire.Stream{ID: s.id, Offset: r.lo, Data: ts.buf[r.lo-ts.base : hi-ts.base]}
		ts.lost.remove(r.lo, hi)
		c.stats.StreamBytesRetransmitted += hi - r.lo
		if ts.fin && hi == ts.end() && !ts.finSent {
			f.Fin, ts.finSent = true, true
		}
		return f, true
	}
	ss := &c.streams
	credit := min(ts.limit, ts.next+(ss.sendLimit-ss.sendUsed))
	hi := min(ts.end(), ts.next+uint64(maxData), credit)
	if hi == ts.next && !(ts.fin && !ts.finSent && ts.next == ts.end()) {
		if ts.end() > ts.next {
			c.streamsBlocked = true // data waiting for flow-control credit
		}
		return wire.Stream{}, false
	}
	f := wire.Stream{ID: s.id, Offset: ts.next, Data: ts.buf[ts.next-ts.base : hi-ts.base]}
	ss.sendUsed += hi - ts.next
	ts.next = hi
	if ts.fin && hi == ts.end() {
		f.Fin, ts.finSent = true, true
	}
	return f, true
}

// nextRepeatFrame returns a STREAM frame repeating bytes in flight, those
// sent but neither acknowledged nor declared lost, within budget bytes,
// rotating among streams and through each stream's bytes in flight. On a
// path that loses most packets, a lost range is otherwise sent again only
// once an acknowledgement shows the loss, and most acknowledgements are
// lost too, which leaves the path mostly idle; repeats spend that idle
// capacity so more ranges get through each round trip. It returns false
// when nothing is in flight.
func (c *conn) nextRepeatFrame(budget int) (wire.Stream, bool) {
	ss := &c.streams
	maxData := budget - wire.FrameHeaderLen - 13
	if maxData < 0 {
		return wire.Stream{}, false
	}
	for range len(ss.list) {
		if ss.repeatI >= len(ss.list) {
			ss.repeatI = 0
		}
		s := ss.list[ss.repeatI]
		if f, ok := c.repeatFrame(s, maxData); ok {
			return f, true
		}
		ss.repeatI++
	}
	return wire.Stream{}, false
}

// repeatFrame returns s's next repeat, or false once it has gone through
// all of s's bytes in flight (and an unacknowledged FIN) since it last
// returned false.
func (c *conn) repeatFrame(s *stream, maxData int) (wire.Stream, bool) {
	ts := &s.send
	if s.resetSent || s.err != nil {
		return wire.Stream{}, false
	}
	lo := max(ts.repeat, ts.base)
	for _, a := range ts.acked {
		if lo >= a.lo && lo < a.hi {
			lo = a.hi
		}
	}
	finUnacked := ts.finSent && !ts.finAcked && ts.next == ts.end()
	if lo < ts.next {
		hi := min(ts.next, lo+uint64(maxData))
		for _, a := range ts.acked {
			if a.lo > lo {
				hi = min(hi, a.lo)
				break
			}
		}
		ts.repeat = hi
		c.stats.StreamBytesRepeated += hi - lo
		f := wire.Stream{ID: s.id, Offset: lo, Data: ts.buf[lo-ts.base : hi-ts.base]}
		if finUnacked && hi == ts.end() {
			f.Fin, ts.finRepeated = true, true
		}
		return f, true
	}
	if finUnacked && !ts.finRepeated {
		ts.finRepeated = true
		return wire.Stream{ID: s.id, Offset: ts.next, Fin: true}, true
	}
	ts.repeat, ts.finRepeated = ts.base, false // start over next time
	return wire.Stream{}, false
}

// streamPending reports whether s has bytes or a FIN to send.
func (c *conn) streamPending(s *stream) bool {
	ts := &s.send
	return len(ts.lost) > 0 || ts.next < ts.end() || (ts.fin && !ts.finSent)
}

// streamsWaiting reports whether any stream has something it may send now.
func (c *conn) streamsWaiting() bool {
	for _, s := range c.streams.ready {
		if s.queued && c.streams.streams[s.id] == s {
			return true
		}
	}
	return false
}
