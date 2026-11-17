package stream

import (
	"bufio"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laneshetron/arc/internal/bufpool"
)

// DefaultQueue is the default bound on packets waiting to be written to
// one connection. A full queue drops packets, as a congested link would,
// rather than blocking the session's event loop (§16).
const DefaultQueue = 1024

// inbound is a received packet and the address it is reported from. The
// packet comes from bufpool when it fits a pooled buffer.
type inbound struct {
	pkt  []byte
	from netip.AddrPort
}

// link runs one connection: a reader goroutine delivering packets to in,
// and a writer goroutine draining a bounded queue.
type link struct {
	conn  net.Conn
	addr  netip.AddrPort // reported as the source of its packets
	out   chan []byte
	done  chan struct{}
	once  sync.Once
	death atomic.Pointer[error] // first fatal transport error, for classification

	idle time.Duration // close after this long without a received packet; 0: never

	// stall, when positive, closes the link with errStalled once a packet
	// the peer owes a reply has gone this long with no frame read since:
	// an exchange in flight, no progress (a censor's silent freeze,
	// spec/freeze-and-udp-ban.md §2). Client links only.
	stall time.Duration
	// unanswered is when the oldest reply-eliciting packet queued since
	// the last frame read was queued (UnixNano), or 0 if none has been.
	// It is set before the packet is queued, so a reply that arrives
	// before the write returns clears it rather than racing it.
	unanswered atomic.Int64
	// frames counts frames read.
	frames atomic.Int64
	// unwritten counts packets the writer had taken from out but never
	// handed to TCP whole, because a write or flush failed. Set before the
	// writer stops the link, read after it exits (writerDone).
	unwritten  atomic.Int64
	writerDone chan struct{}

	// rotateAt, when positive, signals rotate once track has read this
	// many bytes. Client links only; both are set before run.
	rotateAt int64
	track    *trackingConn
	rotate   chan struct{}
}

func newLink(conn net.Conn, addr netip.AddrPort, queue int, idle time.Duration) *link {
	return &link{conn: conn, addr: addr, out: make(chan []byte, queue), done: make(chan struct{}), idle: idle,
		rotate: make(chan struct{}, 1)}
}

// errStalled ends a link that stopped receiving while it had frames in
// flight. It is a timeout, so classifyDeath reports ModeTimeoutAtNBytes.
var errStalled error = stallError{}

type stallError struct{}

func (stallError) Error() string   { return "stream: no data received while frames were in flight" }
func (stallError) Timeout() bool   { return true }
func (stallError) Temporary() bool { return false }

// watchStall closes the link with errStalled when it stalls (see stall).
func (l *link) watchStall() {
	t := time.NewTicker(l.stall / 8)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case now := <-t.C:
			if since := l.unanswered.Load(); since != 0 && now.UnixNano()-since > int64(l.stall) {
				l.stopWith(errStalled)
				return
			}
		}
	}
}

// stopWith records the link's first fatal error, if any, and closes it.
// The reader and writer goroutines race; the first error wins.
func (l *link) stopWith(err error) {
	if err != nil {
		l.death.CompareAndSwap(nil, &err)
	}
	l.close()
}

// send queues a copy of pkt, reporting false if the queue is full or the
// link closed. elicits marks a packet the peer owes a reply, which arms
// stall detection.
func (l *link) send(pkt []byte, elicits bool) bool {
	select {
	case <-l.done:
		return false
	default:
	}
	var b []byte
	if len(pkt) <= bufpool.Packet {
		b = append(bufpool.Get(), pkt...)
	} else {
		b = append([]byte(nil), pkt...)
	}
	// Arm stall detection before queueing, so a reply that arrives
	// before the writer has even returned clears it, and disarm it if
	// the queue refuses the packet: nothing was sent, so no reply is owed.
	var armed int64
	if elicits && l.stall > 0 {
		if now := time.Now().UnixNano(); l.unanswered.CompareAndSwap(0, now) {
			armed = now
		}
	}
	select {
	case l.out <- b:
		return true
	default:
		bufpool.Put(b)
		if armed != 0 {
			l.unanswered.CompareAndSwap(armed, 0)
		}
		return false
	}
}

// drain empties a closed link's queue, returning how many packets it
// never handed to TCP: those still queued, and those the writer held
// when a write or flush failed. Packets TCP accepted but never delivered
// (in its send buffer, or in flight) are not counted. Call it after run
// returns.
func (l *link) drain() int {
	n := int(l.unwritten.Load())
	for {
		select {
		case p := <-l.out:
			bufpool.Put(p)
			n++
		default:
			return n
		}
	}
}

func (l *link) close() {
	l.once.Do(func() {
		close(l.done)
		l.conn.Close()
	})
}

// run starts the goroutines and returns when the connection fails or the
// link is closed, with the first fatal transport error if there was one.
// Received packets go to in.
func (l *link) run(in chan<- inbound) error {
	l.writerDone = make(chan struct{})
	go func() {
		defer close(l.writerDone)
		l.write()
	}()
	if l.stall > 0 {
		go l.watchStall()
	}
	l.read(in)
	l.close()
	<-l.writerDone // so drain sees what a failing flush lost
	if p := l.death.Load(); p != nil {
		return *p
	}
	return nil
}

func (l *link) read(in chan<- inbound) {
	fr := newFrameReader(l.conn)
	buf := make([]byte, maxFrame)
	for {
		if l.idle > 0 {
			l.conn.SetReadDeadline(time.Now().Add(l.idle))
		}
		n, err := fr.next(buf)
		if err != nil {
			l.stopWith(err)
			return
		}
		l.frames.Add(1)
		l.unanswered.Store(0)
		if l.rotateAt > 0 && l.track.read.Load() >= l.rotateAt {
			select {
			case l.rotate <- struct{}{}:
			default:
			}
		}
		var pkt []byte
		if n <= bufpool.Packet {
			pkt = append(bufpool.Get(), buf[:n]...)
		} else {
			pkt = append([]byte(nil), buf[:n]...)
		}
		select {
		case in <- inbound{pkt, l.addr}:
		case <-l.done:
			bufpool.Put(pkt)
			return
		}
	}
}

// write sends queued packets, coalescing whatever is queued into one
// flush.
func (l *link) write() {
	w := bufio.NewWriterSize(l.conn, 64<<10)
	var frame []byte
	var ends []int // where each frame of the batch ends, in bytes appended to w
	// fail records the frames of the batch TCP did not take whole, then
	// stops the link. bufio keeps what a failed flush did not write, so
	// what reached TCP is everything given to w but its Buffered tail.
	fail := func(given int, err error) {
		written := given - w.Buffered()
		lost := 0
		for _, end := range ends {
			if end > written {
				lost++
			}
		}
		l.unwritten.Add(int64(lost))
		l.stopWith(err)
	}
	for {
		var pkt []byte
		select {
		case pkt = <-l.out:
		case <-l.done:
			return
		}
		ends = ends[:0]
		given := 0
		for {
			frame = appendFrame(frame[:0], pkt)
			bufpool.Put(pkt)
			ends = append(ends, given+len(frame))
			n, err := w.Write(frame)
			given += n
			if err != nil {
				fail(given, err)
				return
			}
			select {
			case pkt = <-l.out:
				continue
			default:
			}
			break
		}
		if err := w.Flush(); err != nil {
			fail(given, err)
			return
		}
	}
}

// readBatch fills bufs from in, blocking until at least one packet is
// available, and returns the count.
func readBatch(in <-chan inbound, done <-chan struct{}, bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	var first inbound
	select {
	case first = <-in:
	case <-done:
		return 0, net.ErrClosed
	}
	n := 0
	deliver := func(p inbound) {
		sizes[n] = copy(bufs[n], p.pkt)
		addrs[n] = p.from
		bufpool.Put(p.pkt)
		n++
	}
	deliver(first)
	for n < len(bufs) {
		select {
		case p := <-in:
			deliver(p)
		default:
			return n, nil
		}
	}
	return n, nil
}
