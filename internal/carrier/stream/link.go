package stream

import (
	"bufio"
	"net"
	"net/netip"
	"sync"
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
	conn net.Conn
	addr netip.AddrPort // reported as the source of its packets
	out  chan []byte
	done chan struct{}
	once sync.Once

	idle time.Duration // close after this long without a received packet; 0: never
}

func newLink(conn net.Conn, addr netip.AddrPort, queue int, idle time.Duration) *link {
	return &link{conn: conn, addr: addr, out: make(chan []byte, queue), done: make(chan struct{}), idle: idle}
}

// send queues a copy of pkt, reporting false if the queue is full or the
// link closed.
func (l *link) send(pkt []byte) bool {
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
	select {
	case l.out <- b:
		return true
	default:
		bufpool.Put(b)
		return false
	}
}

func (l *link) close() {
	l.once.Do(func() {
		close(l.done)
		l.conn.Close()
	})
}

// run starts the goroutines and returns when the connection fails or the
// link is closed. Received packets go to in.
func (l *link) run(in chan<- inbound) {
	go l.write()
	l.read(in)
	l.close()
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
			return
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
	for {
		var pkt []byte
		select {
		case pkt = <-l.out:
		case <-l.done:
			return
		}
		for {
			frame = appendFrame(frame[:0], pkt)
			bufpool.Put(pkt)
			if _, err := w.Write(frame); err != nil {
				l.close()
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
			l.close()
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
