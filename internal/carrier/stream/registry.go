package stream

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// registry is the relay-side bookkeeping for stream carriers: each
// connection serves as a synthetic address (§16.3), so the session
// treats it like a UDP client address that can reappear (revalidation as
// after NAT rebinding, §14.5). The plain TLS listener and the front both
// admit connections here; every ARC stream carrier a relay serves keeps
// its own synthetic address, whichever endpoint admitted it.
type registry struct {
	ctx      context.Context
	stop     context.CancelFunc
	in       chan inbound
	maxConns int
	queue    int
	idle     time.Duration

	mu    sync.Mutex
	links map[netip.AddrPort]*link
	next  uint64
}

// newRegistry sets registry defaults like ListenerOptions: MaxConns 4096,
// Idle 5 minutes, Queue DefaultQueue.
func newRegistry(maxConns, queue int, idle time.Duration) *registry {
	if maxConns == 0 {
		maxConns = 4096
	}
	if idle == 0 {
		idle = 5 * time.Minute
	}
	if queue == 0 {
		queue = DefaultQueue
	}
	ctx, stop := context.WithCancel(context.Background())
	return &registry{
		ctx: ctx, stop: stop, in: make(chan inbound, queue),
		maxConns: maxConns, queue: queue, idle: idle,
		links: make(map[netip.AddrPort]*link),
	}
}

// addr assigns the next synthetic stream address, under mu.
func (r *registry) addr() netip.AddrPort {
	r.next++
	var a [16]byte
	copy(a[:8], streamPrefix[:])
	binary.BigEndian.PutUint64(a[8:], r.next)
	return netip.AddrPortFrom(netip.AddrFrom16(a), 0)
}

// serve registers conn as one carrier connection, runs it until it fails
// or the registry closes, and forgets it. The caller has finished any
// transport-level handshake it required. opened, if set, learns the
// carrier's address once registered; serve returns that address
// (invalid if conn was refused), how many packets were still queued for
// it when it ended, and the transport error that ended it.
func (r *registry) serve(conn net.Conn, opened func(netip.AddrPort)) (netip.AddrPort, int, error) {
	r.mu.Lock()
	if len(r.links) >= r.maxConns || r.ctx.Err() != nil {
		r.mu.Unlock()
		conn.Close()
		return netip.AddrPort{}, 0, errRegistryFull
	}
	k := newLink(conn, r.addr(), r.queue, r.idle)
	r.links[k.addr] = k
	r.mu.Unlock()
	if opened != nil {
		opened(k.addr)
	}

	err := k.run(r.in)

	r.mu.Lock()
	delete(r.links, k.addr)
	r.mu.Unlock()
	return k.addr, k.drain(), err
}

var errRegistryFull = errors.New("stream: carrier limit reached or endpoint closed")

// writeBatch queues each packet for the connection its address names.
// Packets for unknown addresses or full queues are dropped.
func (r *registry) writeBatch(pkts [][]byte, addrs []netip.AddrPort) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range pkts {
		if k := r.links[addrs[i]]; k != nil {
			k.send(p)
		}
	}
	return nil
}

// readBatch reads received packets, blocking until at least one arrives.
func (r *registry) readBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	return readBatch(r.in, r.ctx.Done(), bufs, sizes, addrs)
}

// conns reports the number of open connections.
func (r *registry) conns() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.links)
}

// close stops the registry and closes every connection.
func (r *registry) close() {
	r.stop()
	r.mu.Lock()
	for _, k := range r.links {
		k.close()
	}
	r.mu.Unlock()
}
