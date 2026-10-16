package stream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// ListenerOptions configures the relay side.
type ListenerOptions struct {
	// TLS holds the relay's certificate. The listener requires TLS 1.3
	// and ALPN "arc/1".
	TLS *tls.Config
	// Camouflage accepts carrier connections that present a browser's
	// ALPN ("h2" or "http/1.1") instead of "arc/1", as the client
	// camouflage profile does. The negotiated label does not affect
	// framing. A relay so configured should hold a certificate covering
	// the cover names its clients present.
	Camouflage bool
	// MaxConns bounds pending handshakes and established connections together (default 4096).
	MaxConns int
	// MaxPending bounds TLS work independently of established carriers (default 128).
	MaxPending int
	// MaxConnsPerSource and MaxPendingPerSource apply to the actual TCP peer
	// IP before any synthetic ARC address is assigned (defaults 64 and 4).
	MaxConnsPerSource   int
	MaxPendingPerSource int
	// HandshakeTimeout bounds a pending handshake (default 10 seconds,
	// as the client allows). TLS is the carrier for networks that block
	// UDP, which are often lossy as well: a lost ClientHello waits out
	// TCP's retransmission timeout, doubling with each loss, and a shorter
	// limit would fail the fallback exactly where it is needed. The
	// pending budgets, not this timeout, bound the work an attacker can
	// hold.
	HandshakeTimeout time.Duration
	// Idle closes a connection that receives nothing for this long
	// (default 5 minutes: well past keepalives and the session idle
	// timeout).
	Idle time.Duration
	// Queue bounds packets waiting to be written per connection;
	// DefaultQueue if zero.
	Queue int
}

// Listener accepts TLS/TCP carrier connections for a relay. Each
// connection is reported to the session as a distinct synthetic address
// (see IsStreamAddr), so the session treats it like a UDP client address:
// a client that reconnects arrives from a new address and is revalidated
// as after NAT rebinding (§14.5). It implements the engine's DatagramConn.
type Listener struct {
	ln   net.Listener
	opts ListenerOptions
	in   chan inbound
	ctx  context.Context
	stop context.CancelFunc

	mu             sync.Mutex
	links          map[netip.AddrPort]*link
	connections    map[*tls.Conn]*acceptedConn // includes pending TLS work
	pending        int
	sources        map[netip.Addr]int
	pendingSources map[netip.Addr]int
	next           uint64
}

type acceptedConn struct {
	source  netip.Addr
	pending bool
}

// streamPrefix is the first 8 bytes of synthetic addresses: a unique
// local IPv6 prefix spelling "arc/1" that no UDP client can have.
var streamPrefix = [8]byte{0xfd, 'a', 'r', 'c', '/', '1', 0, 0}

// IsStreamAddr reports whether a is a Listener connection's synthetic
// address.
func IsStreamAddr(a netip.AddrPort) bool {
	b := a.Addr().As16()
	return a.Addr().Is6() && [8]byte(b[:8]) == streamPrefix
}

// Listen starts accepting on addr.
func Listen(addr string, opts ListenerOptions) (*Listener, error) {
	if opts.MaxConns == 0 {
		opts.MaxConns = 4096
	}
	if opts.MaxPending == 0 {
		opts.MaxPending = 128
	}
	if opts.MaxConnsPerSource == 0 {
		opts.MaxConnsPerSource = 64
	}
	if opts.MaxPendingPerSource == 0 {
		opts.MaxPendingPerSource = 4
	}
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 10 * time.Second
	}
	if opts.MaxConns < 0 || opts.MaxPending < 0 || opts.MaxConnsPerSource < 0 || opts.MaxPendingPerSource < 0 || opts.HandshakeTimeout < 0 || opts.Queue < 0 || opts.Idle < 0 {
		return nil, errors.New("stream: connection, queue and idle limits must not be negative")
	}
	if opts.Idle == 0 {
		opts.Idle = 5 * time.Minute
	}
	if opts.Queue == 0 {
		opts.Queue = DefaultQueue
	}
	cfg := opts.TLS.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{ALPN}
	if opts.Camouflage {
		cfg.NextProtos = append(cfg.NextProtos, browserALPN...)
	}
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithCancel(context.Background())
	l := &Listener{
		ln: tls.NewListener(tcp, cfg), opts: opts, in: make(chan inbound, opts.Queue),
		ctx: ctx, stop: stop, links: make(map[netip.AddrPort]*link),
		connections: make(map[*tls.Conn]*acceptedConn), sources: make(map[netip.Addr]int), pendingSources: make(map[netip.Addr]int),
	}
	go l.accept()
	return l, nil
}

// Addr returns the listening address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

func (l *Listener) accept() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond) // e.g. out of file descriptors
			continue
		}
		tc := conn.(*tls.Conn)
		peer, err := netip.ParseAddrPort(tc.RemoteAddr().String())
		if err != nil {
			tc.Close()
			continue
		}
		source := peer.Addr().Unmap()
		l.mu.Lock()
		if len(l.connections) >= l.opts.MaxConns || l.pending >= l.opts.MaxPending ||
			l.sources[source] >= l.opts.MaxConnsPerSource || l.pendingSources[source] >= l.opts.MaxPendingPerSource || l.ctx.Err() != nil {
			l.mu.Unlock()
			tc.Close()
			continue
		}
		l.connections[tc] = &acceptedConn{source: source, pending: true}
		l.sources[source]++
		l.pendingSources[source]++
		l.pending++
		l.mu.Unlock()
		go l.serve(tc)
	}
}

func (l *Listener) serve(conn *tls.Conn) {
	defer func() {
		conn.Close()
		l.mu.Lock()
		entry := l.connections[conn]
		if entry.pending {
			l.finishPending(entry)
		}
		l.sources[entry.source]--
		if l.sources[entry.source] == 0 {
			delete(l.sources, entry.source)
		}
		delete(l.connections, conn)
		l.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(l.ctx, l.opts.HandshakeTimeout)
	err := conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	// The camouflage profile lets clients offer a browser's ALPN; the
	// label does not affect framing, and the ARC session inside
	// authenticates the client.
	switch p := conn.ConnectionState().NegotiatedProtocol; {
	case p == ALPN:
	case l.opts.Camouflage && slices.Contains(browserALPN, p):
	default:
		conn.Close()
		return
	}
	if tcp, ok := conn.NetConn().(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}
	l.mu.Lock()
	if l.ctx.Err() != nil {
		l.mu.Unlock()
		conn.Close()
		return
	}
	l.finishPending(l.connections[conn])
	l.next++
	var a [16]byte
	copy(a[:8], streamPrefix[:])
	binary.BigEndian.PutUint64(a[8:], l.next)
	addr := netip.AddrPortFrom(netip.AddrFrom16(a), 0)
	k := newLink(conn, addr, l.opts.Queue, l.opts.Idle)
	l.links[addr] = k
	l.mu.Unlock()

	k.run(l.in)

	l.mu.Lock()
	delete(l.links, addr)
	l.mu.Unlock()
}

// finishPending runs under mu. The total and per-source connection
// permits remain held until the established carrier closes.
func (l *Listener) finishPending(entry *acceptedConn) {
	entry.pending = false
	l.pending--
	l.pendingSources[entry.source]--
	if l.pendingSources[entry.source] == 0 {
		delete(l.pendingSources, entry.source)
	}
}

// WriteBatch queues each packet for the connection its address names.
// Packets for unknown addresses or full queues are dropped.
func (l *Listener) WriteBatch(pkts [][]byte, addrs []netip.AddrPort) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, p := range pkts {
		if k := l.links[addrs[i]]; k != nil {
			k.send(p)
		}
	}
	return nil
}

// ReadBatch reads received packets, blocking until at least one arrives.
func (l *Listener) ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	return readBatch(l.in, l.ctx.Done(), bufs, sizes, addrs)
}

// Conns returns the number of open connections.
func (l *Listener) Conns() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.links)
}

// Close stops accepting and closes every connection.
func (l *Listener) Close() error {
	l.stop()
	err := l.ln.Close()
	l.mu.Lock()
	for conn := range l.connections {
		conn.Close()
	}
	for _, k := range l.links {
		k.close()
	}
	l.mu.Unlock()
	return err
}
