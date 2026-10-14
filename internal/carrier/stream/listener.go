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
	// MaxConns bounds concurrent connections (default 4096).
	MaxConns int
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

	mu    sync.Mutex
	links map[netip.AddrPort]*link
	next  uint64
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
		go l.serve(conn.(*tls.Conn))
	}
}

func (l *Listener) serve(conn *tls.Conn) {
	ctx, cancel := context.WithTimeout(l.ctx, 10*time.Second)
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
	if len(l.links) >= l.opts.MaxConns || l.ctx.Err() != nil {
		l.mu.Unlock()
		conn.Close()
		return
	}
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
	for _, k := range l.links {
		k.close()
	}
	l.mu.Unlock()
	return err
}
