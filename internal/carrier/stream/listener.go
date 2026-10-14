package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"
)

// ListenerOptions configures the relay side.
type ListenerOptions struct {
	// TLS holds the relay's certificate. The listener requires TLS 1.3
	// and, unless Camouflage is set, ALPN "arc/1".
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
	ln         net.Listener
	reg        *registry
	camouflage bool // browser ALPN admitted, per ListenerOptions.Camouflage
}

// streamPrefix is the first 8 bytes of synthetic addresses: a unique
// local IPv6 prefix spelling "arc/1" that no UDP client can have.
var streamPrefix = [8]byte{0xfd, 'a', 'r', 'c', '/', '1', 0, 0}

// IsStreamAddr reports whether a is a stream carrier's synthetic address.
func IsStreamAddr(a netip.AddrPort) bool {
	b := a.Addr().As16()
	return a.Addr().Is6() && [8]byte(b[:8]) == streamPrefix
}

// Listen starts accepting on addr.
func Listen(addr string, opts ListenerOptions) (*Listener, error) {
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
	l := &Listener{
		ln:         tls.NewListener(tcp, cfg),
		reg:        newRegistry(opts.MaxConns, opts.Queue, opts.Idle),
		camouflage: opts.Camouflage,
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
	ctx, cancel := context.WithTimeout(l.reg.ctx, 10*time.Second)
	err := conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	// The camouflage profile lets clients offer a browser's ALPN; the
	// label does not affect framing, and the ARC session inside
	// authenticates the client.
	p := conn.ConnectionState().NegotiatedProtocol
	if p != ALPN && !(l.camouflage && slices.Contains(browserALPN, p)) {
		conn.Close()
		return
	}
	if tcp, ok := conn.NetConn().(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}
	l.reg.serve(conn)
}

// WriteBatch queues each packet for the connection its address names.
// Packets for unknown addresses or full queues are dropped.
func (l *Listener) WriteBatch(pkts [][]byte, addrs []netip.AddrPort) error {
	return l.reg.writeBatch(pkts, addrs)
}

// ReadBatch reads received packets, blocking until at least one arrives.
func (l *Listener) ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	return l.reg.readBatch(bufs, sizes, addrs)
}

// Conns returns the number of open connections.
func (l *Listener) Conns() int { return l.reg.conns() }

// Close stops accepting and closes every connection.
func (l *Listener) Close() error {
	l.reg.close()
	return l.ln.Close()
}
