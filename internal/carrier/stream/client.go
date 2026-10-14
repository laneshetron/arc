package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
)

// ClientOptions configures a client carrier.
type ClientOptions struct {
	// Addr is the relay's TLS endpoint, host:port.
	Addr string
	// TLS verifies the relay's certificate (ServerName, RootCAs). The
	// carrier requires TLS 1.3 and ALPN "arc/1", unless Camouflage is
	// set: then the outer handshake is cover and the ARC session
	// underneath provides security.
	TLS *tls.Config
	// Camouflage, when set, presents the outer TLS as ordinary browser
	// traffic (cover server name, optional browser fingerprint, optional
	// ClientHello segmentation) instead of verifying the relay and
	// negotiating ALPN "arc/1".
	Camouflage *Camouflage
	// Socket options for the TCP connection.
	Sockopt sockopt.Options
	// Peer is reported as the source of received packets, so the engine
	// can treat the carrier like its UDP ones.
	Peer netip.AddrPort
	// Queue bounds packets waiting to be written; DefaultQueue if zero.
	Queue int
	// MaxBackoff caps the delay between reconnection attempts (default
	// 30 s; attempts start 500 ms apart and double).
	MaxBackoff time.Duration
	// OnState, if set, is called when the connection comes up (err nil)
	// or a dial attempt or connection fails.
	OnState func(err error)
}

// Client is a TLS/TCP carrier to one relay. It connects in the background
// and reconnects after failures; while disconnected, writes are dropped,
// which the session sees as loss. It implements the engine's DatagramConn.
type Client struct {
	opts ClientOptions
	in   chan inbound
	ctx  context.Context
	stop context.CancelFunc

	mu  sync.Mutex
	cur *link
}

// Dial starts a client carrier. It returns at once; the connection comes
// up in the background.
func Dial(opts ClientOptions) *Client {
	if opts.Queue == 0 {
		opts.Queue = DefaultQueue
	}
	if opts.MaxBackoff == 0 {
		opts.MaxBackoff = 30 * time.Second
	}
	ctx, stop := context.WithCancel(context.Background())
	c := &Client{opts: opts, in: make(chan inbound, opts.Queue), ctx: ctx, stop: stop}
	go c.connectLoop()
	return c
}

func (c *Client) connectLoop() {
	backoff := 500 * time.Millisecond
	for c.ctx.Err() == nil {
		l, err := c.connect()
		if err == nil {
			c.setLink(l) // before OnState, so a write it prompts is not dropped
		}
		if c.opts.OnState != nil {
			c.opts.OnState(err)
		}
		if err == nil {
			start := time.Now()
			go func() { // Close may have missed a link that was still dialing
				select {
				case <-c.ctx.Done():
					l.close()
				case <-l.done:
				}
			}()
			l.run(c.in)
			c.setLink(nil)
			if c.ctx.Err() != nil {
				return
			}
			if c.opts.OnState != nil {
				c.opts.OnState(errors.New("stream: connection closed"))
			}
			if time.Since(start) > 10*time.Second {
				backoff = 500 * time.Millisecond // it worked for a while
			}
		}
		select {
		case <-time.After(backoff):
		case <-c.ctx.Done():
			return
		}
		backoff = min(2*backoff, c.opts.MaxBackoff)
	}
}

func (c *Client) connect() (*link, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	conn, _, alpn, err := c.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	// The camouflage profile offers a browser's ALPN, so the negotiated
	// label is not the carrier's; the ARC session authenticates the peer.
	if c.opts.Camouflage == nil && alpn != ALPN {
		conn.Close()
		return nil, errors.New("stream: relay did not negotiate ALPN " + ALPN)
	}
	return newLink(conn, c.opts.Peer, c.opts.Queue, 0), nil
}

// dialTLS connects to the relay endpoint and runs the TLS handshake,
// returning the TLS connection, its underlying transport, and the
// negotiated protocol. SetNoDelay runs before the handshake: the
// camouflage profile needs its ClientHello fragments to leave as TCP
// segments at once.
func (c *Client) dialTLS(ctx context.Context) (_ net.Conn, raw net.Conn, alpn string, err error) {
	raw, err = (&net.Dialer{
		Control:   sockopt.Control(c.opts.Sockopt),
		KeepAlive: 15 * time.Second,
	}).DialContext(ctx, "tcp", c.opts.Addr)
	if err != nil {
		return nil, nil, "", err
	}
	defer func() {
		if err != nil && raw != nil {
			raw.Close()
		}
	}()
	if tcp, ok := raw.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}
	if cam := c.opts.Camouflage; cam != nil {
		return cam.dial(ctx, raw, c.opts.Addr, c.opts.TLS)
	}
	config := c.opts.TLS
	if config == nil {
		config = &tls.Config{}
	}
	cfg := config.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{ALPN}
	conn := tls.Client(raw, cfg)
	if err = conn.HandshakeContext(ctx); err != nil {
		return nil, nil, "", err
	}
	return conn, raw, conn.ConnectionState().NegotiatedProtocol, nil
}

func (c *Client) setLink(l *link) {
	c.mu.Lock()
	c.cur = l
	c.mu.Unlock()
}

// Connected reports whether the carrier has a connection now.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur != nil
}

// WriteBatch queues packets for the relay; addrs are ignored. Packets are
// dropped while disconnected or when the queue is full.
func (c *Client) WriteBatch(pkts [][]byte, _ []netip.AddrPort) error {
	c.mu.Lock()
	l := c.cur
	c.mu.Unlock()
	if l == nil {
		return nil
	}
	for _, p := range pkts {
		l.send(p)
	}
	return nil
}

// ReadBatch reads received packets, blocking until at least one arrives.
func (c *Client) ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	return readBatch(c.in, c.ctx.Done(), bufs, sizes, addrs)
}

// Close stops the carrier.
func (c *Client) Close() error {
	c.stop()
	c.mu.Lock()
	if c.cur != nil {
		c.cur.close()
	}
	c.mu.Unlock()
	return nil
}
