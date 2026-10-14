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
	// carrier requires TLS 1.3 and ALPN "arc/1".
	TLS *tls.Config
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
	cfg := c.opts.TLS.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{ALPN}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Control: sockopt.Control(c.opts.Sockopt), KeepAlive: 15 * time.Second},
		Config:    cfg,
	}
	conn, err := d.DialContext(ctx, "tcp", c.opts.Addr)
	if err != nil {
		return nil, err
	}
	if p := conn.(*tls.Conn).ConnectionState().NegotiatedProtocol; p != ALPN {
		conn.Close()
		return nil, errors.New("stream: relay did not negotiate ALPN " + ALPN)
	}
	conn.(*tls.Conn).NetConn().(*net.TCPConn).SetNoDelay(true)
	return newLink(conn, c.opts.Peer, c.opts.Queue, 0), nil
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
