package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
)

// FrontDialOptions configures a client carrier over the relay's front:
// the TLS session is ordinary HTTPS, and the carrier rides an
// authenticated HTTP upgrade inside it. The session itself still
// authenticates the relay (spec D2); the front's admission token only
// gates the upgrade.
type FrontDialOptions struct {
	// Token is the admission token, one of the deployment's client
	// access tokens. A wrong or missing token gets cover content, and
	// the dial reports ModeFrontRefused.
	Token string
	// Path is requested in the upgrade; default "/".
	Path string
}

// ClientOptions configures a client carrier.
type ClientOptions struct {
	// Addr is the relay's TLS endpoint, host:port.
	Addr string
	// Endpoints, when set, are bootstrap-resolved dial targets. The TLS
	// ServerName still refers to the original hostname. Reconnects rotate
	// through these targets without depending on DNS inside the tunnel.
	// Without them the client resolves Addr before each attempt until a
	// lookup succeeds, then keeps those addresses, so a lookup that fails
	// at startup (DNS not up yet) delays the carrier instead of stopping
	// the client.
	Endpoints []netip.AddrPort
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
	// Front, when set, upgrades the TLS session into the stream carrier
	// through the relay's fail-closed HTTPS front, rather than speaking
	// the carrier's own ALPN.
	Front *FrontDialOptions
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
	// StallTimeout closes a connection that has had a frame in flight
	// this long without receiving anything, reporting it as
	// ModeTimeoutAtNBytes, and redials: a censor that silently stops
	// delivering a connection's data (the TSPU freeze) otherwise leaves
	// the carrier on it until TCP gives up, many minutes later. Default
	// DefaultStallTimeout; negative disables.
	StallTimeout time.Duration
	// OnState, if set, is called when the connection comes up (err nil)
	// or a dial attempt or connection fails.
	OnState func(err error)
}

// DefaultStallTimeout is ClientOptions.StallTimeout's default: above the
// round trip plus queueing of any link worth keeping, and short enough
// that a frozen connection costs the session seconds, not its path
// (spec/freeze-and-udp-ban.md §2).
const DefaultStallTimeout = 2 * time.Second

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

	// Used by the connecting goroutine only.
	endpoints    []netip.AddrPort
	nextEndpoint int
	lookup       func(context.Context, string, string) ([]netip.Addr, error) // nil: the system resolver
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
	if opts.StallTimeout == 0 {
		opts.StallTimeout = DefaultStallTimeout
	}
	ctx, stop := context.WithCancel(context.Background())
	c := &Client{opts: opts, in: make(chan inbound, opts.Queue), ctx: ctx, stop: stop}
	go c.connectLoop()
	return c
}

func (c *Client) connectLoop() {
	const initialBackoff = 500 * time.Millisecond
	backoff := initialBackoff
	for c.ctx.Err() == nil {
		redial := false // dial again without waiting
		l, track, err := c.connect()
		if c.ctx.Err() != nil { // closed mid-dial: nothing to report
			if l != nil {
				l.close()
			}
			return
		}
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
			derr := l.run(c.in)
			c.setLink(nil)
			if c.ctx.Err() != nil {
				return
			}
			if c.opts.OnState != nil {
				if derr != nil {
					c.opts.OnState(classifyDeath(track, derr))
				} else {
					c.opts.OnState(errors.New("stream: connection closed"))
				}
			}
			switch {
			case errors.Is(derr, errStalled) && l.frames.Load() > 0:
				// It carried data until a censor froze it: redial at once.
				// Stalls pace these dials to one per StallTimeout.
				backoff, redial = initialBackoff, true
			case time.Since(start) > 10*time.Second:
				backoff = initialBackoff // it worked for a while
			}
		}
		wait := backoff
		if redial {
			wait = 0
		}
		select {
		case <-time.After(wait):
		case <-c.ctx.Done():
			return
		}
		backoff = min(2*backoff, c.opts.MaxBackoff)
	}
}

func (c *Client) connect() (*link, *trackingConn, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	conn, raw, alpn, err := c.dialTLS(ctx)
	if err != nil {
		return nil, nil, err
	}
	// The camouflage and front profiles offer web ALPN, so the
	// negotiated label is not the carrier's; the ARC session
	// authenticates the peer.
	if c.opts.Camouflage == nil && c.opts.Front == nil && alpn != ALPN {
		conn.Close()
		return nil, nil, &Failure{Mode: ModeDied, At: raw.total(),
			Err: errors.New("stream: relay did not negotiate ALPN " + ALPN)}
	}
	if c.opts.Front != nil {
		uconn, err := upgradeFront(conn, c.opts.Addr, c.opts.Front)
		if err != nil {
			conn.Close()
			return nil, nil, &Failure{Mode: ModeFrontRefused, At: raw.total(), Err: err}
		}
		conn = uconn
	}
	l := newLink(conn, c.opts.Peer, c.opts.Queue, 0)
	l.stall = max(c.opts.StallTimeout, 0)
	return l, raw, nil
}

// dialTLS connects to the relay endpoint and runs the TLS handshake,
// returning the TLS connection, its tracked transport (whose byte counts
// classify any later death), and the negotiated protocol. Failures are
// classified (§8 taxonomy): OnState receives a *Failure, not a bare
// error. SetNoDelay runs before the handshake: the camouflage profile
// needs its ClientHello fragments to leave as TCP segments at once.
func (c *Client) dialTLS(ctx context.Context) (net.Conn, *trackingConn, string, error) {
	if len(c.endpoints) == 0 {
		c.endpoints = c.opts.Endpoints
	}
	if len(c.endpoints) == 0 {
		lookup := c.lookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupNetIP
		}
		eps, err := resolveEndpoints(ctx, c.opts.Addr, lookup)
		if err != nil {
			return nil, nil, "", classifyConnect(err)
		}
		c.endpoints = eps
	}
	// The TLS server name still comes from Addr (see handshakeTLS).
	addr := c.endpoints[c.nextEndpoint%len(c.endpoints)].String()
	c.nextEndpoint = (c.nextEndpoint + 1) % len(c.endpoints)
	tcp, err := (&net.Dialer{
		Control:   sockopt.Control(c.opts.Sockopt),
		KeepAlive: 15 * time.Second,
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, "", classifyConnect(err)
	}
	raw := &trackingConn{Conn: tcp}
	if t, ok := tcp.(*net.TCPConn); ok {
		t.SetNoDelay(true)
	}
	conn, alpn, err := c.handshakeTLS(ctx, raw)
	if err != nil {
		raw.Close()
		return nil, nil, "", classifyHandshake(raw, err)
	}
	return conn, raw, alpn, nil
}

// handshakeTLS runs the carrier's TLS handshake over raw: the plain
// carrier (spec §16.3) with verified identity and ALPN arc/1, the
// camouflage profile, which hands the whole outer handshake its shape,
// or the front, which negotiates HTTP/1.1 for its upgrade.
func (c *Client) handshakeTLS(ctx context.Context, raw *trackingConn) (net.Conn, string, error) {
	if cam := c.opts.Camouflage; cam != nil {
		if c.opts.Front != nil { // per-dial override, not a mutation of the caller's
			clone := *cam
			clone.ALPN = []string{"http/1.1"} // the upgrade is an HTTP/1.1 mechanism
			return clone.Handshake(ctx, raw, c.opts.Addr, c.opts.TLS)
		}
		return cam.Handshake(ctx, raw, c.opts.Addr, c.opts.TLS)
	}
	cfg, err := clientConfig(c.opts.TLS, c.opts.Addr)
	if err != nil {
		return nil, "", err
	}
	cfg.MinVersion = tls.VersionTLS13
	if c.opts.Front != nil {
		cfg.NextProtos = []string{"http/1.1"} // the upgrade is an HTTP/1.1 mechanism
	} else {
		cfg.NextProtos = []string{ALPN}
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, "", err
	}
	return conn, conn.ConnectionState().NegotiatedProtocol, nil
}

// clientConfig clones base (nil for defaults) and, like tls.Dial, fills
// an empty server name from addr's host.
func clientConfig(base *tls.Config, addr string) (*tls.Config, error) {
	if base == nil {
		base = &tls.Config{}
	}
	cfg := base.Clone()
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("stream: no TLS server name: %w", err)
		}
		cfg.ServerName = host
	}
	return cfg, nil
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
		l.send(p, false)
	}
	return nil
}

// WriteBatchEliciting is WriteBatch, told which packets the relay owes a
// reply (an acknowledgement within its maximum ACK delay). Only those arm
// stall detection (StallTimeout); WriteBatch arms it for none.
func (c *Client) WriteBatchEliciting(pkts [][]byte, _ []netip.AddrPort, eliciting []bool) error {
	c.mu.Lock()
	l := c.cur
	c.mu.Unlock()
	if l == nil {
		return nil
	}
	for i, p := range pkts {
		l.send(p, eliciting[i])
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
