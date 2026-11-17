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
	// RotateBytes, when positive, moves the carrier to a fresh connection
	// each time the current one has received this many bytes, dialing
	// the next one ahead of time: a censor that caps each connection's
	// downlink (the TSPU freeze) then never freezes one in use. Without
	// it, the carrier learns a budget from its stalls (see learn), per
	// dial destination.
	RotateBytes int64
	// OnLearn, if set, is called when the carrier learns a rotation
	// budget for a destination from its stalls.
	OnLearn func(dest netip.AddrPort, budget int64)
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

	// Used by the connecting goroutine only (and by one spare dial at a
	// time, which it hands over through spareCh).
	// Learned per dial destination: a cap observed on one relay address
	// says nothing about another (a hosting address and a domestic one).
	budgets   map[netip.AddrPort]int64 // rotate after receiving this much
	lastStall map[netip.AddrPort]int64 // bytes the last stalled connection received
	spare     *dialed
	spareBusy bool // a spare dial is running and will send on spareCh
	spareCh   chan dialed

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
	c := &Client{opts: opts, in: make(chan inbound, opts.Queue), ctx: ctx, stop: stop,
		budgets: map[netip.AddrPort]int64{}, lastStall: map[netip.AddrPort]int64{}, spareCh: make(chan dialed, 1)}
	go c.connectLoop()
	return c
}

// dialed is the outcome of one connection attempt.
type dialed struct {
	l     *link
	track *trackingConn
	dest  netip.AddrPort // the endpoint dialed; invalid if none was
	err   error
	at    time.Time
}

// maxSpareAge bounds how long a pre-dialed spare connection waits unused
// before it is replaced: the relay or a middlebox may have dropped it.
const maxSpareAge = time.Minute

func (c *Client) connectLoop() {
	const initialBackoff = 500 * time.Millisecond
	backoff := initialBackoff
	d := c.take()
	for c.ctx.Err() == nil {
		if d.err != nil {
			if c.opts.OnState != nil {
				c.opts.OnState(d.err)
			}
			if !c.sleep(backoff) {
				return
			}
			backoff = min(2*backoff, c.opts.MaxBackoff)
			d = c.take()
			continue
		}
		l, track, dest := d.l, d.track, d.dest
		budget := c.budget(dest)
		if budget > 0 {
			l.track, l.rotateAt = track, budget
		}
		c.setLink(l) // before OnState, so a write it prompts is not dropped
		if c.opts.OnState != nil {
			c.opts.OnState(nil)
		}
		if budget > 0 {
			c.startSpare()
		}
		start := time.Now()
		ran := make(chan error, 1)
		go func() { ran <- l.run(c.in) }()

		// Wait for the link to end or to reach its budget. A spare
		// still dialing never blocks this loop: the active link's death
		// and Close are handled while it dials, and the switch happens
		// when both the budget is reached and the spare is ready.
		var derr error
		rotated, rotate, due := false, l.rotate, false
	wait:
		for {
			var spareDone chan dialed
			if c.spareBusy {
				spareDone = c.spareCh
			}
			select {
			case derr = <-ran:
				break wait
			case <-rotate:
				due = true
			case sp := <-spareDone:
				c.spareBusy, c.spare = false, &sp
				if sp.err != nil && c.opts.OnState != nil {
					c.opts.OnState(sp.err)
				}
			case <-c.ctx.Done():
				l.close()
				c.dropSpare()
				return
			}
			if !due || c.spareBusy {
				continue
			}
			next, ok := c.freshSpare()
			if !ok {
				// No usable spare: keep this connection. It may still
				// stall and redial; the next one dials a new spare.
				due, rotate = false, nil
				continue
			}
			// The connection nears the censor's cap: move to the spare
			// (make before break, spec/freeze-and-udp-ban.md §3).
			go c.retire(l, ran)
			d, rotated = next, true
			break wait
		}
		if rotated {
			continue
		}
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
		wait := backoff
		switch {
		case errors.Is(derr, errStalled) && l.frames.Load() > 0:
			// It carried data until a censor froze it: redial at once.
			// Stalls pace these dials to one per StallTimeout.
			c.learn(dest, track.read.Load())
			backoff, wait = initialBackoff, 0
		case time.Since(start) > 10*time.Second:
			backoff = initialBackoff // it worked for a while
			wait = backoff
		}
		if wait > 0 && !c.sleep(wait) {
			return
		}
		if wait > 0 {
			backoff = min(2*backoff, c.opts.MaxBackoff)
		}
		d = c.take()
	}
	c.dropSpare()
}

// sleep waits d, reporting false if the carrier closed meanwhile.
func (c *Client) sleep(d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-c.ctx.Done():
		return false
	}
}

// take returns the next connection: the spare, if one is ready or being
// dialed and fresh, otherwise a new dial. Only one dial runs at a time.
func (c *Client) take() dialed {
	if c.spareBusy {
		select {
		case sp := <-c.spareCh:
			c.spare = &sp
		case <-c.ctx.Done():
			return dialed{err: context.Canceled}
		}
		c.spareBusy = false
	}
	if sp, ok := c.freshSpare(); ok {
		return sp
	}
	return c.connect()
}

// freshSpare takes the spare connection if it is up and not stale,
// closing it otherwise.
func (c *Client) freshSpare() (dialed, bool) {
	sp := c.spare
	c.spare = nil
	switch {
	case sp == nil:
		return dialed{}, false
	case sp.err == nil && time.Since(sp.at) < maxSpareAge:
		return *sp, true
	case sp.l != nil:
		sp.l.close()
	}
	return dialed{}, false
}

// budget is the rotation budget for connections to dest: RotateBytes if
// set, else what stalls on dest taught; 0 for none.
func (c *Client) budget(dest netip.AddrPort) int64 {
	if c.opts.RotateBytes > 0 {
		return c.opts.RotateBytes
	}
	return c.budgets[dest]
}

// startSpare dials a spare connection in the background, unless one is
// ready or being dialed.
func (c *Client) startSpare() {
	if c.spareBusy || c.spare != nil {
		return
	}
	c.spareBusy = true
	go func() { c.spareCh <- c.connect() }()
}

// dropSpare closes the spare connection, waiting for one being dialed.
func (c *Client) dropSpare() {
	if c.spareBusy {
		sp := <-c.spareCh
		c.spareBusy, c.spare = false, &sp
	}
	if c.spare != nil && c.spare.l != nil {
		c.spare.l.close()
	}
	c.spare = nil
}

// retire closes a link the carrier rotated away from, once the relay has
// had StallTimeout to move its downlink to the successor. Until then it
// keeps delivering what the relay still sends on it.
func (c *Client) retire(l *link, ran <-chan error) {
	grace := c.opts.StallTimeout
	if grace <= 0 {
		grace = DefaultStallTimeout
	}
	select {
	case <-time.After(grace):
	case <-ran:
	case <-c.ctx.Done():
	}
	l.close()
}

// minCap is the least a stalled connection must have received for its
// stall to count as a byte cap rather than a dead link.
const minCap = 4 << 10

// learn records how much a stalled connection to dest received. Two
// consecutive stalls on dest within 25% of each other, both above minCap,
// are a byte cap (spec/freeze-and-udp-ban.md §3): later connections to
// dest rotate at half the smaller count. Other destinations are not
// affected, and a configured budget is never changed.
func (c *Client) learn(dest netip.AddrPort, read int64) {
	prev := c.lastStall[dest]
	c.lastStall[dest] = read
	if c.opts.RotateBytes > 0 || !dest.IsValid() || prev < minCap || read < minCap {
		return
	}
	lo, hi := min(prev, read), max(prev, read)
	if 4*(hi-lo) > hi {
		return
	}
	if budget := lo / 2; c.budgets[dest] == 0 || budget < c.budgets[dest] {
		c.budgets[dest] = budget
		if c.opts.OnLearn != nil {
			c.opts.OnLearn(dest, budget)
		}
	}
}

// connectTimeout bounds a whole connection attempt: TCP, TLS, and the
// front's HTTP upgrade.
var connectTimeout = 10 * time.Second

// connect makes one connection attempt, bounded by connectTimeout and
// abandoned when the carrier closes.
func (c *Client) connect() dialed {
	ctx, cancel := context.WithTimeout(c.ctx, connectTimeout)
	defer cancel()
	conn, raw, dest, alpn, err := c.dialTLS(ctx)
	fail := func(err error) dialed { return dialed{dest: dest, err: err, at: time.Now()} }
	if err != nil {
		return fail(err)
	}
	// The camouflage and front profiles offer web ALPN, so the
	// negotiated label is not the carrier's; the ARC session
	// authenticates the peer.
	if c.opts.Camouflage == nil && c.opts.Front == nil && alpn != ALPN {
		conn.Close()
		return fail(&Failure{Mode: ModeDied, At: raw.total(),
			Err: errors.New("stream: relay did not negotiate ALPN " + ALPN)})
	}
	if c.opts.Front != nil {
		// The upgrade is plain reads and writes: bound it by the same
		// deadline, and by Close.
		dl, _ := ctx.Deadline()
		conn.SetDeadline(dl)
		stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
		uconn, err := upgradeFront(conn, c.opts.Addr, c.opts.Front)
		if !stop() || err != nil {
			conn.Close()
			if err == nil {
				err = ctx.Err()
			}
			mode := ModeFrontRefused
			if isTimeout(err) { // no answer to the upgrade, not a refusal
				mode = ModeTimeoutAtNBytes
			}
			return fail(&Failure{Mode: mode, At: raw.total(), Err: err})
		}
		conn.SetDeadline(time.Time{})
		conn = uconn
	}
	l := newLink(conn, c.opts.Peer, c.opts.Queue, 0)
	l.stall = max(c.opts.StallTimeout, 0)
	return dialed{l: l, track: raw, dest: dest, at: time.Now()}
}

// dialTLS connects to the relay endpoint and runs the TLS handshake,
// returning the TLS connection, its tracked transport (whose byte counts
// classify any later death), and the negotiated protocol. Failures are
// classified (§8 taxonomy): OnState receives a *Failure, not a bare
// error. SetNoDelay runs before the handshake: the camouflage profile
// needs its ClientHello fragments to leave as TCP segments at once.
func (c *Client) dialTLS(ctx context.Context) (net.Conn, *trackingConn, netip.AddrPort, string, error) {
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
			return nil, nil, netip.AddrPort{}, "", classifyConnect(err)
		}
		c.endpoints = eps
	}
	// The TLS server name still comes from Addr (see handshakeTLS).
	dest := c.endpoints[c.nextEndpoint%len(c.endpoints)]
	addr := dest.String()
	c.nextEndpoint = (c.nextEndpoint + 1) % len(c.endpoints)
	tcp, err := (&net.Dialer{
		Control:   sockopt.Control(c.opts.Sockopt),
		KeepAlive: 15 * time.Second,
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, dest, "", classifyConnect(err)
	}
	raw := &trackingConn{Conn: tcp}
	if t, ok := tcp.(*net.TCPConn); ok {
		t.SetNoDelay(true)
	}
	conn, alpn, err := c.handshakeTLS(ctx, raw)
	if err != nil {
		raw.Close()
		return nil, nil, dest, "", classifyHandshake(raw, err)
	}
	return conn, raw, dest, alpn, nil
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
