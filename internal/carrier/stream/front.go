package stream

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// UpgradeToken is the HTTP Upgrade protocol name that switches an
// authenticated front connection into the stream carrier. It is a plain
// token per RFC 7230 -- no version, since the upgraded protocol is ARC's
// ordinary stream framing, whose version the session negotiates.
const UpgradeToken = "arc"

// FrontOptions configures the relay's front: one TLS endpoint that is,
// to any observer, an ordinary HTTPS site. Every unauthenticated request
// is served cover content; a request carrying an admission token
// upgrades into the stream carrier (§12.2). The front is fail-closed --
// it never refuses a connection for its shape, so an active prober sees
// a website whatever it tries -- and doubles as the relay's own
// reachability canary (network-profiling.md §7).
type FrontOptions struct {
	// TLS holds the relay's certificate. For the persona to survive
	// certificate-checking probers it should be publicly valid for the
	// domain clients dial (the relay operator's own domain; this carrier
	// does not borrow third parties' names).
	TLS *tls.Config
	// Tokens admit the carrier upgrade. They are the deployment's client
	// access tokens; a request without one is served cover content,
	// indistinguishable from any other visitor.
	Tokens [][]byte
	// Site serves cover content; nil serves a minimal built-in page.
	// Operators should point it at an innocuous real site.
	Site http.Handler
	// MaxConns bounds all concurrent connections, visitors and carriers
	// together (default 4096).
	MaxConns int
	// MaxPending bounds connections that are not carriers: TLS
	// handshakes, and HTTP visitors until they close (default 128).
	MaxPending int
	// MaxConnsPerSource and MaxPendingPerSource apply to the TCP peer's
	// IP (defaults 64 and 8; browsers open up to 6 HTTP/1.1 connections
	// to a site, so a visitor stays within the pending budget).
	MaxConnsPerSource   int
	MaxPendingPerSource int
	// HandshakeTimeout bounds the TLS handshake, and then reading each
	// request's headers (default 10 seconds, as ListenerOptions).
	HandshakeTimeout time.Duration
	// VisitorIdle closes a visitor's keep-alive connection after this
	// long without a request (default 60 seconds).
	VisitorIdle time.Duration
	// Report, if set, learns of each carrier connection when it is
	// upgraded and when it ends (see ConnReport). Visitors, including
	// requests whose token did not admit them, are not reported. It is
	// called from the connection's goroutine and must not block.
	Report func(ConnReport)
	// Idle closes a carrier connection that receives nothing for this
	// long (default 5 minutes).
	Idle time.Duration
	// Queue bounds packets waiting to be written per carrier connection.
	Queue int
}

// Front is the relay's fail-closed HTTPS front. It implements the
// engine's DatagramConn: carrier connections appear from synthetic
// stream addresses (IsStreamAddr), exactly like the plain listener's.
type Front struct {
	ln     net.Listener
	srv    *http.Server
	reg    *registry
	adm    *admission
	cover  http.Handler
	tokens [][]byte
	report func(ConnReport)
}

// Refusals returns the connections refused by admission limits since it
// was last called.
func (f *Front) Refusals() Refusals { return f.adm.takeRefusals() }

// ListenFront starts the front on addr.
func ListenFront(addr string, opts FrontOptions) (*Front, error) {
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
		opts.MaxPendingPerSource = 8
	}
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 10 * time.Second
	}
	if opts.VisitorIdle == 0 {
		opts.VisitorIdle = 60 * time.Second
	}
	if opts.MaxConns < 0 || opts.MaxPending < 0 || opts.MaxConnsPerSource < 0 || opts.MaxPendingPerSource < 0 ||
		opts.HandshakeTimeout < 0 || opts.VisitorIdle < 0 || opts.Queue < 0 || opts.Idle < 0 {
		return nil, errors.New("stream: front connection, timeout, queue and idle limits must not be negative")
	}
	cfg := opts.TLS.Clone()
	cfg.MinVersion = tls.VersionTLS13
	// A browser-alike offer must succeed: the cover site is ordinary
	// HTTPS, h2 included.
	cfg.NextProtos = []string{"h2", "http/1.1"}
	noteHello(cfg)
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	// Limits apply as each TCP connection arrives, before any TLS work.
	adm := newAdmission(admissionLimits{
		maxConns: opts.MaxConns, maxPending: opts.MaxPending,
		maxConnsPerSource: opts.MaxConnsPerSource, maxPendingPerSource: opts.MaxPendingPerSource,
	})
	f := &Front{
		ln:     tls.NewListener(&admittedListener{Listener: tcp, adm: adm}, cfg),
		reg:    newRegistry(opts.MaxConns, opts.Queue, opts.Idle),
		adm:    adm,
		cover:  opts.Site,
		tokens: opts.Tokens,
		report: opts.Report,
	}
	if f.cover == nil {
		f.cover = http.HandlerFunc(defaultCover)
	}
	// ReadHeaderTimeout also bounds the TLS handshake (net/http uses the
	// shortest of its read and write timeouts); IdleTimeout frees the
	// pending permits idle visitors hold.
	f.srv = &http.Server{Handler: http.HandlerFunc(f.handle), ReadHeaderTimeout: opts.HandshakeTimeout, IdleTimeout: opts.VisitorIdle}
	go func() {
		f.srv.Serve(f.ln) // returns ErrServerClosed on Close; nothing else to do
	}()
	return f, nil
}

// handle admits an authenticated carrier upgrade or serves cover
// content. Nothing about an unauthenticated request may behave
// differently from an ordinary site, so refusal is indistinguishable:
// the cover speaks.
func (f *Front) handle(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Header.Get("Upgrade"), UpgradeToken) && f.admits(r.Header.Get("Authorization")) {
		hj, ok := w.(http.Hijacker)
		if !ok { // h2 connections cannot hijack; none reach here carrying the token
			f.cover.ServeHTTP(w, r)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			f.cover.ServeHTTP(w, r)
			return
		}
		if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\nUpgrade: " + UpgradeToken + "\r\n\r\n")); err != nil {
			conn.Close()
			return
		}
		conn.SetDeadline(time.Time{}) // the header timeout must not govern the carrier
		var raw *countedConn
		if ac, ok := conn.(*tls.Conn).NetConn().(*admittedConn); ok {
			raw, _ = ac.Conn.(*countedConn)
			if raw != nil {
				if tcp, ok := raw.Conn.(*net.TCPConn); ok {
					tcp.SetNoDelay(true)
				}
			}
			ac.permit.established() // a carrier now, off the visitor budgets
		}
		// Bytes past the client's request may already sit in the hijacked
		// buffer; the carrier's frames must not lose them.
		var pc net.Conn = conn
		if n := bufrw.Reader.Buffered(); n > 0 {
			b, _ := bufrw.Reader.Peek(n)
			pc = &prefixConn{Conn: conn, prefix: append([]byte(nil), b...)}
		}
		report := f.report
		if raw == nil {
			report = nil
		}
		go func() {
			var opened func(netip.AddrPort)
			if report != nil {
				opened = func(a netip.AddrPort) { report(raw.report(true, a, nil)) }
			}
			addr, err := f.reg.serve(pc, opened)
			if report != nil && f.reg.ctx.Err() == nil {
				report(raw.report(false, addr, err))
			}
		}()
		return
	}
	f.cover.ServeHTTP(w, r)
}

// admits compares a "Bearer" authorization against the admission tokens
// in constant time per token.
func (f *Front) admits(auth string) bool {
	const bearer = "Bearer "
	if len(auth) <= len(bearer) || !strings.EqualFold(auth[:len(bearer)], bearer) {
		return false
	}
	presented := []byte(auth[len(bearer):])
	for _, t := range f.tokens {
		if subtle.ConstantTimeCompare(t, presented) == 1 {
			return true
		}
	}
	return false
}

// defaultCover is the front's fallback page: intentionally boring.
func defaultCover(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Services</title></head>
<body><h1>Service status</h1><p>All systems operational.</p></body>
</html>`)
}

// Addr returns the listening address.
func (f *Front) Addr() net.Addr { return f.ln.Addr() }

// WriteBatch queues each packet for the carrier connection its address
// names. Packets for unknown addresses or full queues are dropped.
func (f *Front) WriteBatch(pkts [][]byte, addrs []netip.AddrPort) error {
	return f.reg.writeBatch(pkts, addrs)
}

// ReadBatch reads received packets, blocking until at least one arrives.
func (f *Front) ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	return f.reg.readBatch(bufs, sizes, addrs)
}

// Conns returns the number of open carrier connections.
func (f *Front) Conns() int { return f.reg.conns() }

// Close stops accepting and closes every carrier connection.
func (f *Front) Close() error {
	f.reg.close()
	err := f.srv.Close()
	f.adm.closeAll() // hijacked carriers are no longer the server's to close
	return err
}

// upgradeFront sends the front's upgrade request over the client's TLS
// session and returns the connection, with any bytes the server sent
// past its response preserved ahead of the carrier's frames.
func upgradeFront(conn net.Conn, addr string, front *FrontDialOptions) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("stream: front: %w", err)
	}
	path := front.Path
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: " + UpgradeToken + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Authorization: Bearer " + front.Token + "\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}
	// The body is not read: after a 101 the remaining bytes are the
	// carrier's own, and resp.Body is never closed, which would close
	// the connection.
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), UpgradeToken) {
		return nil, fmt.Errorf("stream: front offered %q, no upgrade", resp.Status)
	}
	if br.Buffered() == 0 {
		return conn, nil
	}
	prefix, _ := br.Peek(br.Buffered())
	return &prefixConn{Conn: conn, prefix: append([]byte(nil), prefix...)}, nil
}

// prefixConn serves bytes that arrived before a handshake finished from
// its prefix, then reads from the connection. Writes always pass.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
