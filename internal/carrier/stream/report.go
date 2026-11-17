package stream

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"
)

// ConnReport describes a TCP connection a relay endpoint accepted, for
// the operator's logs: where it came from, how far it got, and what it
// carried. Everything in it is unauthenticated until the ARC session on
// the carrier authenticates, so an endpoint reports at most two per
// connection, and its admission limits bound how many arrive.
type ConnReport struct {
	// Open is set when the connection has just become a carrier, and
	// clear when it has ended, whether or not it became one.
	Open bool
	Peer netip.AddrPort // the TCP peer
	// Addr is the carrier's synthetic address (IsStreamAddr), as the
	// session sees it; invalid if the connection never became a carrier.
	Addr netip.AddrPort
	// Hello is set once a complete ClientHello arrived; ServerName and
	// ALPN are what it offered.
	Hello      bool
	ServerName string
	ALPN       []string
	// Duration is the time since the connection was accepted.
	Duration time.Duration
	// BytesIn and BytesOut count bytes on the TCP connection, TLS records
	// included (and, on the front, the HTTP upgrade).
	BytesIn, BytesOut int64
	// Err ends the connection, if it ended with one: a failed TLS
	// handshake, ErrALPN, or the carrier's transport error.
	Err error
}

// ErrALPN ends a connection whose TLS handshake succeeded with an ALPN
// the listener does not carry: none, or a browser's without Camouflage.
var ErrALPN = errors.New("stream: no carrier ALPN negotiated")

// countedConn counts the bytes through a connection and keeps what its
// ClientHello offered.
type countedConn struct {
	net.Conn
	accepted   time.Time
	in, out    atomic.Int64
	hello      bool     // set during the handshake, read after it
	serverName string   // likewise
	alpn       []string // likewise
}

func (c *countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.in.Add(int64(n))
	return n, err
}

func (c *countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.out.Add(int64(n))
	return n, err
}

// noteHello wraps cfg so the countedConn under each handshake keeps what
// its ClientHello offered.
func noteHello(cfg *tls.Config) {
	next := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		c, _ := hello.Conn.(*countedConn)
		if ac, ok := hello.Conn.(*admittedConn); ok { // the front's
			c, _ = ac.Conn.(*countedConn)
		}
		if c != nil {
			c.hello, c.serverName, c.alpn = true, hello.ServerName, slices.Clone(hello.SupportedProtos)
		}
		if next != nil {
			return next(hello)
		}
		return nil, nil
	}
}

// report describes c for a ConnReport, with the carrier's address and
// the error that ended it.
func (c *countedConn) report(open bool, addr netip.AddrPort, err error) ConnReport {
	return ConnReport{
		Open: open, Peer: peerOf(c), Addr: addr, Hello: c.hello, ServerName: c.serverName, ALPN: c.alpn,
		Duration: time.Since(c.accepted), BytesIn: c.in.Load(), BytesOut: c.out.Load(), Err: err,
	}
}

// peerOf parses a connection's remote address; invalid if it has none.
func peerOf(c net.Conn) netip.AddrPort {
	a, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}
