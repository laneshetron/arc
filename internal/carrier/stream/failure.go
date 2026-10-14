package stream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
)

// Failure modes, from the carrier error taxonomy of the profiler design
// (network-profiling.md §8) plus the finer results a TLS dial can
// distinguish. A mode records how far the exchange got, never why the
// network killed it; pairing modes with controls (the profiler's P2) is
// what attributes enforcement.
const (
	// Dial-phase failures: the transport never came up.
	ModeConnectRefused = "tcp-connect-refused"
	ModeConnectTimeout = "tcp-connect-timeout"
	// Handshake failures, classified by progress.
	ModeRSTAfterClientHello     = "tcp-rst-after-clienthello"
	ModeEOFAfterClientHello     = "tcp-eof-after-clienthello"
	ModeTimeoutAfterClientHello = "tcp-timeout-after-clienthello"
	ModeKilledAfterServerHello  = "tls-killed-after-serverhello"
	// Failures of an established connection; At holds the bytes
	// exchanged until death.
	ModeResetAtNBytes   = "reset-at-N-bytes"
	ModeClosedAtNBytes  = "closed-at-N-bytes"
	ModeTimeoutAtNBytes = "timeout-at-N-bytes"
	// A death that is none of the above.
	ModeDied = "stream-died"
)

// A Failure is a classified carrier outcome. OnState carries it for dial
// and connection failures; the profiler consumes the Mode, and the
// wrapped error stays for logs.
type Failure struct {
	Mode string
	At   int64 // bytes exchanged until the failure; 0 for handshake modes that measure none
	Err  error
}

func (f *Failure) Error() string {
	if f.At > 0 {
		return fmt.Sprintf("stream: %s at %d bytes: %v", f.Mode, f.At, f.Err)
	}
	return fmt.Sprintf("stream: %s: %v", f.Mode, f.Err)
}

func (f *Failure) Unwrap() error { return f.Err }

// classifyConnect classifies a failure of the TCP dial itself, before any
// TLS byte left the host.
func classifyConnect(err error) *Failure {
	if isTimeout(err) {
		return &Failure{Mode: ModeConnectTimeout, Err: err}
	}
	return &Failure{Mode: ModeConnectRefused, Err: err}
}

// classifyHandshake classifies a TLS failure on a connection that came
// up: did the client send its ClientHello, did any server bytes arrive?
func classifyHandshake(c *trackingConn, err error) *Failure {
	f := &Failure{Mode: ModeDied, At: c.total(), Err: err}
	read, wrote := c.counts()
	switch {
	case wrote == 0:
		// Nothing left the host: a local failure, not network evidence.
	case read == 0:
		switch {
		case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED):
			f.Mode = ModeRSTAfterClientHello
		case isTimeout(err):
			f.Mode = ModeTimeoutAfterClientHello
		default: // EOFs and abrupt closes: the server answered nothing
			f.Mode = ModeEOFAfterClientHello
		}
	default: // server bytes arrived: it died mid-handshake or at its end
		f.Mode = ModeKilledAfterServerHello
	}
	return f
}

// classifyDeath classifies the end of an established carrier connection.
func classifyDeath(c *trackingConn, err error) *Failure {
	f := &Failure{Mode: ModeClosedAtNBytes, At: c.total(), Err: err}
	switch {
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED):
		f.Mode = ModeResetAtNBytes
	case isTimeout(err):
		f.Mode = ModeTimeoutAtNBytes
	}
	return f
}

func isTimeout(err error) bool {
	if os.IsTimeout(err) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// trackingConn counts bytes each way across a carrier connection, so an
// ended connection can be classified by how far it got (§8 taxonomy)
// instead of reduced to one opaque error. It must wrap the transport the
// TLS stack runs on, not the TLS connection itself, so handshake bytes
// are counted too.
type trackingConn struct {
	net.Conn
	wrote, read atomic.Int64
}

func (t *trackingConn) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	t.wrote.Add(int64(n))
	return n, err
}

func (t *trackingConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	t.read.Add(int64(n))
	return n, err
}

func (t *trackingConn) counts() (read, wrote int64) {
	return t.read.Load(), t.wrote.Load()
}

func (t *trackingConn) total() int64 {
	return t.read.Load() + t.wrote.Load()
}
