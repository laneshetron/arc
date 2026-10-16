package stream

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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
	// A front that served cover content instead of upgrading.
	ModeFrontRefused = "front-upgrade-refused"
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
// TLS byte left the host. Only a refused or reset SYN and an unanswered one
// are network evidence; name resolution and local routing failures (no
// such host, unreachable network) are not.
func classifyConnect(err error) *Failure {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns), errors.Is(err, context.Canceled):
		return &Failure{Mode: ModeDied, Err: err}
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return &Failure{Mode: ModeConnectRefused, Err: err}
	case isTimeout(err):
		return &Failure{Mode: ModeConnectTimeout, Err: err}
	}
	return &Failure{Mode: ModeDied, Err: err}
}

// classifyHandshake classifies a TLS failure on a connection that came
// up: did the client send its ClientHello, did any server bytes arrive?
func classifyHandshake(c *trackingConn, err error) *Failure {
	f := &Failure{Mode: ModeDied, At: c.total(), Err: err}
	read, wrote := c.counts()
	switch {
	case wrote == 0, errors.Is(err, context.Canceled):
		// Nothing left the host, or the carrier was closed mid-dial: a
		// local outcome, not network evidence.
	case isPeerOrLocalRejection(err):
		// The far end answered with a TLS alert (say, a relay without
		// camouflage refusing a browser ALPN), or this host rejected the
		// certificate: a configuration fault, not interference.
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
// A write failing with EPIPE means a reset already arrived: the writer can
// see it before the reader does.
func classifyDeath(c *trackingConn, err error) *Failure {
	f := &Failure{Mode: ModeDied, At: c.total(), Err: err}
	switch {
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, syscall.EPIPE):
		f.Mode = ModeResetAtNBytes
	case isTimeout(err):
		f.Mode = ModeTimeoutAtNBytes
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		f.Mode = ModeClosedAtNBytes
	}
	return f
}

// isPeerOrLocalRejection reports whether a handshake failed on a TLS alert
// received from the peer or on this host's certificate verification,
// rather than on the transport.
func isPeerOrLocalRejection(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" {
		return true // crypto/tls and utls both report received alerts so
	}
	var (
		unknown   x509.UnknownAuthorityError
		hostname  x509.HostnameError
		invalid   x509.CertificateInvalidError
		systemErr x509.SystemRootsError
	)
	return errors.As(err, &unknown) || errors.As(err, &hostname) ||
		errors.As(err, &invalid) || errors.As(err, &systemErr)
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
