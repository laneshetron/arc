package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Camouflage configures the camouflage profile of the client carrier:
// the outer TLS presents itself as ordinary browser traffic to the relay
// endpoint rather than as an ARC carrier. The outer TLS is cover only —
// ARC's own authenticated session carries all security (spec D2) — so
// certificate verification may be skipped where no CA is pinned. This
// defeats passive filtering by observers of the ClientHello; it does not
// by itself survive an active prober, which must be answered by a
// fail-closed relay (a later profile).
type Camouflage struct {
	// Name is presented as the TLS server name (SNI): a host the network
	// permits, not the relay's own name. Empty means the TLS
	// configuration's server name, or the endpoint's host. A pinned CA
	// (if any) still verifies against this name, so a relay's certificate
	// must list it.
	Name string
	// Fingerprint shapes the ClientHello as a browser's: "chrome",
	// "edge", "safari", "ios", or "firefox". Empty uses Go's ordinary
	// TLS, whose ClientHello is distinctive.
	Fingerprint string
	// Fragment, when nonzero, sends the ClientHello in TCP segments of
	// at most this many bytes, defeating middleboxes that read the whole
	// server name out of the first segment.
	Fragment int
}

// browserALPN is what a camouflage client offers instead of the carrier's
// ALPN: an observer of the ClientHello sees a browser's offer. The relay
// accepts these where ListenerOptions.Camouflage is set; the negotiated
// label is not used for framing.
var browserALPN = []string{"h2", "http/1.1"}

// FingerprintID maps a browser name to its ClientHello profile. Nothing
// on the wire changes; only the shape of the outer handshake does.
func FingerprintID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	}
	return utls.ClientHelloID{}, fmt.Errorf("stream: unsupported TLS fingerprint %q (want chrome, edge, safari, ios, or firefox)", name)
}

// Validate checks the profile's fields, so a bad configuration fails
// before any dial.
func (cam *Camouflage) Validate() error {
	if cam == nil {
		return nil
	}
	if cam.Fingerprint != "" {
		if _, err := FingerprintID(cam.Fingerprint); err != nil {
			return err
		}
	}
	if cam.Fragment < 0 {
		return errors.New("stream: negative TLS fragment size")
	}
	return nil
}

// dial performs the camouflaged TLS handshake over raw, the TCP
// connection to the relay endpoint at addr. base is the carrier's TLS
// configuration: its pinned roots (if any) still verify the relay, and
// its server name is the fallback for cam.Name. It returns the TLS
// connection, its underlying transport, and the negotiated protocol,
// which the caller does not validate under this profile.
func (cam *Camouflage) dial(ctx context.Context, raw net.Conn, addr string, base *tls.Config) (net.Conn, net.Conn, string, error) {
	if err := cam.Validate(); err != nil {
		return nil, nil, "", err
	}
	if base == nil {
		base = &tls.Config{}
	}
	cfg := base.Clone()
	if cam.Name != "" {
		cfg.ServerName = cam.Name
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, nil, "", fmt.Errorf("stream: camouflage needs a server name: %w", err)
		}
		cfg.ServerName = host
	}
	// The ARC session authenticates the relay (spec D2), so an unverified
	// outer handshake costs no security. Keep verification where a CA is
	// pinned; the certificate must then match the cover name.
	if cfg.RootCAs == nil {
		cfg.InsecureSkipVerify = true
	}
	var hconn net.Conn = raw
	if cam.Fragment > 0 {
		hconn = &fragmentConn{Conn: raw, n: cam.Fragment}
	}
	if cam.Fingerprint != "" {
		id, err := FingerprintID(cam.Fingerprint)
		if err != nil {
			raw.Close()
			return nil, nil, "", err
		}
		uconn := utls.UClient(hconn, &utls.Config{
			ServerName:         cfg.ServerName,
			RootCAs:            cfg.RootCAs,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         utls.VersionTLS13,
			NextProtos:         browserALPN,
		}, id)
		if err := uconn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, nil, "", err
		}
		if f, ok := hconn.(*fragmentConn); ok {
			f.clear = true // post-handshake writes pass whole
		}
		return uconn, raw, uconn.ConnectionState().NegotiatedProtocol, nil
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = browserALPN
	conn := tls.Client(hconn, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, nil, "", err
	}
	if f, ok := hconn.(*fragmentConn); ok {
		f.clear = true // post-handshake writes pass whole
	}
	return conn, raw, conn.ConnectionState().NegotiatedProtocol, nil
}

// fragmentConn splits every write into pieces of at most n bytes while its
// segments are wanted, so the ClientHello spans several TCP segments and a
// middlebox that reads only the first cannot parse it. Once clear is set,
// writes pass through whole, as records after the handshake must.
type fragmentConn struct {
	net.Conn
	n     int
	clear bool
}

func (f *fragmentConn) Write(b []byte) (int, error) {
	if f.clear || len(b) <= f.n {
		return f.Conn.Write(b)
	}
	total := 0
	for len(b) > 0 {
		m := min(f.n, len(b))
		k, err := f.Conn.Write(b[:m])
		total += k
		if err != nil {
			return total, err
		}
		if k == 0 {
			return total, io.ErrShortWrite
		}
		b = b[k:]
	}
	return total, nil
}
