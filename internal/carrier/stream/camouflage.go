package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// Camouflage configures the camouflage profile of the client carrier:
// the outer TLS presents itself as ordinary browser traffic to the relay
// endpoint rather than as an ARC carrier. The outer TLS is cover only —
// ARC's own authenticated session carries all security (spec D2) — so
// certificate verification is skipped under a cover name where no CA is
// pinned. This
// defeats passive filtering by observers of the ClientHello; it does not
// by itself survive an active prober, which must be answered by a
// fail-closed relay (a later profile).
type Camouflage struct {
	// Name is presented as the TLS server name (SNI): a host the network
	// permits, not the relay's own name. Empty means the TLS
	// configuration's server name, or the endpoint's host, verified as by
	// the plain carrier. With a Name, verification is skipped unless a CA
	// is pinned, which then verifies against this name, so a relay's
	// certificate must list it.
	Name string
	// Fingerprint shapes the ClientHello as a browser's: "chrome",
	// "edge", "safari", "ios", or "firefox". Empty uses Go's ordinary
	// TLS, whose ClientHello is distinctive.
	Fingerprint string
	// Fragment, when nonzero, sends the ClientHello in TCP segments of
	// at most this many bytes, defeating middleboxes that read the whole
	// server name out of the first segment.
	Fragment int
	// ALPN overrides the browser offer. The front client needs HTTP/1.1
	// negotiated, for its upgrade; nil offers the browser set, and an
	// empty, non-nil list offers no ALPN at all. Under a
	// Fingerprint the override is written into the browser's own ALPN
	// extension (see fingerprintSpec), which otherwise wins.
	ALPN []string
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

// Handshake performs the camouflaged TLS handshake over raw, an
// established connection to the endpoint named by addr, and returns the
// TLS connection and its negotiated protocol, which callers under this
// profile do not validate. base carries any pinned roots and the
// fallback server name. On failure raw is left open: the caller closes
// it, and the byte counts on a tracking wrapper, if any, survive the
// classification. The profiler uses this as the probe client for
// canaries (network-profiling.md §5); relays are never probed (its P1).
func (cam *Camouflage) Handshake(ctx context.Context, raw net.Conn, addr string, base *tls.Config) (net.Conn, string, error) {
	if cam.Fragment < 0 {
		return nil, "", errors.New("stream: negative TLS fragment size")
	}
	cfg, err := clientConfig(base, addr)
	if err != nil {
		return nil, "", err
	}
	if cam.Name != "" {
		cfg.ServerName = cam.Name
		// A cover name is not the relay's, so no public CA vouches for
		// it; the ARC session authenticates the relay (spec D2), so an
		// unverified outer handshake costs no security. A pinned CA still
		// verifies, and the certificate must then list the cover name.
		// Without a cover name the relay's own name is presented and
		// verified as by the plain carrier.
		if cfg.RootCAs == nil {
			cfg.InsecureSkipVerify = true
		}
	}
	// The front client overrides the ALPN offer (it needs HTTP/1.1
	// negotiated); everyone else offers the browser set.
	protos := cam.ALPN
	if protos == nil {
		protos = browserALPN
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = protos
	var hconn net.Conn = raw
	var frag *fragmentConn
	if cam.Fragment > 0 {
		frag = &fragmentConn{Conn: raw, n: cam.Fragment}
		hconn = frag
	}
	var (
		conn interface {
			net.Conn
			HandshakeContext(context.Context) error
		}
		alpn func() string
	)
	if cam.Fingerprint != "" {
		id, err := FingerprintID(cam.Fingerprint)
		if err != nil {
			return nil, "", err
		}
		ucfg, err := utlsConfig(cfg)
		if err != nil {
			return nil, "", err
		}
		var uconn *utls.UConn
		if cam.ALPN == nil {
			uconn = utls.UClient(hconn, ucfg, id)
		} else {
			// A preset's ALPN extension replaces the configuration's
			// NextProtos, so an override must be written into the
			// preset's own extension.
			spec, err := fingerprintSpec(id, protos)
			if err != nil {
				return nil, "", err
			}
			uconn = utls.UClient(hconn, ucfg, utls.HelloCustom)
			if err := uconn.ApplyPreset(&spec); err != nil {
				return nil, "", err
			}
		}
		conn, alpn = uconn, func() string { return uconn.ConnectionState().NegotiatedProtocol }
	} else {
		tconn := tls.Client(hconn, cfg)
		conn, alpn = tconn, func() string { return tconn.ConnectionState().NegotiatedProtocol }
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, "", err
	}
	if frag != nil {
		frag.clear = true // post-handshake writes pass whole
	}
	return conn, alpn(), nil
}

// fingerprintSpec returns the ClientHello of browser id offering protos
// as its ALPN. The rest of the hello keeps the browser's shape, except
// that ALPS (application settings) is dropped for protocols no longer
// offered: Chromium sends ALPS only for offered protocols, so a
// Chrome-shaped hello with HTTP/1.1-only ALPN carries none (as Chrome's
// own HTTP/1.1-only connections, such as a WebSocket's, do).
func fingerprintSpec(id utls.ClientHelloID, protos []string) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return spec, err
	}
	offered := func(ps []string) bool {
		for _, p := range ps {
			if !slices.Contains(protos, p) {
				return false
			}
		}
		return true
	}
	found := false
	exts := spec.Extensions[:0]
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			found = true
			if len(protos) == 0 {
				continue // RFC 7301 §3.1: an empty list is omitted, as Go TLS does
			}
			e.AlpnProtocols = slices.Clone(protos)
		case *utls.ApplicationSettingsExtension:
			if !offered(e.SupportedProtocols) {
				continue
			}
		case *utls.ApplicationSettingsExtensionNew:
			if !offered(e.SupportedProtocols) {
				continue
			}
		}
		exts = append(exts, ext)
	}
	if !found {
		return spec, fmt.Errorf("stream: TLS fingerprint %s offers no ALPN to override", id.Str())
	}
	spec.Extensions = exts
	return spec, nil
}

// utlsConfig carries cfg over to uTLS, whose configuration is a separate
// type. Fields that cannot be carried and would weaken or change the
// handshake if dropped are refused rather than silently ignored.
func utlsConfig(cfg *tls.Config) (*utls.Config, error) {
	switch {
	case cfg.VerifyConnection != nil:
		return nil, errors.New("stream: TLS fingerprint cannot honor VerifyConnection; use VerifyPeerCertificate")
	case len(cfg.Certificates) > 0, cfg.GetClientCertificate != nil:
		return nil, errors.New("stream: TLS fingerprint does not support client certificates")
	}
	return &utls.Config{
		ServerName:            cfg.ServerName,
		RootCAs:               cfg.RootCAs,
		InsecureSkipVerify:    cfg.InsecureSkipVerify,
		VerifyPeerCertificate: cfg.VerifyPeerCertificate,
		KeyLogWriter:          cfg.KeyLogWriter,
		Rand:                  cfg.Rand,
		Time:                  cfg.Time,
		MinVersion:            cfg.MinVersion,
		NextProtos:            cfg.NextProtos,
	}, nil
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
