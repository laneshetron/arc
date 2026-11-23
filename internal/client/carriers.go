// Package client sets up and runs an ARC tunnel client: it opens the
// carriers, runs the session engine over a packet device the caller
// provides, and reports the network the relay assigns, so that each
// platform can apply it its own way (spec §17).
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
	"github.com/laneshetron/arc/internal/carrier/stream"
	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/tun"
)

// CarrierOptions choose a client's carriers.
type CarrierOptions struct {
	Relay     netip.AddrPort
	Binds     []string
	NoOffload bool
	NoUDP     bool // only the TLS and front carriers
	// Censorship holds UDP back from any relay address a stream carrier
	// uses: under TSPU, UDP to foreign hosting gets the whole address
	// banned for minutes, stream carriers included.
	Censorship bool
	FullTunnel bool
	Mark       uint32

	TLS, TLSCA, TLSName      string
	TLSCover, TLSFingerprint string
	TLSFragment              int
	Front, FrontToken        string
	RotateBytes              int64 // stream connections rotate after this many bytes received; 0: learn
}

// OpenCarriers opens a UDP carrier per interface, unless NoUDP, and a TLS
// or front carrier per interface when asked. The returned function closes
// them. Ending ctx stops setup: OpenCarriers then returns ctx's error.
func OpenCarriers(ctx context.Context, log *slog.Logger, o CarrierOptions) ([]engine.Carrier, func(), error) {
	var closers []io.Closer
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i].Close()
		}
	}
	fail := func(err error) ([]engine.Carrier, func(), error) {
		closeAll()
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if o.NoUDP && o.TLS == "" && o.Front == "" {
		return fail(errors.New("-no-udp needs -tls or -front"))
	}
	if !o.Relay.Addr().Unmap().Is4() {
		return fail(fmt.Errorf("relay %v: only IPv4 relays are supported", o.Relay.Addr()))
	}
	// Resolve each stream endpoint once, before full-tunnel DNS can route
	// lookups into the tunnel the carrier exists to rescue. The same
	// answer decides the UDP hold-back and is what the stream carrier
	// dials, so a second lookup cannot disagree with the first. A stream
	// carrier whose lookup failed keeps resolving when it connects.
	resolved := map[string]resolution{}
	for _, addr := range []string{o.TLS, o.Front} {
		if _, done := resolved[addr]; addr != "" && !done {
			lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			eps, err := resolveEndpoints(lctx, addr)
			cancel()
			if ctx.Err() != nil {
				return fail(ctx.Err())
			}
			resolved[addr] = resolution{eps, err}
		}
	}
	if o.Censorship && !o.NoUDP && sharesStreamAddr(log, o.Relay, resolved) {
		log.Info("censorship posture: no UDP to the relay; a UDP ban on its address would take the TLS carriers down too",
			"relay", o.Relay.Addr())
		o.NoUDP = true
	}
	binds := append([]string(nil), o.Binds...)
	// Each carrier talks only to the relay, so its socket is connected.
	sockOpts := udp.Options{NoOffload: o.NoOffload, Peer: o.Relay}
	if len(binds) == 0 {
		binds = []string{""}
	}
	if o.FullTunnel && tun.PolicyRouting {
		sockOpts.Mark = o.Mark
	} else if o.FullTunnel {
		// Without marks, an unbound carrier would route into the tunnel
		// it carries. This binding doesn't follow later changes of the
		// default route; pass -bind for each interface to use them all.
		for i, iface := range binds {
			if iface == "" {
				var err error
				if binds[i], err = tun.Underlay(); err != nil {
					return fail(err)
				}
				log.Info("binding carrier to the default route's interface", "interface", binds[i])
			}
		}
	}
	carriers := make([]engine.Carrier, 0, len(binds))
	for _, iface := range binds {
		if o.NoUDP {
			break
		}
		name := iface
		if name == "" {
			name = "default"
		}
		sockOpts.Device = iface
		sockOpts.OnReconnect = func(local netip.AddrPort) {
			log.Info("carrier reconnected to the relay", "carrier", name, "local", local)
		}
		conn, err := udp.Listen(netip.MustParseAddrPort("0.0.0.0:0"), sockOpts)
		if err != nil {
			return fail(fmt.Errorf("open carrier %q: %w", iface, err))
		}
		closers = append(closers, conn)
		log.Info("carrier", "carrier", name, "local", conn.LocalAddr())
		carriers = append(carriers, engine.Carrier{Name: name, Conn: conn})
	}
	var camo *stream.Camouflage
	if o.TLSCover != "" || o.TLSFingerprint != "" || o.TLSFragment != 0 {
		camo = &stream.Camouflage{Name: o.TLSCover, Fingerprint: o.TLSFingerprint, Fragment: o.TLSFragment}
		if err := camo.Validate(); err != nil {
			return fail(fmt.Errorf("-tls-fingerprint/-tls-fragment: %w", err))
		}
		log.Info("tls carrier will pose as ordinary web traffic",
			"cover", camo.Name, "fingerprint", camo.Fingerprint, "fragment", camo.Fragment)
	}
	for _, sc := range []struct {
		addr, kind string
		front      *stream.FrontDialOptions
	}{
		{o.TLS, "tls", nil},
		{o.Front, "front", &stream.FrontDialOptions{Token: o.FrontToken}},
	} {
		if sc.addr == "" {
			continue
		}
		tlsConfig, err := clientTLS(sc.addr, o.TLSCA, o.TLSName)
		if err != nil {
			return fail(err)
		}
		endpoints, err := resolved[sc.addr].eps, resolved[sc.addr].err
		if err != nil {
			log.Warn("resolving the relay's "+sc.kind+" endpoint; retrying when the carrier connects", "relay", sc.addr, "err", err)
		}
		for _, iface := range binds {
			name := iface
			if name == "" {
				name = "default"
			}
			name += "/" + sc.kind
			conn := stream.Dial(stream.ClientOptions{
				Addr: sc.addr, Endpoints: endpoints, TLS: tlsConfig, Peer: o.Relay,
				Camouflage: camo, Front: sc.front, RotateBytes: o.RotateBytes,
				Sockopt: sockopt.Options{Mark: sockOpts.Mark, Device: iface},
				OnState: func(err error) {
					if err != nil {
						log.Debug(sc.kind+" carrier", "carrier", name, "err", err)
					}
				},
				OnLearn: func(dest netip.AddrPort, budget int64) {
					log.Info("connections stall at a byte cap; rotating them ahead of it",
						"carrier", name, "relay", dest, "budget_bytes", budget)
				},
			})
			closers = append(closers, conn)
			carriers = append(carriers, engine.Carrier{Name: name, Conn: conn, Fallback: true})
		}
	}
	return carriers, closeAll, nil
}

// resolution is one lookup of a stream endpoint.
type resolution struct {
	eps []netip.AddrPort
	err error
}

// resolveEndpoints is stream.ResolveEndpoints; tests replace it.
var resolveEndpoints = stream.ResolveEndpoints

// sharesStreamAddr reports whether a stream carrier (-tls or -front)
// reaches the relay at relay's address, judged by the resolutions the
// stream carriers will dial. A stream endpoint whose lookup failed counts
// as shared: it resolves again when it connects, perhaps to that address,
// and the answer that risks a ban is the one to avoid.
func sharesStreamAddr(log *slog.Logger, relay netip.AddrPort, resolved map[string]resolution) bool {
	for addr, r := range resolved {
		if r.err != nil {
			log.Warn("censorship posture: cannot resolve the stream endpoint; presuming it shares the relay's address", "endpoint", addr, "err", r.err)
			return true
		}
		for _, ep := range r.eps {
			if ep.Addr().Unmap() == relay.Addr().Unmap() {
				return true
			}
		}
	}
	return false
}

// clientTLS builds the TLS configuration for -tls: the system roots or the
// -tls-ca file, and the server name from -tls-server-name or the -tls host.
func clientTLS(addr, caFile, serverName string) (*tls.Config, error) {
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("-tls: %w", err)
		}
		serverName = host
	}
	cfg := &tls.Config{ServerName: serverName}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-tls-ca: no certificates in %s", caFile)
		}
	}
	return cfg, nil
}
