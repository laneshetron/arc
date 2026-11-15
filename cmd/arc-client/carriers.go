package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
	"github.com/laneshetron/arc/internal/carrier/stream"
	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/tun"
)

// carrierOptions are the flags that choose a client's carriers.
type carrierOptions struct {
	Relay      netip.AddrPort
	Binds      []string
	NoOffload  bool
	FullTunnel bool
	Mark       uint32

	TLS, TLSCA, TLSName      string
	TLSCover, TLSFingerprint string
	TLSFragment              int
	Front, FrontToken        string
}

// openCarriers opens a UDP carrier per interface, and a TLS or front
// carrier per interface when asked. The returned function closes them.
func openCarriers(log *slog.Logger, o carrierOptions) ([]engine.Carrier, func(), error) {
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
		// Resolve before full-tunnel DNS can route lookups into the
		// tunnel the carrier exists to rescue. The UDP carriers may work
		// regardless; the stream carrier keeps resolving the relay until
		// it can.
		bootstrap, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		endpoints, err := stream.ResolveEndpoints(bootstrap, sc.addr)
		cancel()
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
				Camouflage: camo, Front: sc.front,
				Sockopt: sockopt.Options{Mark: sockOpts.Mark, Device: iface},
				OnState: func(err error) {
					if err != nil {
						log.Debug(sc.kind+" carrier", "carrier", name, "err", err)
					}
				},
			})
			closers = append(closers, conn)
			carriers = append(carriers, engine.Carrier{Name: name, Conn: conn, Fallback: true})
		}
	}
	return carriers, closeAll, nil
}
