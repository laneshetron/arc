package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/diag"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// Config is a tunnel client, with its keys and token already loaded.
type Config struct {
	// Relay is the session's address. Carriers.Relay and
	// Carriers.FrontToken are taken from Relay and Token.
	Relay    netip.AddrPort
	RelayKey [32]byte // pinned static public key
	Token    []byte   // access token, also the front's admission token
	Static   crypto.StaticKey
	Carriers CarrierOptions

	Redundancy     session.RedundancyPolicy
	FEC            wire.FECMode
	SplitTCP       engine.SplitMode
	StatusInterval time.Duration // log each path's state this often; 0: off
	// Diagnostics, if set, is uploaded to the relay's operator whenever a
	// session is up and the relay accepts diagnostics.
	Diagnostics *diag.Journal
	Logger      *slog.Logger

	// OnNetwork applies the network the relay assigned: the platform's
	// address, MTU, routes and DNS. It runs each time a session becomes
	// active, since a reconnect may lease a different address. An error
	// ends the session.
	OnNetwork func(Network) error
}

// Network is what the relay assigned this client for the tunnel.
type Network struct {
	Addr netip.Prefix // the client's tunnel address and the tunnel network
	MTU  int          // the tunnel MTU
	// DNS is the relay's resolver for tunnel traffic, or the unspecified
	// address if it offers none.
	DNS netip.Addr
}

func networkOf(r wire.AuthResult) Network {
	return Network{
		Addr: netip.PrefixFrom(netip.AddrFrom4(r.IPv4), int(r.Prefix4)),
		MTU:  int(r.TunMTU),
		DNS:  netip.AddrFrom4(r.DNSv4),
	}
}

// Run opens the carriers and runs the client over dev until ctx ends or
// the session fails for good. The caller owns dev. Run returns nil when
// ctx is canceled.
func Run(ctx context.Context, cfg Config, dev engine.PacketDevice) error {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	co := cfg.Carriers
	co.Relay, co.FrontToken = cfg.Relay, string(cfg.Token)
	carriers, closeCarriers, err := OpenCarriers(ctx, log, co)
	if err != nil {
		return stopped(ctx, err)
	}
	defer closeCarriers()

	log.Info("starting", "relay", cfg.Relay, "version", Version(), "os", runtime.GOOS, "arch", runtime.GOARCH,
		"carriers", carrierNames(carriers), "split_tcp", cfg.SplitTCP, "share_diagnostics", cfg.Diagnostics != nil)
	ecfg := engine.ClientConfig{
		Session: session.ClientConfig{
			Static: cfg.Static, RelayPublic: cfg.RelayKey[:], Credential: cfg.Token, Redundancy: cfg.Redundancy, FEC: cfg.FEC,
		},
		Relay: cfg.Relay, Carriers: carriers, TUN: dev, Logger: log,
		StatusInterval: cfg.StatusInterval, SplitTCP: cfg.SplitTCP, Diagnostics: cfg.Diagnostics,
	}
	if cfg.OnNetwork != nil {
		ecfg.OnEstablished = func(r wire.AuthResult) error {
			if err := cfg.OnNetwork(networkOf(r)); err != nil {
				return fmt.Errorf("applying the tunnel network: %w", err)
			}
			return nil
		}
	}
	// RunClient sends its first handshake before it looks at ctx, so a
	// stop during setup must be caught here.
	if err := ctx.Err(); err != nil {
		return stopped(ctx, err)
	}
	return stopped(ctx, engine.RunClient(ctx, ecfg))
}

// stopped is err, or nil if err is the cancellation of ctx itself. A
// cancellation from elsewhere, such as an OnNetwork whose own operation
// was canceled, is still a failure.
func stopped(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	return err
}

// Version is the module version and VCS revision the binary was built
// from, as far as the build recorded them.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	v := info.Main.Version
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			v += " " + s.Value
		case "vcs.modified":
			if s.Value == "true" {
				v += "+dirty"
			}
		}
	}
	return v
}

func carrierNames(carriers []engine.Carrier) string {
	names := make([]string, len(carriers))
	for i, c := range carriers {
		names[i] = c.Name
	}
	return strings.Join(names, ",")
}
