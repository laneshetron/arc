// Command arc-client connects to an ARC relay and brings up a TUN
// interface for the tunnel.
//
//	arc-client run -relay 192.0.2.1:4433 -relay-key BASE64 -token-file token -full-tunnel
//	arc-client run -relay 192.0.2.1:4433 -relay-key BASE64 -token-file token -route 198.51.100.0/24
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/keyfile"
	"github.com/laneshetron/arc/internal/profiling"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/tun"
	"github.com/laneshetron/arc/internal/wire"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: arc-client run [flags]")
		os.Exit(2)
	}
	if err := run(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "arc-client:", err)
		os.Exit(1)
	}
}

type prefixList []netip.Prefix

func (p *prefixList) String() string { return fmt.Sprint(*p) }
func (p *prefixList) Set(s string) error {
	v, err := netip.ParsePrefix(s)
	if err != nil {
		return err
	}
	*p = append(*p, v)
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	relay := fs.String("relay", "", "relay UDP address, host:port")
	relayKey := fs.String("relay-key", "", "relay static public key (base64), pinned")
	tokenFile := fs.String("token-file", "token", "file containing the access token")
	keyFile := fs.String("key-file", "", "client static private key; a new one is generated if empty")
	tunName := fs.String("tun", "arc0", "TUN interface name")
	fullTunnel := fs.Bool("full-tunnel", false, "route all traffic through the tunnel")
	var routes prefixList
	fs.Var(&routes, "route", "route this prefix through the tunnel (repeatable)")
	var binds []string
	fs.Func("bind", "bind a carrier socket to this interface (repeatable)", func(iface string) error {
		if iface == "" {
			return errors.New("interface name must not be empty")
		}
		binds = append(binds, iface)
		return nil
	})
	redundancy := session.RedundancyOff
	fs.Func("redundancy", "send traffic on two paths at once: off, auto (while the best path loses over 1%), or always; needs two -bind interfaces", func(v string) error {
		switch v {
		case "off":
			redundancy = session.RedundancyOff
		case "auto":
			redundancy = session.RedundancyAuto
		case "always":
			redundancy = session.RedundancyAlways
		default:
			return errors.New("want off, auto, or always")
		}
		return nil
	})
	status := fs.Duration("status", 0, "log each path's state at this interval (0: off)")
	noOffload := fs.Bool("no-offload", false, "send and receive without UDP GSO/GRO, for comparison")
	mark := fs.Uint("mark", 0x5243, "fwmark for carrier sockets, used by -full-tunnel")
	table := fs.Int("table", 5243, "routing table for -full-tunnel")
	prof := profiling.Register(fs)
	fs.Parse(args)
	stopProfiles, err := prof.Start()
	if err != nil {
		return err
	}
	defer stopProfiles()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	relayAddr, err := netip.ParseAddrPort(*relay)
	if err != nil {
		return fmt.Errorf("-relay: %w", err)
	}
	pin, err := keyfile.Decode32(*relayKey)
	if err != nil {
		return fmt.Errorf("-relay-key: %w", err)
	}
	tokens, err := keyfile.ReadLines(*tokenFile)
	if err != nil {
		return err
	}
	if len(tokens) != 1 {
		return fmt.Errorf("%s: want exactly one token", *tokenFile)
	}
	var static crypto.StaticKey
	if *keyFile != "" {
		static, err = keyfile.LoadStatic(*keyFile)
	} else {
		static, err = crypto.GenerateStaticKey(nil)
	}
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Contains(relayAddr.Addr()) {
			return fmt.Errorf("-route %v contains the relay address; that would loop the tunnel through itself", r)
		}
	}
	if !*fullTunnel && len(routes) == 0 {
		log.Warn("no -route or -full-tunnel given; only the tunnel network is reachable")
	}

	dev, err := tun.Create(*tunName, 1280)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer dev.Close()
	sockOpts := udp.Options{NoOffload: *noOffload}
	if *fullTunnel {
		sockOpts.Mark = uint32(*mark)
	}
	if len(binds) == 0 {
		binds = []string{""}
	}
	carriers := make([]engine.Carrier, 0, len(binds))
	for _, iface := range binds {
		sockOpts.Device = iface
		conn, err := udp.Listen(netip.MustParseAddrPort("0.0.0.0:0"), sockOpts)
		if err != nil {
			return fmt.Errorf("open carrier %q: %w", iface, err)
		}
		defer conn.Close()
		name := iface
		if name == "" {
			name = "default"
		}
		carriers = append(carriers, engine.Carrier{Name: name, Conn: conn})
	}

	var cleanup func() error
	defer func() {
		if cleanup != nil {
			if err := cleanup(); err != nil {
				log.Warn("removing routing rules", "err", err)
			}
		}
	}()
	onEstablished := func(r wire.AuthResult) error {
		addr := netip.PrefixFrom(netip.AddrFrom4(r.IPv4), int(r.Prefix4))
		if err := dev.Configure(addr, int(r.TunMTU)); err != nil {
			return fmt.Errorf("configure %s: %w", dev.Name(), err)
		}
		for _, p := range routes {
			if err := dev.AddRoute(p); err != nil {
				return fmt.Errorf("route %v: %w", p, err)
			}
		}
		if *fullTunnel && cleanup == nil {
			if cleanup, err = dev.FullTunnel(uint32(*mark), *table); err != nil {
				return err
			}
		}
		if r.DNSv4 != [4]byte{} {
			log.Info("relay offers a resolver; configure it to avoid DNS leaks", "dns", netip.AddrFrom4(r.DNSv4))
		}
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting", "relay", relayAddr, "tun", dev.Name(), "full_tunnel", *fullTunnel,
		"routes", strings.Trim(routes.String(), "[]"))
	err = engine.RunClient(ctx, engine.ClientConfig{
		Session: session.ClientConfig{
			Static: static, RelayPublic: pin[:], Credential: []byte(tokens[0]), Redundancy: redundancy,
		},
		Relay: relayAddr, Carriers: carriers, TUN: dev, OnEstablished: onEstablished, Logger: log,
		StatusInterval: *status,
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
