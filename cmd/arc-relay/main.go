// Command arc-relay terminates ARC sessions and forwards their traffic
// through a TUN interface.
//
//	arc-relay genkey > relay.key
//	arc-relay pubkey < relay.key
//	arc-relay run -key-file relay.key -tokens-file tokens -network 10.77.0.1/16
//
// The relay does not configure forwarding or NAT for the tunnel network;
// enable net.ipv4.ip_forward and add a masquerade rule for the network on
// the egress interface (see test/netns/e2e.sh), along with whatever egress
// policy the deployment requires (spec §17.2).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/keyfile"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/tun"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = genkey()
	case "pubkey":
		err = pubkey()
	case "run":
		err = run(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "arc-relay:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: arc-relay genkey | pubkey | run [flags]")
	os.Exit(2)
}

func genkey() error {
	k, err := crypto.GenerateStaticKey(nil)
	if err != nil {
		return err
	}
	fmt.Println(keyfile.Encode(k.Private))
	return nil
}

func pubkey() error {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	priv, err := keyfile.Decode32(string(b))
	if err != nil {
		return err
	}
	k, err := keyfile.StaticFromPrivate(priv)
	if err != nil {
		return err
	}
	fmt.Println(keyfile.Encode(k.Public))
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:4433", "UDP address to listen on")
	keyFile := fs.String("key-file", "relay.key", "relay static private key (from genkey)")
	resetFile := fs.String("reset-secret-file", "reset.secret", "stateless reset secret; created if missing, keep it across restarts")
	tokensFile := fs.String("tokens-file", "tokens", "accepted client tokens, one per line")
	tunName := fs.String("tun", "arc0", "TUN interface name")
	network := fs.String("network", "10.77.0.1/16", "relay tunnel address and client network")
	mtu := fs.Int("mtu", 1280, "tunnel MTU")
	dns := fs.String("dns", "", "IPv4 resolver to offer clients")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	listenAddr, err := netip.ParseAddrPort(*listen)
	if err != nil {
		return err
	}
	netPrefix, err := netip.ParsePrefix(*network)
	if err != nil {
		return err
	}
	static, err := keyfile.LoadStatic(*keyFile)
	if err != nil {
		return err
	}
	resetSecret, err := keyfile.LoadOrCreateSecret(*resetFile)
	if err != nil {
		return err
	}
	lines, err := keyfile.ReadLines(*tokensFile)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("%s: no tokens", *tokensFile)
	}
	gwCfg := gateway.Config{
		Network: netPrefix, TunMTU: uint16(*mtu),
		Keepalive: session.DefaultKeepalive, Idle: session.DefaultIdleTimeout,
	}
	for _, l := range lines {
		gwCfg.Tokens = append(gwCfg.Tokens, []byte(l))
	}
	if *dns != "" {
		if gwCfg.DNS, err = netip.ParseAddr(*dns); err != nil {
			return err
		}
	}
	gw, err := gateway.New(gwCfg)
	if err != nil {
		return err
	}

	dev, err := tun.Create(*tunName, *mtu)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer dev.Close()
	if err := dev.Configure(netPrefix, *mtu); err != nil {
		return fmt.Errorf("configure %s: %w", dev.Name(), err)
	}
	conn, err := udp.Listen(listenAddr, udp.Options{})
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Info("relay listening", "addr", conn.LocalAddr(), "tun", dev.Name(), "network", netPrefix,
		"public_key", keyfile.Encode(static.Public))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = engine.RunRelay(ctx, engine.RelayConfig{
		Session: session.RelayConfig{Static: static, ResetSecret: resetSecret, IdleTimeout: gwCfg.Idle + 10*time.Second},
		Conn:    conn, TUN: dev, Gateway: gw, Logger: log,
	})
	if ctx.Err() != nil {
		return nil
	}
	return err
}
