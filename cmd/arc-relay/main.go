// Command arc-relay terminates ARC sessions and forwards their traffic
// through a TUN interface.
//
//	arc-relay genkey > relay.key
//	arc-relay pubkey < relay.key
//	arc-relay run -key-file relay.key -tokens-file tokens -network 10.77.0.1/16
//
// The tokens file lists the accounts allowed in, one credential per line,
// as NAME TOKEN [relay]. Clients of one account reach each other's tunnel
// addresses; clients of different accounts never do. "relay" lets an
// account's clients reach the relay host: its tunnel address, and the
// addresses of its interfaces, by IP forwarding or split TCP. A bare TOKEN
// line is an account of its own, without relay access. -deny keeps every
// account from networks private to the operator:
//
//	arc-relay run ... -deny 172.31.0.0/16
//
// To change accounts while the relay runs, keep them in a store instead
// (seeded from the tokens file when empty), and use arc-relay accounts:
//
//	arc-relay run ... -accounts-store file:/var/lib/arc/accounts
//	arc-relay accounts add-token lane laptop
//
// For networks that block UDP, also accept TLS/TCP carriers (clients use
// -tls and, for a self-signed certificate, -tls-ca relay.crt):
//
//	arc-relay gencert -hosts relay.example.com,203.0.113.5
//	arc-relay run ... -tls-listen 0.0.0.0:443
//
// Or front the carriers with an ordinary HTTPS site (clients use -front):
// every visitor gets cover content, and an authenticated client's request
// upgrades into the stream carrier.
//
//	arc-relay run ... -front-listen 0.0.0.0:443 -front-site cover/
//
// The relay does not configure forwarding or NAT for the tunnel network;
// enable net.ipv4.ip_forward and add a masquerade rule for the network on
// the egress interface (see test/netns/e2e.sh), along with whatever egress
// policy the deployment requires (spec §17.2).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/carrier/stream"
	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/diag"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/keyfile"
	"github.com/laneshetron/arc/internal/profiling"
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
	case "gencert":
		err = gencert(os.Args[2:])
	case "run":
		err = run(os.Args[2:])
	case "accounts":
		err = accountsCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "arc-relay:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: arc-relay genkey | pubkey | gencert [flags] | run [flags] | accounts [flags] COMMAND")
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

// gencert writes a self-signed certificate and key for -tls-listen.
// Clients trust it with -tls-ca pointing at the certificate.
func gencert(args []string) error {
	fs := flag.NewFlagSet("gencert", flag.ExitOnError)
	hosts := fs.String("hosts", "", "comma-separated DNS names and IP addresses clients use to reach the relay")
	certFile := fs.String("cert", "relay.crt", "certificate output (PEM)")
	keyFile := fs.String("key", "relay.tls.key", "private key output (PEM)")
	days := fs.Int("days", 365, "validity in days")
	fs.Parse(args)
	if *hosts == "" {
		return errors.New("gencert: -hosts is required")
	}
	certPEM, keyPEM, err := stream.SelfSigned(strings.Split(*hosts, ","), time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*certFile, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(*keyFile, keyPEM, 0o600)
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:4433", "UDP address to listen on")
	keyFile := fs.String("key-file", "relay.key", "relay static private key (from genkey)")
	resetFile := fs.String("reset-secret-file", "reset.secret", "stateless reset secret; created if missing, keep it across restarts")
	storeURL := fs.String("accounts-store", "", "keep accounts in this store instead of reading -tokens-file once: file:PATH. The relay then changes accounts while it runs (arc-relay accounts), and authenticates only while it holds the store's writer lease; an empty store is seeded from -tokens-file, if it exists")
	controlDir := fs.String("accounts-control", defaultControlDir, "with -accounts-store: directory for the control socket and the writer lock")
	holder := fs.String("accounts-holder", defaultHolder(), "with -accounts-store: this relay's name in the writer lease, for operators")
	accountsLease := fs.Duration("accounts-lease", accounts.DefaultLease, "with -accounts-store: writer lease length, the longest a store outage goes unnoticed by clients, and the longest a revocation takes to reach a relay that lost the store")
	tokensFile := fs.String("tokens-file", "tokens", "client accounts, one credential per line: NAME TOKEN [relay], or a bare TOKEN for an account of its own; accounts cannot reach each other's clients, and only \"relay\" accounts reach the relay's tunnel address")
	var deny []netip.Prefix
	fs.Func("deny", "IPv4 prefix no client may reach, by IP forwarding or split TCP, e.g. the relay's VPC (repeatable); the relay host's own addresses stay reachable for \"relay\" accounts", func(v string) error {
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("want an IPv4 prefix, e.g. 172.31.0.0/16")
		}
		deny = append(deny, p.Masked())
		return nil
	})
	tunName := fs.String("tun", "arc0", "TUN interface name")
	diagDir := fs.String("diagnostics-dir", "", "accept clients' diagnostics uploads (arc-client -share-diagnostics) and keep each in this directory, under its account's name (default: off)")
	network := fs.String("network", "10.77.0.1/16", "relay tunnel address and client network")
	mtu := fs.Int("mtu", 1280, "tunnel MTU")
	dns := fs.String("dns", "", "IPv4 resolver to offer clients")
	noOffload := fs.Bool("no-offload", false, "send and receive without UDP GSO/GRO, for comparison")
	status := fs.Duration("status", 0, "log each session's paths at this interval (0: off)")
	tlsListen := fs.String("tls-listen", "", "TCP address for TLS/TCP carriers, e.g. 0.0.0.0:443 (default: off)")
	tlsCamouflage := fs.Bool("tls-camouflage", false, "accept TLS carrier connections that present a browser's ALPN (h2, http/1.1) instead of arc/1, as clients posing as browsers do; the certificate should cover those cover names")
	frontListen := fs.String("front-listen", "", "TCP address for the fail-closed HTTPS front, e.g. 0.0.0.0:443 (default: off; exclusive with -tls-listen): an ordinary HTTPS site to everyone, the stream carrier to requests authenticated by a token from -tokens-file")
	frontSite := fs.String("front-site", "", "directory of cover content for -front-listen (default: a minimal built-in page)")
	tlsCert := fs.String("tls-cert", "relay.crt", "TLS certificate (PEM) for -tls-listen")
	tlsKey := fs.String("tls-key", "relay.tls.key", "TLS private key (PEM) for -tls-listen")
	noFEC := fs.Bool("no-fec", false, "decline forward error correction for clients' traffic")
	noStreams := fs.Bool("no-split-tcp", false, "decline to connect clients' TCP streams (split TCP)")
	noRedundancy := fs.Bool("no-redundancy", false, "decline clients' requests to duplicate downlink traffic on two paths")
	maxSessions := fs.Int("max-sessions", 1024, "maximum authenticated sessions (pending handshakes have a separate budget)")
	maxPending := fs.Int("max-pending", 4096, "maximum pending Noise handshakes")
	handshakeRate := fs.Int("handshakes-per-second", 256, "global Noise handshake work rate and burst")
	sourceRate := fs.Int("handshakes-per-source", 8, "per-source-IP Noise handshake work rate and burst")
	maxTLS := fs.Int("max-tls-conns", 4096, "maximum pending and established TLS carrier connections combined (with -front-listen: all front connections, visitors included)")
	maxTLSHandshakes := fs.Int("max-tls-handshakes", 128, "maximum pending TLS handshakes (with -front-listen: front connections that are not carriers, visitors included)")
	maxTLSPerSource := fs.Int("max-tls-conns-per-source", 64, "maximum TLS carrier connections per TCP peer IP (with -front-listen: front connections, visitors included)")
	tlsHandshakeTimeout := fs.Duration("tls-handshake-timeout", 10*time.Second, "time allowed for a TLS carrier handshake (with -front-listen: also each request's headers); lossy networks need several seconds")
	prof := profiling.Register(fs)
	fs.Parse(args)
	if *maxSessions <= 0 || *maxPending <= 0 || *handshakeRate <= 0 || *sourceRate <= 0 || *maxTLS <= 0 || *maxTLSHandshakes <= 0 || *maxTLSPerSource <= 0 || *tlsHandshakeTimeout <= 0 {
		return errors.New("session, handshake and TLS limits must be positive")
	}
	stopProfiles, err := prof.Start()
	if err != nil {
		return err
	}
	defer stopProfiles()

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
	var staticAccounts []gateway.Account
	var writer *accounts.Writer
	if *storeURL == "" {
		lines, err := keyfile.ReadLines(*tokensFile)
		if err != nil {
			return err
		}
		if len(lines) == 0 {
			return fmt.Errorf("%s: no tokens", *tokensFile)
		}
		if staticAccounts, err = gateway.ParseAccounts(lines); err != nil {
			return fmt.Errorf("%s: %w", *tokensFile, err)
		}
	} else {
		if *frontListen != "" {
			return errors.New("-front-listen needs -tokens-file: the front admits by plaintext tokens, which -accounts-store does not keep")
		}
		store, err := openStore(*storeURL)
		if err != nil {
			return err
		}
		writer = &accounts.Writer{Store: store, Holder: *holder, Lease: *accountsLease, Log: log,
			Seed: func() (*accounts.State, error) {
				data, err := os.ReadFile(*tokensFile)
				if errors.Is(err, os.ErrNotExist) {
					return &accounts.State{}, nil
				}
				if err != nil {
					return nil, err
				}
				log.Info("accounts store is empty; seeding it from the tokens file", "file", *tokensFile)
				return accounts.Parse(data, time.Now())
			}}
	}
	gwCfg := gateway.Config{
		Network: netPrefix, TunMTU: uint16(*mtu),
		Keepalive: session.DefaultKeepalive, Idle: session.DefaultIdleTimeout,
		Accounts: staticAccounts, Deny: deny,
	}
	if writer != nil {
		gwCfg.Gate = writer.Serving
	}
	if gwCfg.HostAddrs, err = hostAddrs(); err != nil {
		return err
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if writer != nil {
		ctl := accounts.Control{Dir: *controlDir}
		unlock, err := ctl.Lock()
		if err != nil {
			return fmt.Errorf("-accounts-control %s: %w", *controlDir, err)
		}
		defer unlock()
		writer.OnState, writer.OnLost = gw.Apply, gw.Suspend
		writer.TokenFile = ctl.TokenFile()
		done := make(chan struct{})
		go func() { writer.Run(ctx); close(done) }()
		defer func() { stop(); <-done }() // release the lease on the way out
		go func() {
			if err := ctl.Serve(ctx, writer); err != nil {
				log.Error("accounts control socket stopped", "err", err)
			}
		}()
	}

	dev, err := tun.Create(*tunName, *mtu)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer dev.Close()
	if err := dev.Configure(netPrefix, *mtu); err != nil {
		return fmt.Errorf("configure %s: %w", dev.Name(), err)
	}
	conn, err := udp.Listen(listenAddr, udp.Options{NoOffload: *noOffload})
	if err != nil {
		return err
	}
	defer conn.Close()

	var streams engine.DatagramConn
	tlsAddr := ""
	attempts := engine.NewAttemptLog(log)
	if *tlsListen != "" && *frontListen != "" {
		return errors.New("-tls-listen and -front-listen are mutually exclusive: the engine carries one stream carrier")
	}
	if *tlsListen != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return fmt.Errorf("-tls-listen: %w", err)
		}
		ln, err := stream.Listen(*tlsListen, stream.ListenerOptions{
			TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Camouflage: *tlsCamouflage,
			MaxConns: *maxTLS, MaxPending: *maxTLSHandshakes, MaxConnsPerSource: *maxTLSPerSource,
			HandshakeTimeout: *tlsHandshakeTimeout, Report: attempts.TLS,
		})
		if err != nil {
			return err
		}
		defer ln.Close()
		streams, tlsAddr = ln, ln.Addr().String()
	} else if *frontListen != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return fmt.Errorf("-front-listen: %w", err)
		}
		var site http.Handler
		if *frontSite != "" {
			site = http.FileServer(http.Dir(*frontSite))
		}
		front, err := stream.ListenFront(*frontListen, stream.FrontOptions{
			TLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
			Tokens: gw.Tokens(), Site: site,
			MaxConns: *maxTLS, MaxPending: *maxTLSHandshakes, MaxConnsPerSource: *maxTLSPerSource,
			HandshakeTimeout: *tlsHandshakeTimeout, Report: attempts.TLS,
		})
		if err != nil {
			return err
		}
		defer front.Close()
		streams, tlsAddr = front, front.Addr().String()
	}

	log.Info("relay listening", "addr", conn.LocalAddr(), "tls", tlsAddr, "tun", dev.Name(), "network", netPrefix, "accounts_store", *storeURL,
		"host_addrs", gwCfg.HostAddrs, "deny", deny, "diagnostics_dir", *diagDir,
		"public_key", keyfile.Encode(static.Public))
	rcfg := engine.RelayConfig{
		Session: session.RelayConfig{
			Static: static, ResetSecret: resetSecret, IdleTimeout: gwCfg.Idle + 10*time.Second,
			NoRedundancy: *noRedundancy, NoFEC: *noFEC, NoStreams: *noStreams,
			MaxSessions: *maxSessions, MaxPending: *maxPending, HandshakesPerSecond: *handshakeRate, HandshakesPerSource: *sourceRate,
		},
		Conn: conn, Streams: streams, TUN: dev, Gateway: gw, Logger: log, StatusInterval: *status,
		Attempts: attempts,
	}
	if *diagDir != "" {
		if err := os.MkdirAll(*diagDir, 0o700); err != nil {
			return fmt.Errorf("-diagnostics-dir: %w", err)
		}
		rcfg.Diagnostics = &diag.Store{Dir: *diagDir}
	}
	err = engine.RunRelay(ctx, rcfg)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// hostAddrs returns the IPv4 addresses of the host's interfaces, which
// only accounts with relay access may reach. They are read once, at
// startup: restart the relay after an interface's address changes.
func hostAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("list host addresses: %w", err)
	}
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}
