// Command arc-client connects to an ARC relay and brings up a TUN
// interface for the tunnel.
//
//	arc-client run -relay 192.0.2.1:4433 -relay-key BASE64 -token-file token -full-tunnel
//	arc-client run -relay 192.0.2.1:4433 -relay-key BASE64 -token-file token -route 198.51.100.0/24
//	arc-client enroll -profile ~/.config/arc/relay arc1:...
//	arc-client run -profile ~/.config/arc/relay -full-tunnel
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/diag"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/keyfile"
	"github.com/laneshetron/arc/internal/profiling"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/tun"
	"github.com/laneshetron/arc/internal/wire"
)

func main() {
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "run":
		err = run(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "enroll":
		err = enroll(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: arc-client run [flags]\n       arc-client enroll [flags] INVITE")
		os.Exit(2)
	}
	if err != nil {
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
	profileDir := fs.String("profile", "", "use the profile arc-client enroll wrote in this directory: its key, token and relay settings, which other flags override")
	relay := fs.String("relay", "", "relay UDP address, host:port")
	relayKey := fs.String("relay-key", "", "relay static public key (base64), pinned")
	tokenFile := fs.String("token-file", "token", "file containing the access token")
	keyFile := fs.String("key-file", "", "client static private key; a new one is generated if empty")
	tunName := fs.String("tun", tun.DefaultName, "TUN interface name")
	journalFile := fs.String("journal", "", "keep a diagnostics journal in this file: the client's log at debug level, as JSON lines, kept across runs (default journal.jsonl with -share-diagnostics)")
	shareDiagnostics := fs.Bool("share-diagnostics", false, "upload the journal to the relay's operator whenever a session is up, if the relay accepts diagnostics; it holds this client's log (carrier outcomes, path quality, addresses of the relay and of this host's links), not its traffic or token, which ARC does not log")
	fullTunnel := fs.Bool("full-tunnel", false, "route all traffic through the tunnel")
	dns := fs.String("dns", "", "trusted IPv4 DNS resolver (overrides the relay's resolver)")
	dnsMode := fs.String("dns-mode", tun.DNSManager, "full-tunnel DNS setup: "+tun.DNSManager+" or manual (requires -dns and an externally configured resolver)")
	var routes prefixList
	fs.Var(&routes, "route", "route this prefix through the tunnel (repeatable)")
	var binds []string
	fs.Func("bind", "bind a carrier socket to this interface (repeatable; on macOS, a full tunnel binds to the default route's interface if none is given)", func(iface string) error {
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
	tlsAddr := fs.String("tls", "", "relay TLS/TCP endpoint, host:port: adds a TLS carrier per interface, used only while no UDP path works")
	tlsCA := fs.String("tls-ca", "", "PEM certificates to trust for -tls (default: the system roots)")
	tlsName := fs.String("tls-server-name", "", "name to verify the relay's TLS certificate against (default: the -tls host)")
	tlsCover := fs.String("tls-cover", "", "pose the TLS carrier as this host instead of the -tls host: present it as the server name (SNI); with no -tls-ca, certificate verification is skipped, since ARC authenticates the relay itself (spec D2)")
	tlsFingerprint := fs.String("tls-fingerprint", "", "shape the TLS ClientHello as a browser's: chrome, edge, safari, ios, or firefox (optional; the relay certificate is still verified unless -tls-cover is set)")
	tlsFragment := fs.Int("tls-fragment", 0, "send the TLS ClientHello in TCP segments of at most this many bytes (optional; the relay certificate is still verified unless -tls-cover is set)")
	frontAddr := fs.String("front", "", "relay HTTPS front endpoint, host:port: like -tls, but the carrier rides an authenticated HTTP upgrade inside an ordinary HTTPS session; the relay's front serves cover content to everyone else. The admission token is the session's -token-file token. -tls-cover, -tls-fingerprint, and -tls-fragment shape the outer handshake as for -tls")
	noOffload := fs.Bool("no-offload", false, "send and receive without UDP GSO/GRO, for comparison")
	noUDP := fs.Bool("no-udp", false, "open no UDP carriers: reach the relay only through -tls or -front (-relay is then the session's address, the -tls endpoint, say)")
	fecMode := wire.FECAuto
	fs.Func("fec", "forward error correction: auto (default; while loss is at least 0.5%), off, or always", func(v string) error {
		switch v {
		case "off":
			fecMode = wire.FECOff
		case "auto":
			fecMode = wire.FECAuto
		case "always":
			fecMode = wire.FECAlways
		default:
			return errors.New("want off, auto, or always")
		}
		return nil
	})
	splitMode := engine.SplitOff
	fs.Func("split-tcp", "carry TCP connections as streams, ended here and opened by the relay (spec §11.3): "+
		"off (default), auto (new connections while the link loses at least 10%), or always", func(v string) error {
		switch v {
		case "off":
			splitMode = engine.SplitOff
		case "auto":
			splitMode = engine.SplitAuto
		case "always":
			splitMode = engine.SplitAlways
		default:
			return errors.New("want off, auto, or always")
		}
		return nil
	})
	mark := fs.Uint("mark", 0x5243, "fwmark for carrier sockets, used by -full-tunnel (Linux)")
	table := fs.Int("table", 5243, "routing table for -full-tunnel (Linux)")
	prof := profiling.Register(fs)
	fs.Parse(args)
	if *profileDir != "" {
		p, err := loadProfile(*profileDir)
		if err != nil {
			return err
		}
		if err := p.apply(fs); err != nil {
			return err
		}
	}
	if !*fullTunnel {
		var dnsFlag bool
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "dns" || f.Name == "dns-mode" {
				dnsFlag = true
			}
		})
		if dnsFlag {
			return errors.New("-dns and -dns-mode require -full-tunnel; configure split-tunnel DNS with your resolver manager")
		}
	}
	if *fullTunnel && tun.PolicyRouting && (*mark == 0 || uint64(*mark) > 1<<32-1 || *table <= 0 || (*table >= 253 && *table <= 255)) {
		return errors.New("-full-tunnel requires a nonzero 32-bit -mark and a dedicated routing -table (not 253, 254 or 255)")
	}
	if *dnsMode != tun.DNSManager && *dnsMode != "manual" {
		return errors.New("-dns-mode must be " + tun.DNSManager + " or manual")
	}
	var trustedDNS netip.Addr
	if *dns != "" {
		var err error
		trustedDNS, err = netip.ParseAddr(*dns)
		if err != nil {
			return fmt.Errorf("-dns: %w", err)
		}
		if err := tun.ValidateDNS(trustedDNS); err != nil {
			return err
		}
	}
	if *fullTunnel && *dnsMode == "manual" && !trustedDNS.IsValid() {
		return errors.New("-full-tunnel -dns-mode manual requires an explicit trusted -dns ADDRESS and external resolver configuration")
	}
	stopProfiles, err := prof.Start()
	if err != nil {
		return err
	}
	defer stopProfiles()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if *shareDiagnostics && *journalFile == "" {
		*journalFile = "journal.jsonl"
	}
	relayAddr, err := netip.ParseAddrPort(*relay)
	if err != nil {
		return fmt.Errorf("-relay: %w", err)
	}
	pin, err := keyfile.Decode32(*relayKey)
	if err != nil {
		return fmt.Errorf("-relay-key: %w", err)
	}
	var journal *diag.Journal
	if *journalFile != "" {
		// The journal is bound to this relay: its operator never receives
		// what a run against another relay recorded.
		// Diagnostics never keep the tunnel from coming up: without a
		// usable journal, the client runs without one.
		journal, err = diag.OpenJournal(*journalFile, base64.StdEncoding.EncodeToString(pin[:]), 0)
		if err != nil {
			log.Warn("running without a diagnostics journal", "journal", *journalFile, "err", err)
			journal = nil
		} else {
			defer journal.Close()
			log = diag.Tee(log.Handler(), journal.Handler())
			if n := journal.Discarded(); n > 0 {
				log.Warn("journal held another relay's diagnostics; discarded them", "journal", *journalFile, "bytes", n)
			}
		}
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
	carriers, closeCarriers, err := openCarriers(log, carrierOptions{
		Relay: relayAddr, Binds: binds, NoOffload: *noOffload, NoUDP: *noUDP, FullTunnel: *fullTunnel, Mark: uint32(*mark),
		TLS: *tlsAddr, TLSCA: *tlsCA, TLSName: *tlsName, TLSCover: *tlsCover, TLSFingerprint: *tlsFingerprint,
		TLSFragment: *tlsFragment, Front: *frontAddr, FrontToken: tokens[0],
	})
	if err != nil {
		return err
	}
	defer closeCarriers()

	var cleanup func() error
	var cleanupDNS func() error
	defer func() {
		if cleanupDNS != nil {
			if err := cleanupDNS(); err != nil {
				log.Warn("restoring DNS", "err", err)
			}
		}
		if cleanup != nil {
			if err := cleanup(); err != nil {
				log.Warn("removing routing rules", "err", err)
			}
		}
	}()
	onEstablished := func(r wire.AuthResult) error {
		resolver := trustedDNS
		if !resolver.IsValid() {
			resolver = netip.AddrFrom4(r.DNSv4)
		}
		if *fullTunnel {
			if err := tun.ValidateDNS(resolver); err != nil {
				return fmt.Errorf("full tunnel requires -dns ADDRESS or an authenticated relay resolver: %w", err)
			}
		}
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
		if *fullTunnel && *dnsMode == tun.DNSManager {
			nextCleanup, err := dev.ConfigureDNS(resolver)
			if err != nil {
				return err
			}
			cleanupDNS = nextCleanup
		} else if *fullTunnel {
			log.Info("using externally configured DNS", "resolver", resolver)
		} else if !resolver.IsUnspecified() {
			log.Info("relay offers a resolver; configure split-tunnel DNS with your resolver manager", "dns", resolver)
		}
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting", "relay", relayAddr, "tun", dev.Name(), "full_tunnel", *fullTunnel,
		"routes", strings.Trim(routes.String(), "[]"), "version", version(), "os", runtime.GOOS, "arch", runtime.GOARCH,
		"carriers", carrierNames(carriers), "split_tcp", splitMode, "share_diagnostics", *shareDiagnostics)
	cfg := engine.ClientConfig{
		Session: session.ClientConfig{
			Static: static, RelayPublic: pin[:], Credential: []byte(tokens[0]), Redundancy: redundancy, FEC: fecMode,
		},
		Relay: relayAddr, Carriers: carriers, TUN: dev, OnEstablished: onEstablished, Logger: log,
		StatusInterval: *status, SplitTCP: splitMode,
	}
	if *shareDiagnostics {
		cfg.Diagnostics = journal
	}
	err = engine.RunClient(ctx, cfg)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
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

// version is the module version and VCS revision the binary was built
// from, as far as the build recorded them.
func version() string {
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
