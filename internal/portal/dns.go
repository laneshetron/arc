package portal

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
)

// UpstreamResolver answers probe B through the physical link's own upstream
// (spec/captive-portals.md §4.4).
//
// Not the system resolver: once ARC is up, managed DNS replaces it with the
// tunnel's (`tun.dnsState.configure` sets `~.` with `default-route yes`), so a
// query through it would measure relay-side DNS and always look honest. Hence
// the platform-specific discovery below — `resolvectl` reports a link's
// configured upstreams rather than systemd-resolved's 127.0.0.53 stub, and
// macOS keeps them in the dynamic store.
type UpstreamResolver struct {
	// Interface is the physical link, e.g. "wlan0" or "en0".
	Interface string
	// Discover finds the upstream addresses for it. Nil uses the
	// platform default.
	Discover func(ctx context.Context, iface string) ([]netip.Addr, error)
	// Timeout bounds each query. Defaults to 3s.
	Timeout time.Duration
	// Socket options for the query, so the lookup binds to the link and
	// bypasses the TUN like every other probe (§4.1). An ordinary dialer here
	// would route the query through the tunnel once full-tunnel routing is
	// installed, which measures relay-side DNS and always looks honest.
	Sockopt sockopt.Options
	// Dial delivers each query. Nil uses a net.Dialer applying Sockopt; it is a
	// field so a test can record the address without swapping a package global,
	// which would race with a probe whose resolver is still winding down.
	Dial func(ctx context.Context, network, addr string, opts sockopt.Options) (net.Conn, error)
	// Resolve answers a hostname for the HTTP probes' dialer, so probe A does
	// not fall back to the system resolver (§4.1). Nil uses the link's
	// upstreams through resolve.
	Resolve func(ctx context.Context, name string) ([]netip.Addr, error)

	// noSystemFallback, once set, withdraws the one case where the HTTP
	// probes' dialer may ask the system resolver: a link with no discoverable
	// upstream. Before the tunnel exists the system resolver is the network's;
	// once full-tunnel routing is up it is the tunnel's, and asking it would
	// report relay-side DNS as the network's (§4.4). See DisableSystemFallback.
	noSystemFallback atomic.Bool

	// connect dials a resolved endpoint for the HTTP probes. Nil uses a
	// net.Dialer applying Sockopt; tests set it to see which address — or which
	// unresolved hostname — a probe would have dialed.
	connect func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DisableSystemFallback stops the HTTP probes from ever consulting the system
// resolver, including on a link with no upstream of its own. The client calls
// it once the full tunnel is installed: from then on the system resolver
// answers through ARC, so a probe that used it would be measuring the tunnel it
// is meant to look beneath. A link with no upstream then reports no answer,
// which is the honest outcome — nothing physical could resolve the name.
func (u *UpstreamResolver) DisableSystemFallback() { u.noSystemFallback.Store(true) }

// Honesty resolves name through the link's upstream and reports whether the
// answer is categorically implausible (§4.4).
func (u *UpstreamResolver) Honesty(ctx context.Context, name string) (DNSVerdict, error) {
	servers, err := u.discover(ctx)
	if err != nil {
		return DNSUnmeasured, err
	}
	if len(servers) == 0 {
		// A stub-only or DoH-only host has no upstream to ask. That is
		// unmeasurable, not honest — the state then rests on probe A alone.
		return DNSUnmeasured, nil
	}

	timeout := u.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	addrs, err := queryFirst(ctx, servers, name, timeout, u.Sockopt, u.Dial)
	if err != nil {
		return DNSUnmeasured, err
	}
	return judgeAnswer(addrs), nil
}

// ErrNoUpstream reports that the link has no discoverable upstream, so there is
// nothing to ask. It is different from an upstream that failed: the first means
// the system resolver is the only option left, the second means the link's DNS is
// broken and a system answer would come from the tunnel.
var ErrNoUpstream = errors.New("portal: no upstream on this link")

// resolve returns the addresses a name resolves to on this link, going to the
// link's own upstreams (§4.4) so the answer describes the physical network
// rather than the tunnel.
//
// The first upstream that answers wins. An error means nothing on the link
// could resolve it, and the caller decides whether to fall back.
func (u *UpstreamResolver) resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	servers, err := u.discover(ctx)
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		// A stub-only or DoH-only host has no upstream to ask.
		return nil, ErrNoUpstream
	}
	timeout := u.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return queryFirst(ctx, servers, name, timeout, u.Sockopt, u.Dial)
}

// discover finds this link's upstreams. Every way discovery itself can fail is
// reported as ErrNoUpstream; see below.
//
// An attachment with no interface name — Linux with policy routing, where the
// mark rather than a binding keeps traffic physical — still has exactly one
// link under it: the one the marked route leaves by. Discovery asks for that
// link by name. Taking every link's resolvers instead would include ARC's own
// TUN once managed DNS installs a resolver there, and a query to it sent
// outside the tunnel either fails after its full timeout or answers for the
// wrong network.
func (u *UpstreamResolver) discover(ctx context.Context) ([]netip.Addr, error) {
	if u.Discover != nil {
		return u.Discover(ctx, u.Interface)
	}
	iface := u.Interface
	if iface == "" {
		link, err := physicalLink(ctx, u.Sockopt.Mark)
		if err != nil {
			return nil, fmt.Errorf("%w: finding the physical link: %v", ErrNoUpstream, err)
		}
		if link == "" {
			return nil, fmt.Errorf("%w: no route names a physical link", ErrNoUpstream)
		}
		iface = link
	}
	servers, err := discoverUpstream(ctx, iface)
	if err != nil {
		// A discovery failure — no resolvectl, systemd-resolved not running,
		// scutil failing — means there is no upstream ARC can find, not an
		// upstream that failed to answer. The distinction decides the HTTP
		// probes' fallback: before the tunnel, a host without the discovery
		// mechanism degrades to the system resolver and probe A alone, as
		// documented; an upstream that was found and did not answer never
		// does.
		return nil, fmt.Errorf("%w: %v", ErrNoUpstream, err)
	}
	return servers, nil
}

// physicalLink names the interface a marked packet to the public internet
// leaves by. It is the platform's; the default has no way to tell.
var physicalLink = func(ctx context.Context, mark uint32) (string, error) {
	return "", errors.New("portal: physical link discovery not implemented on this platform")
}

// judgeAnswer applies §4.4's rule: an address is anomalous only when it is
// categorically implausible for a public name. A different public address is
// not evidence of anything, because answers legitimately vary by geography and
// resolver.
func judgeAnswer(addrs []netip.Addr) DNSVerdict {
	if len(addrs) == 0 {
		// No answer at all: an NXDOMAIN or a filtered name. That is a
		// resolver saying something odd, but not the hijack shape this probe
		// looks for, so it is left to the profiler.
		return DNSClean
	}
	for _, a := range addrs {
		if implausible(a) {
			return DNSAnomalous
		}
	}
	return DNSClean
}

// implausible reports whether a is a shape no public name should resolve to.
func implausible(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return true
	}
	switch {
	case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsMulticast(), a.IsUnspecified(), a.IsInterfaceLocalMulticast():
		return true
	case a.Is4():
		switch {
		case a.IsPrivate():
			return true
		case a.As4()[0] == 0: // 0.0.0.0/8, "this network"
			return true
		case a.As4()[0] == 100 && a.As4()[1] >= 64: // 100.64/10 CGNAT
			return true
		case a.As4()[0] == 192 && a.As4()[1] == 0 && a.As4()[2] == 0: // 192.0.0/24
			return true
		case a.As4()[0] == 198 && (a.As4()[1] == 18 || a.As4()[1] == 19): // 198.18/15 benchmarking
			return true
		case a.As4()[0] >= 240: // 240/4 reserved
			return true
		}
	}
	return false
}

// queryFirst asks each server in turn, returning the first answer. Port 53 is
// assumed unless an address carries one.
func queryFirst(ctx context.Context, servers []netip.Addr, name string, timeout time.Duration, opts sockopt.Options, dial dialFunc) ([]netip.Addr, error) {
	if dial == nil {
		dial = dialContext
	}
	var lastErr error
	for _, s := range servers {
		c, cancel := context.WithTimeout(ctx, timeout)
		addrs, err := lookupWith(c, s, name, opts, dial)
		cancel()
		if err == nil {
			return addrs, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("portal: no upstream answered")
	}
	return nil, lastErr
}

// lookupWith resolves name against one explicit server, keeping the query off
// the system resolver and therefore off the TUN.
func lookupWith(ctx context.Context, server netip.Addr, name string, opts sockopt.Options, dial dialFunc) ([]netip.Addr, error) {
	r := &net.Resolver{PreferGo: true, Dial: upstreamDial(server, opts, dial)}
	return r.LookupNetIP(ctx, "ip", name)
}

// dialFunc connects to addr applying opts. It is a parameter rather than a
// package-level variable so a test can substitute one without racing a probe
// whose resolver goroutines are still winding down.
type dialFunc func(ctx context.Context, network, addr string, opts sockopt.Options) (net.Conn, error)

// upstreamDial returns the Dial function that redirects every query to one
// server, ignoring the address the resolver passes — which is the system's,
// read from resolv.conf, and is exactly what §4.4 must not use.
//
// Named and exported to the package's tests so the redirection can be asserted
// directly instead of by counting packets.
func upstreamDial(server netip.Addr, opts sockopt.Options, dial dialFunc) func(ctx context.Context, network, _ string) (net.Conn, error) {
	if dial == nil {
		dial = dialContext
	}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, net.JoinHostPort(server.String(), "53"), opts)
	}
}

// dialContext is net.Dialer.DialContext with the socket options applied.
func dialContext(ctx context.Context, network, addr string, opts sockopt.Options) (net.Conn, error) {
	d := net.Dialer{Control: sockopt.Control(opts)}
	return d.DialContext(ctx, network, addr)
}

// discoverUpstream is the platform default. Split so the platform files can
// supply it without build tags here.
var discoverUpstream = func(ctx context.Context, iface string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("portal: upstream discovery not implemented on this platform")
}

// parseResolvectlDNS reads `resolvectl dns IFACE` output, keeping global
// upstreams out and rejecting stubs.
//
// The output names each link and then its servers:
//
//	Global: 8.8.8.8
//	Link 3 (wlan0): 192.168.1.1 2001:db8::1
//
// Only the named link's servers are taken: the global list belongs to
// systemd-resolved and is reached through the stub, which is what this probe
// must avoid. An empty name matches nothing — every other link's servers, ARC's
// TUN among them, are not this attachment's (see UpstreamResolver.discover).
func parseResolvectlDNS(out []byte, iface string) []netip.Addr {
	var addrs []netip.Addr
	if iface == "" {
		return nil
	}
	inLink := false
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Link ") {
			// "Link 3 (wlan0): 1.1.1.1 ..."
			inLink = strings.Contains(line, "("+iface+")")
			if i := strings.Index(line, "):"); i >= 0 && inLink {
				addrs = append(addrs, parseAddrList(line[i+2:])...)
			}
			continue
		}
		if inLink {
			addrs = append(addrs, parseAddrList(line)...)
		}
	}
	return usableUpstreams(addrs)
}

// parseAddrList pulls IP addresses out of a whitespace-separated list,
// tolerating the trailing punctuation resolvectl emits.
func parseAddrList(s string) []netip.Addr {
	var out []netip.Addr
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, ",;")
		if a, err := netip.ParseAddr(f); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// usableUpstreams drops loopback and link-local stubs: a stub forwards through
// the daemon, which is what routes into the tunnel (§4.4).
func usableUpstreams(in []netip.Addr) []netip.Addr {
	out := in[:0]
	seen := map[netip.Addr]bool{}
	for _, a := range in {
		a = a.Unmap()
		if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
			continue
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// parseScutilDNS reads `scutil --dns` output and returns the resolvers for the
// service whose interface matches iface.
//
// The output is stanza-based:
//
//	resolver #1
//	  nameserver[0] : 192.168.1.1
//	  if_index : 6 (en0)
//
// A resolver with no if_index is a global one, reached through the daemon.
func parseScutilDNS(out []byte, iface string) []netip.Addr {
	var addrs []netip.Addr
	var cur []netip.Addr
	// An unnamed attachment (no interface bound) has no single service to ask,
	// so every resolver is a candidate — otherwise the if_index line below
	// would clear the initial match and nothing would ever qualify.
	anyService := iface == ""
	curMatches := anyService

	flush := func() {
		if curMatches {
			addrs = append(addrs, cur...)
		}
		cur = nil
		curMatches = anyService
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "resolver #"):
			flush()
		case strings.HasPrefix(line, "nameserver["):
			if i := strings.Index(line, ":"); i >= 0 {
				if a, err := netip.ParseAddr(strings.TrimSpace(line[i+1:])); err == nil {
					cur = append(cur, a)
				}
			}
		case strings.HasPrefix(line, "if_index"):
			// "if_index : 6 (en0)"
			if !anyService {
				curMatches = strings.Contains(line, "("+iface+")")
			}
		}
	}
	flush()
	return usableUpstreams(addrs)
}

// runCommand is exec.CommandContext, indirected for tests.
var runCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}
