package portal

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"
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
}

// Honesty resolves name through the link's upstream and reports whether the
// answer is categorically implausible (§4.4).
func (u *UpstreamResolver) Honesty(ctx context.Context, name string) (DNSVerdict, error) {
	discover := u.Discover
	if discover == nil {
		discover = discoverUpstream
	}
	servers, err := discover(ctx, u.Interface)
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
	addrs, err := queryFirst(ctx, servers, name, timeout)
	if err != nil {
		return DNSUnmeasured, err
	}
	return judgeAnswer(addrs), nil
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
func queryFirst(ctx context.Context, servers []netip.Addr, name string, timeout time.Duration) ([]netip.Addr, error) {
	var lastErr error
	for _, s := range servers {
		c, cancel := context.WithTimeout(ctx, timeout)
		addrs, err := lookupWith(c, s, name)
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
func lookupWith(ctx context.Context, server netip.Addr, name string) ([]netip.Addr, error) {
	r := &net.Resolver{PreferGo: true, Dial: upstreamDial(server)}
	return r.LookupNetIP(ctx, "ip", name)
}

// upstreamDial returns the Dial function that redirects every query to one
// server, ignoring the address the resolver passes — which is the system's,
// read from resolv.conf, and is exactly what §4.4 must not use.
//
// Named and exported to the package's tests so the redirection can be asserted
// directly instead of by counting packets.
func upstreamDial(server netip.Addr) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialContext(ctx, network, net.JoinHostPort(server.String(), "53"))
	}
}

// dialContext is net.Dialer.DialContext, indirected so a test can assert the
// address without opening a socket.
var dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
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
// must avoid.
func parseResolvectlDNS(out []byte, iface string) []netip.Addr {
	var addrs []netip.Addr
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
	curMatches := iface == ""

	flush := func() {
		if curMatches {
			addrs = append(addrs, cur...)
		}
		cur = nil
		curMatches = iface == ""
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
			curMatches = strings.Contains(line, "("+iface+")")
		}
	}
	flush()
	return usableUpstreams(addrs)
}

// runCommand is exec.CommandContext, indirected for tests.
var runCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}
