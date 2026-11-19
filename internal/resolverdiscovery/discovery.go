// Package resolverdiscovery finds the upstream resolver the lifeline may use
// (spec/dns-lifeline.md §5.2).
//
// The interesting part is not reading the platform's configuration but
// refusing most of what it says. What the network hands a host is usually a
// *stub* — 127.0.0.53 on systemd, a loopback or link-local address on macOS
// — and a stub is not a destination this path can use. Pinning an adapter
// socket to a stub does not pin where its queries go, and once ARC is up the
// stub forwards the lifeline's own queries back into the tunnel the
// lifeline exists to rescue.
//
// So discovery has two halves: ask the platform for the physical link's
// real upstreams, then refuse everything that is not a routable IPv4
// unicast address outside the tunnel.
package resolverdiscovery

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrUnavailable reports that the host has no resolver the lifeline may use.
// §5.2 makes this a correct "unsupported" answer rather than a reason to
// fall back to the stub: a DoH/DoT-only network exposes no plain resolver
// address, and using the stub instead would silently route the lifeline's
// queries into the tunnel.
var ErrUnavailable = errors.New("resolverdiscovery: no eligible upstream resolver")

// Eligible reports whether addr may be used as the lifeline's resolver.
//
// The predicate is the same one tun.ValidateDNS applies to an installed
// resolver — global-unicast IPv4, not loopback, not link-local — because a
// lifeline resolver has to survive the same scrutiny as one ARC installs.
// The extra rule here is that a stub is also refused, since a stub is
// exactly the address that routes into the tunnel once managed DNS is up.
func Eligible(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	a := addr.Unmap()
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	return !isStub(a)
}

// stubPrefixes are the well-known local resolver addresses. They are
// refused by prefix rather than by equality because the exact address is a
// platform detail: systemd-resolved owns all of 127.0.0.53, macOS resolves
// through 127.0.0.1 and fe80::1 on a link, and dnsmasq commonly sits on
// 127.0.0.1.
var stubPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),    // every loopback resolver
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, incl. cloud metadata
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT, which a tunnel may own
}

// isStub reports whether addr is one of the local addresses a resolver
// commonly listens on. The 100.64/10 range is included because ARC's own
// tunnel addresses may live there; a resolver inside the tunnel is
// unreachable exactly when the lifeline is needed.
func isStub(addr netip.Addr) bool {
	for _, p := range stubPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Choose returns the first eligible address in candidates, in the order the
// platform listed them, and ErrUnavailable if there is none.
//
// Order is kept rather than sorted because the platform's order is its
// preference — the resolver it would use first — and §5.2 has no reason to
// disagree with it beyond eligibility. Duplicates are collapsed so a
// repeated address from two services does not cost a second failed attempt.
func Choose(candidates []netip.Addr) (netip.Addr, error) {
	seen := make(map[netip.Addr]bool, len(candidates))
	for _, c := range candidates {
		a := c.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		if Eligible(a) {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: %d candidate(s), none eligible", ErrUnavailable, len(candidates))
}

// Explain describes why each candidate was refused, for the journal. §5.2
// requires the client to say when the lifeline is unavailable rather than
// fail silently, and "the only resolver was 127.0.0.53" is the sentence a
// user needs to understand why.
func Explain(candidates []netip.Addr) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		a := c.Unmap()
		switch {
		case !a.IsValid():
			out = append(out, "invalid")
		case a.IsLinkLocalUnicast():
			// Before the IPv4 check: fe80::1 is the macOS stub, and calling
			// it merely "not IPv4" would hide that it is a local resolver.
			out = append(out, a.String()+": link-local")
		case a.IsLoopback() || isStub(a):
			out = append(out, a.String()+": local stub")
		case !a.Is4():
			out = append(out, a.String()+": not IPv4")
		case !a.IsGlobalUnicast():
			out = append(out, a.String()+": not unicast")
		default:
			out = append(out, a.String()+": eligible")
		}
	}
	return out
}
