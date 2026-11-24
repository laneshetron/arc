//go:build linux

package portal

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// linuxUpstream asks resolvectl for the link's configured upstreams (§4.4).
//
// resolvectl is required: `-dns-mode manual` on a host without
// systemd-resolved means there is no discoverable upstream, and probe B then
// reports unmeasurable rather than falling back to the stub, which would route
// through the daemon and into the tunnel.
//
// iface is always a real link name here. `resolvectl dns ""` is not "every
// link" — resolvectl rejects the empty name — and every link would include
// ARC's TUN anyway; UpstreamResolver.discover names the link first.
func linuxUpstream(ctx context.Context, iface string) ([]netip.Addr, error) {
	out, err := runCommand(ctx, "resolvectl", "dns", iface)
	if err != nil {
		return nil, err
	}
	return parseResolvectlDNS(out, iface), nil
}

// publicProbeAddrs are the destinations a route lookup asks about: any public
// address works, since only the chosen output link matters. IPv6 second, for a
// v6-only host with no v4 default.
var publicProbeAddrs = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2606:4700:4700::1111")}

// linuxPhysicalLink asks the kernel which link a packet carrying mark would
// leave by — `ip route get 1.1.1.1 mark M`. With policy routing installed the
// mark is what selects the physical table, so this names the link under the
// tunnel rather than the TUN; before the tunnel, and with no mark, it is the
// ordinary default route's link.
func linuxPhysicalLink(_ context.Context, mark uint32) (string, error) {
	var lastErr error
	for _, dst := range publicProbeAddrs {
		routes, err := netlink.RouteGetWithOptions(dst, &netlink.RouteGetOptions{Mark: mark})
		if err != nil {
			lastErr = err
			continue
		}
		for _, r := range routes {
			if r.LinkIndex <= 0 {
				continue
			}
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				lastErr = err
				continue
			}
			return link.Attrs().Name, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no route to the public internet")
	}
	return "", lastErr
}

func init() {
	discoverUpstream = linuxUpstream
	physicalLink = linuxPhysicalLink
}
