//go:build linux

package portal

import (
	"context"
	"net/netip"
)

// linuxUpstream asks resolvectl for the link's configured upstreams (§4.4).
//
// resolvectl is required: `-dns-mode manual` on a host without
// systemd-resolved means there is no discoverable upstream, and probe B then
// reports unmeasurable rather than falling back to the stub, which would route
// through the daemon and into the tunnel.
func linuxUpstream(ctx context.Context, iface string) ([]netip.Addr, error) {
	out, err := runCommand(ctx, "resolvectl", "dns", iface)
	if err != nil {
		return nil, err
	}
	return parseResolvectlDNS(out, iface), nil
}

func init() { discoverUpstream = linuxUpstream }
