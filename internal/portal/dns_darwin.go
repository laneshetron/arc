//go:build darwin

package portal

import (
	"context"
	"net/netip"
)

// darwinUpstream reads the link's resolvers from the dynamic store via
// `scutil --dns` (§4.4).
//
// macOS keeps per-service resolvers there and the system resolver is a
// forwarder, so asking the system resolver would measure the daemon rather
// than the link — and once ARC is up, that daemon forwards into the tunnel.
func darwinUpstream(ctx context.Context, iface string) ([]netip.Addr, error) {
	out, err := runCommand(ctx, "scutil", "--dns")
	if err != nil {
		return nil, err
	}
	return parseScutilDNS(out, iface), nil
}

func init() { discoverUpstream = darwinUpstream }
