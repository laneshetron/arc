package tun

import (
	"errors"
	"fmt"
	"net/netip"
)

// ValidateDNS rejects resolver addresses that cannot be routed through an
// IPv4 tunnel. Private unicast resolvers supplied by the relay are allowed.
func ValidateDNS(addr netip.Addr) error {
	if !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return errors.New("tun: DNS resolver must be a routable IPv4 unicast address")
	}
	return nil
}

// configureDNS gives systemd-resolved a per-link resolver and the default
// DNS routing domain. Revert removes this interface's settings, including
// partial setup on failure. No global resolver configuration is replaced.
func configureDNS(run func(...string) error, iface string, addr netip.Addr) (func() error, error) {
	if err := ValidateDNS(addr); err != nil {
		return nil, err
	}
	cleanup := func() error { return run("revert", iface) }
	for _, args := range [][]string{
		{"dns", iface, addr.String()},
		{"domain", iface, "~."},
		{"default-route", iface, "yes"},
	} {
		if err := run(args...); err != nil {
			return nil, errors.Join(fmt.Errorf("tun: configure DNS: %w", err), cleanup())
		}
	}
	return cleanup, nil
}
