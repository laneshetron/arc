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
	return new(dnsState).configure(run, iface, addr)
}

type dnsState struct {
	current netip.Addr
	cleanup func() error
}

// Reconnects with the same resolver are no-ops. Changes overwrite the
// per-link settings in place; a failed update restores the old resolver
// without first exposing the other links' resolver configuration.
func (s *dnsState) configure(run func(...string) error, iface string, addr netip.Addr) (func() error, error) {
	if err := ValidateDNS(addr); err != nil {
		return nil, err
	}
	if addr == s.current {
		return s.cleanup, nil
	}
	cleanup := func() error {
		err := run("revert", iface)
		if err == nil {
			s.current, s.cleanup = netip.Addr{}, nil
		}
		return err
	}
	apply := func(resolver netip.Addr) error {
		for _, args := range [][]string{
			{"dns", iface, resolver.String()},
			{"domain", iface, "~."},
			{"default-route", iface, "yes"},
		} {
			if err := run(args...); err != nil {
				return err
			}
		}
		return nil
	}
	if err := apply(addr); err != nil {
		var rollback error
		if s.current.IsValid() {
			rollback = apply(s.current)
			if rollback != nil {
				s.current = netip.Addr{}
			}
		} else {
			rollback = cleanup()
		}
		return nil, errors.Join(fmt.Errorf("tun: configure DNS: %w", err), rollback)
	}
	s.current, s.cleanup = addr, cleanup
	return cleanup, nil
}
