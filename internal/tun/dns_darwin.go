package tun

import (
	"errors"
	"fmt"
	"net/netip"
)

// dnsService is the configd dynamic-store service the tunnel's DNS is
// published under. It is fixed, not per interface, so a client restarted
// after a crash replaces whatever the last one left behind.
const dnsService = "State:/Network/Service/arc"

// ConfigureDNS makes addr the system's default resolver. It publishes the
// tunnel as a network service in configd's dynamic store, marked to
// override the primary service, so macOS resolves through the tunnel's DNS
// instead of the underlay's while the tunnel is up (as VPN clients do).
// Nothing persistent is changed: the entries live until removed or reboot,
// and the returned function removes them.
func (d *Device) ConfigureDNS(addr netip.Addr) (func() error, error) {
	if err := ValidateDNS(addr); err != nil {
		return nil, err
	}
	if addr == d.dns.current {
		return d.dns.cleanup, nil
	}
	if !d.addr.IsValid() {
		return nil, errors.New("tun: configure the interface before DNS")
	}
	cleanup := func() error {
		err := command(dnsRemoveScript, "scutil")
		if err == nil {
			d.dns.current, d.dns.cleanup = netip.Addr{}, nil
		}
		return err
	}
	if err := command(dnsScript(d.name, d.addr.Addr(), addr), "scutil"); err != nil {
		return nil, errors.Join(fmt.Errorf("tun: configure DNS: %w", err), cleanup())
	}
	d.dns.current, d.dns.cleanup = addr, cleanup
	return cleanup, nil
}

// dnsScript publishes the DNS entry before the IPv4 one that makes the
// service primary, so the service never becomes primary without its
// resolver.
func dnsScript(iface string, local, resolver netip.Addr) string {
	return fmt.Sprintf(`d.init
d.add ServerAddresses * %[3]s
set %[4]s/DNS
d.init
d.add Addresses * %[2]s
d.add Router %[2]s
d.add InterfaceName %[1]s
d.add OverridePrimary # 1
set %[4]s/IPv4
quit
`, iface, local, resolver, dnsService)
}

var dnsRemoveScript = fmt.Sprintf("remove %[1]s/IPv4\nremove %[1]s/DNS\nquit\n", dnsService)
