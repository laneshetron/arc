package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Configure assigns addr to the interface, sets its MTU, and brings it up.
// Any previous address is replaced, which matters after a reconnect leases
// a different one.
func (d *Device) Configure(addr netip.Prefix, mtu int) error {
	link, err := netlink.LinkByName(d.name)
	if err != nil {
		return err
	}
	old, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return err
	}
	for _, a := range old {
		if a.IPNet.String() != prefixNet(addr).String() {
			if err := netlink.AddrDel(link, &a); err != nil {
				return err
			}
		}
	}
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: prefixNet(addr)}); err != nil {
		return fmt.Errorf("address %v: %w", addr, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// AddRoute routes prefix through the interface in the main table.
func (d *Device) AddRoute(prefix netip.Prefix) error {
	link, err := netlink.LinkByName(d.name)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixNet(prefix)})
}

// FullTunnel sends all traffic through the interface except packets
// carrying mark, which the carrier sockets set (§17.1). It follows the
// wg-quick layout:
//
//	ip rule add not fwmark MARK table TABLE
//	ip rule add table main suppress_prefixlength 0
//	ip route add default dev IFACE table TABLE
//
// IPv6 is blackholed in the same table so it cannot leak around an
// IPv4-only tunnel. The returned function removes the rules.
func (d *Device) FullTunnel(mark uint32, table int) (cleanup func() error, err error) {
	link, err := netlink.LinkByName(d.name)
	if err != nil {
		return nil, err
	}
	routes := []*netlink.Route{
		{LinkIndex: link.Attrs().Index, Dst: prefixNet(netip.MustParsePrefix("0.0.0.0/0")), Table: table},
		{Dst: prefixNet(netip.MustParsePrefix("::/0")), Table: table, Type: unix.RTN_UNREACHABLE, Family: unix.AF_INET6},
	}
	var rules []*netlink.Rule
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		viaTunnel := netlink.NewRule()
		viaTunnel.Family, viaTunnel.Mark, viaTunnel.Invert, viaTunnel.Table = family, mark, true, table
		mainUnlessDefault := netlink.NewRule()
		mainUnlessDefault.Family, mainUnlessDefault.Table, mainUnlessDefault.SuppressPrefixlen = family, unix.RT_TABLE_MAIN, 0
		rules = append(rules, viaTunnel, mainUnlessDefault)
	}

	cleanup = func() error {
		var errs []error
		for _, r := range rules {
			if err := netlink.RuleDel(r); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, err)
			}
		}
		for _, r := range routes {
			netlink.RouteDel(r) // the routes go away with the interface anyway
		}
		return errors.Join(errs...)
	}
	for _, r := range routes {
		if err := netlink.RouteReplace(r); err != nil {
			cleanup()
			return nil, fmt.Errorf("route %v: %w", r.Dst, err)
		}
	}
	for _, r := range rules {
		if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
			cleanup()
			return nil, fmt.Errorf("rule: %w", err)
		}
	}
	return cleanup, nil
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
