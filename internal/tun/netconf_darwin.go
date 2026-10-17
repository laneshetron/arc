package tun

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DefaultName lets the kernel pick the next free utunN; macOS names TUN
// interfaces no other way.
const DefaultName = "utun"

// DNSManager is the resolver manager ConfigureDNS uses.
const DNSManager = "scutil"

// PolicyRouting is false: macOS has no socket marks, so a full tunnel
// needs every carrier bound to its underlay interface (see Underlay).
const PolicyRouting = false

// command runs a configuration tool, returning its output in any error.
// Tests replace it.
var command = func(stdin string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// Configure assigns addr to the point-to-point interface, sets its MTU,
// brings it up, and routes addr's network through it. After a reconnect
// leases a different address, the old network's route is removed.
func (d *Device) Configure(addr netip.Prefix, mtu int) error {
	if !addr.Addr().Is4() {
		return errors.New("tun: only IPv4 addresses are supported")
	}
	if d.addr.IsValid() && d.addr.Masked() != addr.Masked() {
		d.route("delete", "-inet", "-net", d.addr.Masked().String())
	}
	a := addr.Addr().String()
	mask := net.IP(net.CIDRMask(addr.Bits(), 32)).String()
	if err := command("", "ifconfig", d.name, "inet", a, a, "netmask", mask, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	d.addr = addr
	return d.AddRoute(addr.Masked())
}

// AddRoute routes prefix through the interface, replacing any route to the
// same prefix.
func (d *Device) AddRoute(prefix netip.Prefix) error {
	if !prefix.Addr().Is4() {
		return errors.New("tun: only IPv4 routes are supported")
	}
	return d.route("add", "-inet", "-net", prefix.Masked().String(), "-interface", d.name)
}

// route runs route(8); an add that finds the prefix already routed
// changes that route instead.
func (d *Device) route(op string, args ...string) error {
	err := command("", "route", append([]string{"-n", op}, args...)...)
	if err != nil && op == "add" && strings.Contains(err.Error(), "File exists") {
		err = command("", "route", append([]string{"-n", "change"}, args...)...)
	}
	return err
}

// fullTunnelRoutes cover all of IPv4 with two halves, which outrank the
// default route without replacing it, and reject all of IPv6 so it cannot
// leak around an IPv4-only tunnel (applications fall back to IPv4 at
// once). Directly connected networks keep their more specific routes, so
// unlike on Linux the local network stays reachable outside the tunnel.
func (d *Device) fullTunnelRoutes() [][]string {
	return [][]string{
		{"-inet", "-net", "0.0.0.0/1", "-interface", d.name},
		{"-inet", "-net", "128.0.0.0/1", "-interface", d.name},
		{"-inet6", "-net", "::/1", "::1", "-reject"},
		{"-inet6", "-net", "8000::/1", "::1", "-reject"},
	}
}

// FullTunnel sends all traffic through the interface. mark and table are
// unused: carriers stay out of the tunnel by being bound to their underlay
// interface, which routes them by its scoped routes. The returned function
// removes the routes.
func (d *Device) FullTunnel(_ uint32, _ int) (cleanup func() error, err error) {
	routes := d.fullTunnelRoutes()
	var added [][]string
	cleanup = func() error {
		var errs []error
		for _, r := range added {
			if err := d.route("delete", r[:3]...); err != nil && !strings.Contains(err.Error(), "not in table") {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	for _, r := range routes {
		if err := d.route("add", r...); err != nil {
			cleanup()
			return nil, err
		}
		added = append(added, r)
	}
	return cleanup, nil
}

// Underlay returns the interface of the current default route, for
// binding a carrier that names no interface. Call it before FullTunnel.
func Underlay() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("tun: finding the default route's interface: %w", err)
	}
	return parseRouteInterface(out)
}

func parseRouteInterface(out []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if name, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "interface: "); ok {
			return name, nil
		}
	}
	return "", errors.New("tun: no default route; connect to a network or pass -bind")
}
