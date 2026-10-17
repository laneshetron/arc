package tun

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// fakeCommands records commands instead of running them. fail returns the
// error a command should fail with, or nil.
func fakeCommands(t *testing.T, fail func(cmd string) error) *[]string {
	var calls []string
	saved := command
	command = func(stdin, name string, args ...string) error {
		cmd := strings.Join(append([]string{name}, args...), " ")
		if stdin != "" {
			cmd += " <<" + strings.ReplaceAll(strings.TrimSpace(stdin), "\n", "; ")
		}
		calls = append(calls, cmd)
		if fail != nil {
			return fail(cmd)
		}
		return nil
	}
	t.Cleanup(func() { command = saved })
	return &calls
}

func TestConfigureAndReconnect(t *testing.T) {
	calls := fakeCommands(t, nil)
	d := &Device{name: "utun7"}
	if err := d.Configure(netip.MustParsePrefix("10.77.0.2/16"), 1280); err != nil {
		t.Fatal(err)
	}
	// Same network, new address: the route stays.
	if err := d.Configure(netip.MustParsePrefix("10.77.0.9/16"), 1280); err != nil {
		t.Fatal(err)
	}
	// A different network: the old route goes.
	if err := d.Configure(netip.MustParsePrefix("10.88.0.2/24"), 1400); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ifconfig utun7 inet 10.77.0.2 10.77.0.2 netmask 255.255.0.0 mtu 1280 up",
		"route -n add -inet -net 10.77.0.0/16 -interface utun7",
		"ifconfig utun7 inet 10.77.0.9 10.77.0.9 netmask 255.255.0.0 mtu 1280 up",
		"route -n add -inet -net 10.77.0.0/16 -interface utun7",
		"route -n delete -inet -net 10.77.0.0/16",
		"ifconfig utun7 inet 10.88.0.2 10.88.0.2 netmask 255.255.255.0 mtu 1400 up",
		"route -n add -inet -net 10.88.0.0/24 -interface utun7",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commands:\n%s", strings.Join(*calls, "\n"))
	}
}

func TestAddRouteReplacesExisting(t *testing.T) {
	calls := fakeCommands(t, func(cmd string) error {
		if strings.Contains(cmd, " add ") {
			return errors.New("route: writing to routing socket: File exists")
		}
		return nil
	})
	d := &Device{name: "utun7"}
	if err := d.AddRoute(netip.MustParsePrefix("198.51.100.7/24")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route -n add -inet -net 198.51.100.0/24 -interface utun7",
		"route -n change -inet -net 198.51.100.0/24 -interface utun7",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commands:\n%s", strings.Join(*calls, "\n"))
	}
	if err := d.AddRoute(netip.MustParsePrefix("2001:db8::/32")); err == nil {
		t.Fatal("IPv6 route accepted")
	}
}

func TestFullTunnelRoutesAndCleanup(t *testing.T) {
	calls := fakeCommands(t, nil)
	d := &Device{name: "utun7"}
	cleanup, err := d.FullTunnel(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route -n add -inet -net 0.0.0.0/1 -interface utun7",
		"route -n add -inet -net 128.0.0.0/1 -interface utun7",
		"route -n add -inet6 -net ::/1 ::1 -reject",
		"route -n add -inet6 -net 8000::/1 ::1 -reject",
		"route -n delete -inet -net 0.0.0.0/1",
		"route -n delete -inet -net 128.0.0.0/1",
		"route -n delete -inet6 -net ::/1",
		"route -n delete -inet6 -net 8000::/1",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commands:\n%s", strings.Join(*calls, "\n"))
	}
}

func TestFullTunnelUndoesPartialSetup(t *testing.T) {
	failure := errors.New("route: writing to routing socket: Network is unreachable")
	calls := fakeCommands(t, func(cmd string) error {
		if strings.Contains(cmd, "add -inet6 -net ::/1") {
			return failure
		}
		return nil
	})
	d := &Device{name: "utun7"}
	if cleanup, err := d.FullTunnel(0, 0); cleanup != nil || !errors.Is(err, failure) {
		t.Fatalf("FullTunnel: %v", err)
	}
	want := []string{
		"route -n add -inet -net 0.0.0.0/1 -interface utun7",
		"route -n add -inet -net 128.0.0.0/1 -interface utun7",
		"route -n add -inet6 -net ::/1 ::1 -reject",
		"route -n delete -inet -net 0.0.0.0/1",
		"route -n delete -inet -net 128.0.0.0/1",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commands:\n%s", strings.Join(*calls, "\n"))
	}
}

func TestConfigureDNSDarwin(t *testing.T) {
	calls := fakeCommands(t, nil)
	d := &Device{name: "utun7"}
	if _, err := d.ConfigureDNS(netip.MustParseAddr("1.1.1.1")); err == nil {
		t.Fatal("DNS configured before the interface")
	}
	d.addr = netip.MustParsePrefix("10.77.0.2/16")
	cleanup, err := d.ConfigureDNS(netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	// A reconnect with the same resolver changes nothing.
	if _, err := d.ConfigureDNS(netip.MustParseAddr("1.1.1.1")); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"scutil <<d.init; d.add ServerAddresses * 1.1.1.1; set State:/Network/Service/arc/DNS; " +
			"d.init; d.add Addresses * 10.77.0.2; d.add Router 10.77.0.2; d.add InterfaceName utun7; " +
			"d.add OverridePrimary # 1; set State:/Network/Service/arc/IPv4; quit",
		"scutil <<remove State:/Network/Service/arc/IPv4; remove State:/Network/Service/arc/DNS; quit",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commands:\n%s", strings.Join(*calls, "\n"))
	}
	if d.dns.current.IsValid() {
		t.Fatal("resolver still recorded after cleanup")
	}
}

func TestParseRouteInterface(t *testing.T) {
	out := []byte(`   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`)
	if name, err := parseRouteInterface(out); err != nil || name != "en0" {
		t.Fatalf("got %q, %v", name, err)
	}
	if _, err := parseRouteInterface([]byte("route: writing to routing socket: not in table\n")); err == nil {
		t.Fatal("no default route parsed as one")
	}
}
