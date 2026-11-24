//go:build linux

package portal

import (
	"context"
	"net/netip"
	"testing"
)

// TestLinuxUpstreamIgnoresTheTunnelsResolver is discovery with both a physical
// link and ARC's TUN carrying resolvers, as they do once managed DNS is
// installed: only the physical link's servers may be asked, and resolvectl is
// always given a real link name.
func TestLinuxUpstreamIgnoresTheTunnelsResolver(t *testing.T) {
	origRun, origLink := runCommand, physicalLink
	defer func() { runCommand, physicalLink = origRun, origLink }()

	physicalLink = func(context.Context, uint32) (string, error) { return "wlan0", nil }
	var args [][]string
	runCommand = func(_ context.Context, name string, a ...string) ([]byte, error) {
		args = append(args, a)
		return []byte("Global: 8.8.8.8\nLink 3 (wlan0): 192.168.1.1\nLink 9 (arc0): 10.64.0.1\n"), nil
	}

	u := &UpstreamResolver{}
	got, err := u.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddr("192.168.1.1")
	if len(got) != 1 || got[0] != want {
		t.Errorf("upstreams = %v, want only the physical link's %v", got, want)
	}
	for _, a := range args {
		for _, s := range a {
			if s == "" {
				t.Errorf("resolvectl called with an empty interface: %q", a)
			}
		}
	}
}
