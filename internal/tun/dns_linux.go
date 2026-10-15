package tun

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"time"
)

// ConfigureDNS requires systemd-resolved. Hosts using another resolver
// manager must configure their resolver explicitly with -dns-mode manual.
func (d *Device) ConfigureDNS(addr netip.Addr) (func() error, error) {
	path, err := exec.LookPath("resolvectl")
	if err != nil {
		return nil, fmt.Errorf("tun: resolvectl is required for managed DNS (or use -dns-mode manual -dns ADDRESS): %w", err)
	}
	run := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("resolvectl %v: %w: %s", args, err, out)
		}
		return nil
	}
	return configureDNS(run, d.name, addr)
}
