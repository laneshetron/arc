package main

import (
	"strings"
	"testing"
)

func TestSplitTunnelRejectsIgnoredDNSFlags(t *testing.T) {
	for _, args := range [][]string{{"-dns", "1.1.1.1"}, {"-dns-mode", "manual"}, {"-dns-mode", "systemd-resolved"}} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "require -full-tunnel") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

// TestAllowlistRejectsSplitTCP: the posture leaves only TLS-borne
// carriers, so split TCP, which would carry inner TLS inside them, is
// refused rather than placed there.
func TestAllowlistRejectsSplitTCP(t *testing.T) {
	for _, mode := range []string{"auto", "always"} {
		err := run([]string{"-allowlist", "-front", "203.0.113.7:443", "-split-tcp", mode})
		if err == nil || !strings.Contains(err.Error(), "-split-tcp cannot be used with -allowlist") {
			t.Errorf("-split-tcp %s: %v", mode, err)
		}
	}
}
