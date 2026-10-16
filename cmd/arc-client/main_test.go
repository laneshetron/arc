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
