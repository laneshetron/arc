package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

func TestPrintDevices(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	devices := []wire.DeviceInfo{
		{ID: [8]byte{1}, Created: 1_790_000_000, LastSeen: 1_800_000_000, Key: [8]byte{0xa1}, Name: "desktop"},
		{ID: [8]byte{2}, Parent: [8]byte{1}, Created: 1_795_000_000, Key: [8]byte{0xb1}, Name: "laptop"},
		{ID: [8]byte{3}, Parent: [8]byte{2}, Created: 1_796_000_000, Key: [8]byte{0xc1}, Name: "phone"},
		{ID: [8]byte{4}, Parent: [8]byte{9}, Created: 1_797_000_000, Key: [8]byte{0xd1}, Name: "tablet"},
		{ID: [8]byte{5}, Created: 1_700_000_000, Name: "legacy-1"},
	}
	var b bytes.Buffer
	printDevices(&b, devices, []byte{0xb1, 0, 0, 0, 0, 0, 0, 0}, now)
	out := b.String()
	for _, want := range []string{"desktop ", "  laptop (this device)", "    phone", "tablet (its inviter is revoked)", "legacy-1", "unbound", "now"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
