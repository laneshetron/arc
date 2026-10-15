package tun

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestConfigureDNSAndRestore(t *testing.T) {
	var calls [][]string
	run := func(args ...string) error { calls = append(calls, append([]string(nil), args...)); return nil }
	cleanup, err := configureDNS(run, "arc0", netip.MustParseAddr("10.77.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"dns", "arc0", "10.77.0.1"}, {"domain", "arc0", "~."}, {"default-route", "arc0", "yes"}, {"revert", "arc0"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("DNS calls: %v", calls)
	}
}
func TestConfigureDNSRollsBackPartialFailure(t *testing.T) {
	var calls []string
	failure := errors.New("resolver service unavailable")
	run := func(args ...string) error {
		calls = append(calls, args[0])
		if args[0] == "domain" {
			return failure
		}
		return nil
	}
	cleanup, err := configureDNS(run, "arc0", netip.MustParseAddr("1.1.1.1"))
	if cleanup != nil || !errors.Is(err, failure) || !reflect.DeepEqual(calls, []string{"dns", "domain", "revert"}) {
		t.Fatalf("partial setup: %v, %v", calls, err)
	}
}
func TestInvalidDNSRejectedBeforeSetup(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "127.0.0.53", "169.254.1.1", "224.0.0.1", "255.255.255.255", "::1", "2001:db8::1"} {
		_, err := configureDNS(func(...string) error { t.Fatal("invalid resolver reached setup"); return nil }, "arc0", netip.MustParseAddr(s))
		if err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
