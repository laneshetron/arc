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

func TestDNSReconnectSkipsUnchangedSettingsAndUpdatesInPlace(t *testing.T) {
	var s dnsState
	var calls [][]string
	run := func(args ...string) error { calls = append(calls, append([]string(nil), args...)); return nil }
	first := netip.MustParseAddr("1.1.1.1")
	second := netip.MustParseAddr("9.9.9.9")
	if _, err := s.configure(run, "arc0", first); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := s.configure(run, "arc0", first); err != nil || len(calls) != 0 {
		t.Fatal("unchanged reconnect touched DNS")
	}
	if _, err := s.configure(run, "arc0", second); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || calls[0][2] != second.String() {
		t.Fatalf("update calls: %v", calls)
	}
	for _, args := range calls {
		if args[0] == "revert" {
			t.Fatal("update reverted DNS")
		}
	}
	calls = nil
	failure := errors.New("new resolver failed")
	failedRun := func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "dns" && args[2] == first.String() {
			return failure
		}
		return nil
	}
	if _, err := s.configure(failedRun, "arc0", first); !errors.Is(err, failure) {
		t.Fatal("expected update failure")
	}
	if s.current != second || len(calls) != 4 || calls[1][2] != second.String() {
		t.Fatalf("old resolver not restored: %v", calls)
	}
	for _, args := range calls {
		if args[0] == "revert" {
			t.Fatal("failed update reverted prior DNS")
		}
	}
}
