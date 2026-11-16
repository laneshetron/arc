package main

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/laneshetron/arc/internal/invite"
)

func TestProfileFromInvite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	inv := &invite.Invite{Carriers: invite.CarrierUDP | invite.CarrierTLS, Addr: netip.MustParseAddr("203.0.113.7"),
		UDPPort: 4433, TLSPort: 443, ServerName: "s3.amazonaws.com", Fingerprint: "chrome", ID: [8]byte{1}, Secret: [16]byte{2}}
	p, _, token, err := prepareProfile(dir, inv)
	if err != nil {
		t.Fatal(err)
	}
	// Rerun with the same invite: the same token, never a new one.
	p2, _, token2, err := prepareProfile(dir, inv)
	if err != nil || string(token2) != string(token) {
		t.Fatalf("resumed: %v, token changed %v", err, string(token2) != string(token))
	}
	other := *inv
	other.ID = [8]byte{9}
	if _, _, _, err := prepareProfile(dir, &other); err == nil {
		t.Error("a second invite into an unfinished profile")
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	for _, f := range []string{"relay", "relay-key", "token-file", "key-file", "tls", "tls-cover", "tls-fingerprint"} {
		fs.String(f, "", "")
	}
	fs.Bool("no-udp", false, "")
	if err := p2.apply(fs); err == nil || !strings.Contains(err.Error(), "not finished") {
		t.Errorf("an unfinished profile ran: %v", err)
	}
	delete(p.settings, "invite")
	p.settings["device"] = "laptop"
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs.Parse([]string{"-tls-cover", "example.com"})
	if err := loaded.apply(fs); err != nil {
		t.Fatal(err)
	}
	get := func(n string) string { return fs.Lookup(n).Value.String() }
	if get("relay") != "203.0.113.7:4433" || get("tls") != "203.0.113.7:443" || get("tls-fingerprint") != "chrome" ||
		get("token-file") != filepath.Join(dir, "token") || get("key-file") != filepath.Join(dir, "key") {
		t.Errorf("flags from the profile: relay %s tls %s fp %s token %s", get("relay"), get("tls"), get("tls-fingerprint"), get("token-file"))
	}
	if get("no-udp") != "false" {
		t.Error("UDP turned off for an invite that offers it")
	}
	if get("tls-cover") != "example.com" {
		t.Error("a flag given on the command line was overridden")
	}
	if _, _, _, err := prepareProfile(dir, inv); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Errorf("enrolling into an enrolled profile: %v", err)
	}
}

// TestTLSOnlyInvite: an invite without UDP makes a profile that opens no
// UDP carrier, with the session at the TLS endpoint.
func TestTLSOnlyInvite(t *testing.T) {
	p := &profile{dir: t.TempDir(), settings: map[string]string{}}
	p.fromInvite(&invite.Invite{Carriers: invite.CarrierTLS, Addr: netip.MustParseAddr("::ffff:203.0.113.7"), TLSPort: 443})
	if p.settings["no-udp"] != "true" || p.settings["relay"] != "203.0.113.7:443" || p.settings["tls"] != "203.0.113.7:443" {
		t.Fatalf("settings: %v", p.settings)
	}
	carriers, closeAll, err := openCarriers(slog.New(slog.DiscardHandler), carrierOptions{Relay: netip.MustParseAddrPort("203.0.113.7:443"), NoUDP: true,
		TLS: p.settings["tls"], TLSCover: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	if len(carriers) != 1 || !carriers[0].Fallback || carriers[0].Name != "default/tls" {
		t.Fatalf("carriers: %+v", carriers)
	}
	if _, _, err := openCarriers(slog.New(slog.DiscardHandler), carrierOptions{Relay: netip.MustParseAddrPort("203.0.113.7:443"), NoUDP: true}); err == nil {
		t.Error("-no-udp without a stream carrier")
	}
	if _, _, err := openCarriers(slog.New(slog.DiscardHandler), carrierOptions{Relay: netip.MustParseAddrPort("[2001:db8::1]:4433")}); err == nil {
		t.Error("an IPv6 relay")
	}
}

// TestProfileLock: a second enrollment into a profile is refused while
// the first holds it.
func TestProfileLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	unlock, err := lockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockProfile(dir); err == nil || !strings.Contains(err.Error(), "another arc-client enroll") {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	unlock2, err := lockProfile(dir)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	unlock2()
}

// TestWritePrivateConcurrent: concurrent replacements of a file each
// land whole, through temporary files of their own.
func TestWritePrivateConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile")
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for n := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- writePrivate(path, bytes.Repeat([]byte(fmt.Sprint(n%10)), 4096))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) != 4096 || !bytes.Equal(data, bytes.Repeat(data[:1], 4096)) {
		t.Fatalf("file torn or missing: %d bytes, %v", len(data), err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}
