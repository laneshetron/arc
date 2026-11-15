package main

import (
	"flag"
	"net/netip"
	"path/filepath"
	"strings"
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
	if get("tls-cover") != "example.com" {
		t.Error("a flag given on the command line was overridden")
	}
	if _, _, _, err := prepareProfile(dir, inv); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Errorf("enrolling into an enrolled profile: %v", err)
	}
}
