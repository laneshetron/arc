package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/laneshetron/arc/internal/invite"
	"github.com/laneshetron/arc/internal/keyfile"
)

// A profile is a directory holding one device's identity for one relay
// (self-service-accounts.md §3.4): its static key (key), its token
// (token), and, in the file profile, how to reach the relay and the
// device it enrolled as. arc-client enroll writes it; arc-client run
// -profile DIR uses it.
type profile struct {
	dir      string
	settings map[string]string // the profile file, in order of keys below
}

// Profile keys. The relay keys are run's flag names, which -profile
// fills in.
var profileKeys = []string{"relay", "relay-key", "no-udp", "tls", "tls-cover", "tls-fingerprint", "device", "device-id", "invite"}

// runKeys are the profile keys that set run's flags.
var runKeys = []string{"relay", "relay-key", "no-udp", "tls", "tls-cover", "tls-fingerprint"}

func (p *profile) path(name string) string { return filepath.Join(p.dir, name) }

// loadProfile reads the profile in dir; a directory without one is an
// empty profile.
func loadProfile(dir string) (*profile, error) {
	p := &profile{dir: dir, settings: map[string]string{}}
	data, err := os.ReadFile(p.path("profile"))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: want KEY=VALUE", p.path("profile"), n)
		}
		p.settings[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return p, sc.Err()
}

func (p *profile) exists() bool { return len(p.settings) > 0 }

// save writes the profile file, creating the directory private to its
// owner.
func (p *profile) save() error {
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# arc-client profile; key and token are beside it\n")
	for _, k := range profileKeys {
		if v := p.settings[k]; v != "" {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	return writePrivate(p.path("profile"), []byte(b.String()))
}

// writePrivate replaces path with data, readable only by its owner,
// through a temporary file of its own.
func writePrivate(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp") // mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// lockProfile takes dir's lock, creating dir, for an enrollment into it:
// a second one waiting for the same profile could make another key and
// token while the first redeems the invite with its own. The lock is
// released when the returned function is called or the process exits.
func lockProfile(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: another arc-client enroll is using this profile", dir)
		}
		return nil, fmt.Errorf("%s: lock: %w", dir, err)
	}
	return func() { f.Close() }, nil
}

// fromInvite sets the relay settings an invite gives: the carriers it
// offers, and no others.
func (p *profile) fromInvite(v *invite.Invite) {
	port := v.UDPPort
	if v.Carriers&invite.CarrierUDP == 0 {
		port = v.TLSPort // the session's address; no UDP carrier answers there
		p.settings["no-udp"] = "true"
	}
	p.settings["relay"] = netip.AddrPortFrom(v.Addr.Unmap(), port).String()
	p.settings["relay-key"] = keyfile.Encode(v.RelayKey[:])
	if v.Carriers&invite.CarrierTLS != 0 {
		p.settings["tls"] = netip.AddrPortFrom(v.Addr.Unmap(), v.TLSPort).String()
		p.settings["tls-cover"] = v.ServerName
		p.settings["tls-fingerprint"] = v.Fingerprint
	}
}

// apply sets fs's flags from the profile, except those given on the
// command line.
func (p *profile) apply(fs *flag.FlagSet) error {
	if !p.exists() {
		return fmt.Errorf("-profile %s: no profile there (run arc-client enroll)", p.dir)
	}
	if p.settings["invite"] != "" {
		return fmt.Errorf("-profile %s: enrollment not finished; rerun arc-client enroll -profile %s", p.dir, p.dir)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	defaults := map[string]string{"token-file": p.path("token"), "key-file": p.path("key")}
	for _, k := range runKeys {
		if v := p.settings[k]; v != "" {
			defaults[k] = v
		}
	}
	for k, v := range defaults {
		if !set[k] {
			if err := fs.Set(k, v); err != nil {
				return fmt.Errorf("-profile %s: %s: %w", p.dir, k, err)
			}
		}
	}
	return nil
}

// defaultDeviceName is the host's name, as a device name.
func defaultDeviceName() string {
	h, _ := os.Hostname()
	h, _, _ = strings.Cut(h, ".")
	var b strings.Builder
	for _, c := range []byte(h) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '_', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if len(name) > invite.MaxDeviceName {
		name = name[:invite.MaxDeviceName]
	}
	if name == "" {
		name = "device"
	}
	return name
}

// deviceID formats an ENROLLED device ID as the relay's records do.
func deviceID(id [8]byte) string { return hex.EncodeToString(id[:]) }
