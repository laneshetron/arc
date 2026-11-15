package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/invite"
	"github.com/laneshetron/arc/internal/keyfile"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

var (
	errEnrolled = errors.New("enrolled")
	errTokenOK  = errors.New("token authenticated")
)

// enroll redeems an invite (self-service-accounts.md §3.4): it makes this
// device a key and a token, writes them with the relay's settings to a
// profile before connecting, and registers the token with the relay over
// ARC itself. Rerun after an interruption, it redeems with the same key
// and token, which the relay recognizes.
func enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	dir := fs.String("profile", "profile", "directory for this device's profile: its key, token and relay settings")
	device := fs.String("device", defaultDeviceName(), "the name to propose for this device; the relay makes it unique in the account")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up after this long")
	var binds []string
	fs.Func("bind", "bind a carrier socket to this interface (repeatable)", func(iface string) error {
		if iface == "" {
			return errors.New("interface name must not be empty")
		}
		binds = append(binds, iface)
		return nil
	})
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: arc-client enroll [flags] INVITE")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	inv, err := invite.Parse(fs.Arg(0))
	if err != nil {
		return err
	}
	if inv.Carriers&invite.CarrierFront != 0 {
		return errors.New("this invite is for the relay's HTTPS front, which enrollment does not support yet")
	}
	if len(*device) > invite.MaxDeviceName {
		return fmt.Errorf("-device: at most %d bytes", invite.MaxDeviceName)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	p, static, token, err := prepareProfile(*dir, inv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	e := &invite.Enrollment{ID: inv.ID, Secret: inv.Secret, Token: token, Name: *device}
	var enrolled *session.Enrolled
	err = connectOnce(ctx, log, p, binds, static, e.Credential(), func(ev session.Enrolled) error {
		enrolled = &ev
		return errEnrolled
	})
	switch {
	case errors.Is(err, errEnrolled):
		p.settings["device"], p.settings["device-id"] = enrolled.Name, deviceID(enrolled.DeviceID)
	case errors.Is(err, session.ErrInviteUsed), errors.Is(err, session.ErrInviteExpired), errors.Is(err, session.ErrAuthFailed):
		// A redemption that may have been made before its answer was
		// lost: the token says whether it was (§3.4).
		log.Info("redemption refused; checking whether an earlier attempt enrolled this device", "reason", err)
		if terr := connectOnce(ctx, log, p, binds, static, token, nil); !errors.Is(terr, errTokenOK) {
			return refusal(err)
		}
		p.settings["device"] = "unknown" // its ENROLLED was lost with the answer
	default:
		if ctx.Err() != nil && !errors.Is(ctx.Err(), context.Canceled) {
			return fmt.Errorf("enrollment timed out after %v (rerun to resume: the profile keeps this attempt)", *timeout)
		}
		return err
	}
	delete(p.settings, "invite")
	if err := p.save(); err != nil {
		return fmt.Errorf("enrolled, but the profile could not be saved: %w", err)
	}
	fmt.Printf("enrolled as %s; connect with:\n  sudo arc-client run -profile %s -full-tunnel\n", p.settings["device"], *dir)
	return nil
}

// refusal explains an enrollment the relay refused.
func refusal(err error) error {
	switch {
	case errors.Is(err, session.ErrInviteUsed):
		return errors.New("the invite was already used by another device; ask for a new one")
	case errors.Is(err, session.ErrInviteExpired):
		return errors.New("the invite has expired; ask for a new one")
	}
	return fmt.Errorf("the relay refused the invite (unknown, cancelled, or mistyped): %w", err)
}

// prepareProfile returns the profile for this enrollment, with its key
// and token: those of an earlier attempt with the same invite, or new
// ones, written before connecting.
func prepareProfile(dir string, inv *invite.Invite) (*profile, crypto.StaticKey, []byte, error) {
	p, err := loadProfile(dir)
	if err != nil {
		return nil, crypto.StaticKey{}, nil, err
	}
	if p.exists() {
		pending, err := invite.Parse(p.settings["invite"])
		switch {
		case p.settings["invite"] == "":
			return nil, crypto.StaticKey{}, nil, fmt.Errorf("%s already holds an enrolled device (%s); enroll into another -profile", dir, p.settings["device"])
		case err != nil || pending.ID != inv.ID:
			return nil, crypto.StaticKey{}, nil, fmt.Errorf("%s holds an unfinished enrollment with another invite; remove it, or enroll into another -profile", dir)
		}
		static, err := keyfile.LoadStatic(p.path("key"))
		if err != nil {
			return nil, crypto.StaticKey{}, nil, err
		}
		tokens, err := keyfile.ReadLines(p.path("token"))
		if err != nil || len(tokens) != 1 {
			return nil, crypto.StaticKey{}, nil, fmt.Errorf("%s: unreadable token from the earlier attempt", dir)
		}
		return p, static, []byte(tokens[0]), nil
	}
	var priv [32]byte
	rand.Read(priv[:])
	static, err := keyfile.StaticFromPrivate(priv)
	if err != nil {
		return nil, crypto.StaticKey{}, nil, err
	}
	token := invite.NewToken()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, crypto.StaticKey{}, nil, err
	}
	if err := writePrivate(p.path("key"), []byte(keyfile.Encode(priv[:])+"\n")); err != nil {
		return nil, crypto.StaticKey{}, nil, err
	}
	if err := writePrivate(p.path("token"), append(bytes.Clone(token), '\n')); err != nil {
		return nil, crypto.StaticKey{}, nil, err
	}
	p.fromInvite(inv)
	p.settings["invite"] = inv.String()
	return p, static, token, p.save()
}

// connectOnce runs a session with credential until it is established
// (errTokenOK) or, with onEnrolled, until ENROLLED, and returns why it
// ended.
func connectOnce(ctx context.Context, log *slog.Logger, p *profile, binds []string, static crypto.StaticKey,
	credential []byte, onEnrolled func(session.Enrolled) error) error {
	relay, err := netip.ParseAddrPort(p.settings["relay"])
	if err != nil {
		return fmt.Errorf("profile relay: %w", err)
	}
	pin, err := keyfile.Decode32(p.settings["relay-key"])
	if err != nil {
		return fmt.Errorf("profile relay-key: %w", err)
	}
	carriers, closeCarriers, err := openCarriers(log, carrierOptions{
		Relay: relay, Binds: binds, TLS: p.settings["tls"], TLSCover: p.settings["tls-cover"],
		TLSFingerprint: p.settings["tls-fingerprint"],
	})
	if err != nil {
		return err
	}
	defer closeCarriers()
	dev := engine.NewNullDevice()
	defer dev.Close()
	cfg := engine.ClientConfig{
		Session: session.ClientConfig{Static: static, RelayPublic: pin[:], Credential: credential},
		Relay:   relay, Carriers: carriers, TUN: dev, Logger: log,
		OnEnrolled: onEnrolled,
	}
	if onEnrolled == nil {
		cfg.OnEstablished = func(wire.AuthResult) error { return errTokenOK }
	}
	err = engine.RunClient(ctx, cfg)
	if err != nil && !errors.Is(err, errEnrolled) && !errors.Is(err, errTokenOK) && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
