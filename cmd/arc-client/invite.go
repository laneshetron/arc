package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/invite"
	"github.com/laneshetron/arc/internal/keyfile"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// requestLife is how long a request for an invite is repeated before the
// client gives it up (self-service-accounts.md §3.6).
const requestLife = time.Hour

var errAnswered = errors.New("invite answered")

// inviteCmd asks the relay, as this enrolled device, for an invite to its
// account, and prints it, for another device to enroll with
// (self-service-accounts.md §3.6). The request's ID is kept in the
// profile before connecting, so an interrupted request repeated within
// the hour gets the same invite, never a second one.
func inviteCmd(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	dir := fs.String("profile", "profile", "this device's profile, as arc-client enroll wrote it")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up after this long (rerun to resume the same request)")
	var binds []string
	fs.Func("bind", "bind a carrier socket to this interface (repeatable)", func(iface string) error {
		if iface == "" {
			return errors.New("interface name must not be empty")
		}
		binds = append(binds, iface)
		return nil
	})
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: arc-client invite [flags]")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	p, static, token, unlock, err := openEnrolled(*dir)
	if err != nil {
		return err
	}
	defer unlock()
	tmpl, err := p.inviteTemplate()
	if err != nil {
		return err
	}
	req, err := pendingRequest(p, time.Now())
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var answer *wire.Invite
	err = connectOnce(ctx, log, p, binds, static, token, func(cfg *engine.ClientConfig) {
		cfg.Request = engine.InviteRequest(req, func(a session.InviteAnswer) error {
			answer = &a.Invite
			return errAnswered
		})
	})
	switch {
	case errors.Is(err, errAnswered):
	case errors.Is(err, session.ErrNoInvites):
		os.Remove(p.path("invite-request"))
		return errors.New("the relay does not let this device mint invites (its account may not, or the device enrolled without a key; ask the operator)")
	case ctx.Err() != nil && !errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("no answer after %v (rerun to resume the same request)", *timeout)
	default:
		return err
	}
	if answer.Status == 0 {
		return printInvite(p, tmpl, answer)
	}
	// A refusal is final for the request: a rerun makes a new one.
	os.Remove(p.path("invite-request"))
	switch answer.Status {
	case wire.CodeCapacity:
		return fmt.Errorf("the relay refused: the account is at its device cap or has %d invites outstanding, or this device may invite no further (its lineage is full)", accounts.MaxOutstanding)
	case wire.CodeInviteExpired:
		return errors.New("this request's invite has expired; rerun for a new one")
	case wire.CodeUnauthorized:
		return errors.New("the relay does not let this device mint invites")
	default:
		return fmt.Errorf("the relay refused the request (code %d)", answer.Status)
	}
}

// printInvite writes the minted invite to stdout, and only once it is
// written forgets the request: until then a rerun repeats the request,
// and the relay answers it with the same invite.
func printInvite(p *profile, tmpl *invite.Invite, answer *wire.Invite) error {
	tmpl.ID, tmpl.Secret = answer.ID, answer.Secret
	if err := tmpl.Validate(); err != nil {
		return fmt.Errorf("the relay's invite: %w", err)
	}
	expires := time.Unix(int64(answer.Expires), 0)
	fmt.Fprintf(os.Stderr, "single-use invite to this account, expires %s; enroll a device with:\n  arc-client enroll -profile DIR INVITE\n", expires.Format(time.RFC3339))
	if _, err := fmt.Fprintln(os.Stdout, tmpl.String()); err != nil {
		return fmt.Errorf("writing the invite: %w (rerun to get it again)", err)
	}
	// Kept, the request would only get this invite again.
	if err := os.Remove(p.path("invite-request")); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	return nil
}

// openEnrolled locks and loads the enrolled device's profile in dir,
// with its static key and token. The caller calls unlock when done.
func openEnrolled(dir string) (p *profile, static crypto.StaticKey, token []byte, unlock func(), err error) {
	locked, err := lockProfile(dir)
	if err != nil {
		return nil, static, nil, nil, err
	}
	defer func() {
		if err != nil {
			locked()
		}
	}()
	if p, err = loadProfile(dir); err != nil {
		return nil, static, nil, nil, err
	}
	switch {
	case !p.exists():
		return nil, static, nil, nil, fmt.Errorf("-profile %s: no profile there (run arc-client enroll)", dir)
	case p.settings["invite"] != "":
		return nil, static, nil, nil, fmt.Errorf("-profile %s: enrollment not finished; rerun arc-client enroll -profile %s", dir, dir)
	}
	if static, err = keyfile.LoadStatic(p.path("key")); err != nil {
		return nil, static, nil, nil, err
	}
	tokens, err := keyfile.ReadLines(p.path("token"))
	if err != nil || len(tokens) != 1 {
		return nil, static, nil, nil, fmt.Errorf("%s: unreadable token", dir)
	}
	return p, static, []byte(tokens[0]), locked, nil
}

// pendingRequest returns the ID of the profile's unanswered request for an
// invite, kept in invite-request with when it was made, or a new one,
// written before it is sent. A request older than requestLife is given
// up.
func pendingRequest(p *profile, now time.Time) ([8]byte, error) {
	var id [8]byte
	if data, err := os.ReadFile(p.path("invite-request")); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 {
			b, herr := hex.DecodeString(f[0])
			t, terr := strconv.ParseInt(f[1], 10, 64)
			if herr == nil && terr == nil && len(b) == 8 && [8]byte(b) != [8]byte{} && now.Sub(time.Unix(t, 0)) < requestLife {
				return [8]byte(b), nil
			}
		}
	}
	for id == [8]byte{} { // zero is malformed on the wire
		rand.Read(id[:])
	}
	line := fmt.Sprintf("%x %d\n", id, now.Unix())
	return id, writePrivate(p.path("invite-request"), []byte(line))
}

// inviteTemplate is an invite to the relay this profile reaches, by the
// carriers it uses, without an ID and secret.
func (p *profile) inviteTemplate() (*invite.Invite, error) {
	relay, err := netip.ParseAddrPort(p.settings["relay"])
	if err != nil {
		return nil, fmt.Errorf("profile relay: %w", err)
	}
	key, err := keyfile.Decode32(p.settings["relay-key"])
	if err != nil {
		return nil, fmt.Errorf("profile relay-key: %w", err)
	}
	v := &invite.Invite{Addr: relay.Addr().Unmap(), RelayKey: key}
	if p.settings["no-udp"] != "true" {
		v.Carriers |= invite.CarrierUDP
		v.UDPPort = relay.Port()
	}
	if t := p.settings["tls"]; t != "" {
		ap, err := netip.ParseAddrPort(t)
		if err != nil {
			return nil, fmt.Errorf("profile tls: %w", err)
		}
		v.Carriers |= invite.CarrierTLS
		v.TLSPort, v.ServerName, v.Fingerprint = ap.Port(), p.settings["tls-cover"], p.settings["tls-fingerprint"]
	}
	return v, nil
}
