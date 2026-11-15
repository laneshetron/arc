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
	unlock, err := lockProfile(*dir)
	if err != nil {
		return err
	}
	defer unlock()
	p, err := loadProfile(*dir)
	if err != nil {
		return err
	}
	switch {
	case !p.exists():
		return fmt.Errorf("-profile %s: no profile there (run arc-client enroll)", *dir)
	case p.settings["invite"] != "":
		return fmt.Errorf("-profile %s: enrollment not finished; rerun arc-client enroll -profile %s", *dir, *dir)
	}
	tmpl, err := p.inviteTemplate()
	if err != nil {
		return err
	}
	static, err := keyfile.LoadStatic(p.path("key"))
	if err != nil {
		return err
	}
	tokens, err := keyfile.ReadLines(p.path("token"))
	if err != nil || len(tokens) != 1 {
		return fmt.Errorf("%s: unreadable token", *dir)
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
	err = connectOnce(ctx, log, p, binds, static, []byte(tokens[0]), func(cfg *engine.ClientConfig) {
		cfg.InviteRequest = &req
		cfg.OnInvite = func(a session.InviteAnswer) error {
			answer = &a.Invite
			return errAnswered
		}
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
	// The request is answered for good, whatever the answer.
	os.Remove(p.path("invite-request"))
	switch answer.Status {
	case 0:
	case wire.CodeCapacity:
		return fmt.Errorf("the relay refused: the account is at its device cap or has %d invites outstanding, or this device may invite no further (its lineage is full)", accounts.MaxOutstanding)
	case wire.CodeInviteExpired:
		return errors.New("this request's invite has expired; rerun for a new one")
	case wire.CodeUnauthorized:
		return errors.New("the relay does not let this device mint invites")
	default:
		return fmt.Errorf("the relay refused the request (code %d)", answer.Status)
	}
	tmpl.ID, tmpl.Secret = answer.ID, answer.Secret
	if err := tmpl.Validate(); err != nil {
		return err
	}
	expires := time.Unix(int64(answer.Expires), 0)
	fmt.Fprintf(os.Stderr, "single-use invite to this account, expires %s; enroll a device with:\n  arc-client enroll -profile DIR INVITE\n", expires.Format(time.RFC3339))
	fmt.Println(tmpl.String())
	return nil
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
			if herr == nil && terr == nil && len(b) == 8 && now.Sub(time.Unix(t, 0)) < requestLife {
				return [8]byte(b), nil
			}
		}
	}
	rand.Read(id[:])
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
