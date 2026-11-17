package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/accounts/s3store"
	"github.com/laneshetron/arc/internal/keyfile"
)

const defaultControlDir = "/run/arc-relay"

// openStore opens the accounts store a -accounts-store URL names:
// s3://BUCKET/KEY for an S3 object, or file:PATH (or a bare path) for a
// local file.
func openStore(url string) (accounts.Store, error) {
	switch {
	case strings.HasPrefix(url, "s3://"):
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s, err := s3store.Open(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("-accounts-store: %w", err)
		}
		return s, nil
	case strings.HasPrefix(url, "file://"):
		return accounts.FileStore{Path: strings.TrimPrefix(url, "file://")}, nil
	case strings.HasPrefix(url, "file:"):
		return accounts.FileStore{Path: strings.TrimPrefix(url, "file:")}, nil
	case strings.Contains(url, "://"):
		return nil, fmt.Errorf("-accounts-store %q: unsupported scheme (want s3://BUCKET/KEY or file:PATH)", url)
	case url == "":
		return nil, errors.New("-accounts-store is empty")
	}
	return accounts.FileStore{Path: url}, nil
}

func defaultHolder() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "relay"
	}
	return strings.NewReplacer(",", "_", " ", "_").Replace(h)
}

// accountsCmd runs an operator command: through a running relay's
// control socket if one answers, else as the writer itself, committing
// to the store under the writer lease (self-service-accounts.md §3.2).
func accountsCmd(args []string) error {
	fs := flag.NewFlagSet("accounts", flag.ExitOnError)
	storeURL := fs.String("store", "", "accounts store, as the relay's -accounts-store (used when no relay is running)")
	controlDir := fs.String("control", defaultControlDir, "the relay's control directory (-accounts-control)")
	relay := fs.Bool("relay", false, "add: the account's clients may reach the relay host")
	inviteAddr := fs.String("address", "", "invite: the relay's public address, which the invite's holder connects to")
	inviteUDP := fs.Uint("udp-port", 4433, "invite: the relay's UDP port (0: no UDP carrier)")
	inviteTLS := fs.Uint("tls-port", 0, "invite: the relay's TLS port (0: no TLS carrier); the relay must run with -tls-camouflage, since enrolled devices pose as browsers")
	inviteCover := fs.String("tls-cover", "", "invite: the host name the TLS carrier poses as (required with -tls-port)")
	inviteFP := fs.String("tls-fingerprint", "", "invite: shape the TLS ClientHello as this browser's: chrome, edge, safari, ios, or firefox")
	inviteTTL := fs.Duration("ttl", accounts.DefaultInviteTTL, "invite: how long the invite lasts")
	relayKey := fs.String("relay-key", "", "invite, with no relay running: the relay's static public key (base64)")
	descendants := fs.Bool("descendants", false, "revoke: also revoke every device enrolled through the device's invites, and theirs in turn")
	maxDevices := fs.Int("max-devices", 0, fmt.Sprintf("add: the account's device cap (default %d, at most %d)", accounts.DefaultMaxDevices, accounts.MaxDevicesLimit))
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), `usage: arc-relay accounts [flags] COMMAND
commands:
  list                       accounts and their devices
  add NAME                   create an account (-relay, -max-devices)
  remove NAME                delete an account and its devices
  add-token ACCOUNT [DEVICE] add a device with a new token, printed once
  invite ACCOUNT             print a single-use invite that enrolls a device
                             (-address, -udp-port, -tls-port, -tls-cover, -ttl)
  revoke ACCOUNT/DEVICE      revoke one device (-descendants: and every device
                             enrolled through its invites, and theirs)
  restore ACCOUNT/DEVICE     reinstate a device that another device revoked,
                             within 7 days (operator revocations are final)
  rotate ACCOUNT             revoke every device and invite of the account,
                             keep its policy, and print a fresh invite
                             (the invite flags, as for invite)
  takeover                   break the lease of a writer known to be dead
                             (a running relay here takes it at once)
flags:`)
		fs.PrintDefaults()
	}
	// Flags may come before or after the command.
	var rest []string
	for len(args) > 0 {
		fs.Parse(args)
		args = fs.Args()
		if len(args) > 0 {
			rest = append(rest, args[0])
			args = args[1:]
		}
	}
	if len(rest) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	ctl := accounts.Control{Dir: *controlDir}
	req := accounts.Request{Op: rest[0], Args: rest[1:], Relay: *relay, MaxDevices: *maxDevices, Descendants: *descendants}
	if req.Op == "invite" || req.Op == "rotate" {
		if *inviteUDP > 65535 || *inviteTLS > 65535 {
			return errors.New("ports are at most 65535")
		}
		req.Invite = &accounts.InviteRequest{Address: *inviteAddr, UDPPort: uint16(*inviteUDP), TLSPort: uint16(*inviteTLS),
			ServerName: *inviteCover, Fingerprint: *inviteFP, TTL: *inviteTTL}
		if *relayKey != "" {
			k, err := keyfile.Decode32(*relayKey)
			if err != nil {
				return fmt.Errorf("-relay-key: %w", err)
			}
			req.RelayKey = k[:]
		}
	}

	resp, err := ctl.Send(req)
	if err == nil {
		return printResponse(resp)
	}
	if !errors.Is(err, accounts.ErrNoRelay) {
		return err
	}
	// No relay here: act as the writer.
	if *storeURL == "" {
		return errors.New("no relay answers on the control socket; pass -store to change the accounts directly")
	}
	store, err := openStore(*storeURL)
	if err != nil {
		return err
	}
	unlock, err := ctl.Lock()
	if errors.Is(err, accounts.ErrLocked) {
		return errors.New("a relay on this host holds the accounts lock but its control socket does not answer")
	}
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	w := &accounts.Writer{Store: store, Holder: "cli-" + defaultHolder(), TokenFile: ctl.TokenFile()}
	if req.Op == "takeover" {
		if err := w.Takeover(ctx); err != nil {
			return err
		}
		if err := w.Release(ctx); err != nil {
			return err
		}
		fmt.Println("lease broken; a waiting relay acquires it within a minute")
		return nil
	}
	if err := w.Acquire(ctx); err != nil {
		var held *accounts.HeldError
		if errors.As(err, &held) {
			return fmt.Errorf("%w; is that relay still running? If it is gone, run: arc-relay accounts -store %s takeover", err, *storeURL)
		}
		return err
	}
	defer w.Release(ctx)
	return printResponse(accounts.Do(ctx, w, req, time.Now()))
}

func printResponse(r accounts.Response) error {
	fmt.Print(r.Output)
	if r.Token != "" {
		fmt.Println(r.Token)
	}
	if r.Invite != "" {
		fmt.Println(r.Invite)
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	return nil
}
