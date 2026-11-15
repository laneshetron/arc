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
	maxDevices := fs.Int("max-devices", 0, fmt.Sprintf("add: the account's device cap (default %d, at most %d)", accounts.DefaultMaxDevices, accounts.MaxDevicesLimit))
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), `usage: arc-relay accounts [flags] COMMAND
commands:
  list                       accounts and their devices
  add NAME                   create an account (-relay, -max-devices)
  remove NAME                delete an account and its devices
  add-token ACCOUNT [DEVICE] add a device with a new token, printed once
  revoke ACCOUNT/DEVICE      revoke one device
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
	req := accounts.Request{Op: rest[0], Args: rest[1:], Relay: *relay, MaxDevices: *maxDevices}

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
	if r.Error != "" {
		return errors.New(r.Error)
	}
	return nil
}
